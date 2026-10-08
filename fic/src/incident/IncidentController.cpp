#include "incident/IncidentController.h"

#include <fic/core/logging/Logger.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/logging/SecurityAudit.h>
#include <fic/core/notification/NotifyUser.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <utility>

namespace fic::incident {
namespace {

using json = nlohmann::json;
using ::fic::core::IncidentSeverity;
using ::fic::core::incidentSeverityIsUnlocked;
using session::LoginSession;
using session::LoginUser;
using session::SessionKind;

// A session is contained when it is gone, or - for a graphical session at
// STANDARD - when the lock was requested AND independently verified.
// Recovery identities are never touched.
bool isOrdinaryTarget(const LoginSession& session) {
    return session.ordinary && !session.recovery && session.uid != 0;
}

} // namespace

std::string runtimeStateToString(RuntimeState state) {
    switch (state) {
        case RuntimeState::Inactive:
            return "inactive";
        case RuntimeState::Applying:
            return "applying";
        case RuntimeState::Active:
            return "active";
        case RuntimeState::Degraded:
            return "degraded";
        case RuntimeState::Clearing:
            return "clearing";
    }
    return "unknown";
}

IncidentController::IncidentController()
    : stateStore_(),
      sessions_(nullptr),
      network_(std::make_shared<NullIncidentNetworkBackend>()) {
}

IncidentController::IncidentController(
    IncidentStateStore stateStore,
    std::shared_ptr<session::SessionContainmentBackend> sessions,
    std::shared_ptr<IncidentNetworkBackend> network)
    : stateStore_(std::move(stateStore)),
      sessions_(std::move(sessions)),
      network_(network != nullptr
                   ? std::move(network)
                   : std::make_shared<NullIncidentNetworkBackend>()) {
}

IncidentResponseModeResult IncidentController::resolveMode() const {
    try {
        return modeResolver_ ? modeResolver_() : IncidentResponseModeResult{};
    } catch (...) {
        return {IncidentResponseMode::Active, false,
                "fallback ACTIVE: mode resolver failed"};
    }
}

IncidentResult IncidentController::settleNonActiveMode(
    IncidentResponseMode mode, IncidentSeverity severity) {
    IncidentResult result;
    result.ok = true;
    result.effectiveSeverity = severity;
    if (lastMode_ == IncidentResponseMode::Active ||
        containment_.networkQuarantined) {
        std::string error;
        if (!network_->applyQuarantine(false, error)) {
            result.ok = false;
            result.detail = "reversible containment cleanup failed: " + error;
        }
    }
    containment_ = {};
    runtime_ = result.ok ? RuntimeState::Inactive : RuntimeState::Degraded;
    result.runtime = runtime_;
    lastMode_ = mode;
    return result;
}

// The containment flow. Severity determines WHICH actions are performed; the
// runtime state records whether they were PROVEN.
//
//   SOFT      : the PAM access gate denies nothing yet; nothing to terminate.
//   STANDARD  : deny new ordinary logins, then LOCK graphical sessions and
//               VERIFY the lock. An unverifiable lock escalates to session
//               termination. SSH/TTY sessions are terminated outright.
//   HARD      : deny new ordinary logins and terminate ALL ordinary login
//               sessions. Background user processes may survive.
//   ISOLATE   : quarantine the network as early as possible, deny new logins,
//               terminate sessions AND the affected ordinary user runtime
//               (including lingering user managers).
IncidentResult IncidentController::applyContainment(
    IncidentSeverity severity,
    const std::string& reason) {
    IncidentResult result;
    result.effectiveSeverity = severity;
    runtime_ = RuntimeState::Applying;

    ContainmentStatus status;
    status.pamGateActive = false;
    std::vector<std::string> failures;
    if (severity >= IncidentSeverity::Standard) {
        std::string gateDiagnostic;
        try {
            status.pamGateActive = accessGateVerifier_ &&
                accessGateVerifier_(gateDiagnostic);
        } catch (...) {
            gateDiagnostic = "PAM gate verifier failed";
        }
        if (!status.pamGateActive) {
            failures.emplace_back("PAM incident access gate is unproven: " +
                                  gateDiagnostic);
        }
    }

    if (incidentSeverityIsUnlocked(severity)) {
        // Clearing removes the reversible containment state. It deliberately
        // does NOT unlock any desktop session: unblocking a user's screen is
        // an interactive decision, not a side effect of clearing an incident.
        std::string networkDiagnostic;
        const bool networkOk =
            network_->applyQuarantine(false, networkDiagnostic);
        status.networkQuarantined = false;
        status.pamGateActive = false;
        status.sessionsContained = true;
        status.userRuntimeContained = true;

        containment_ = status;
        runtime_ = (networkOk && status.sessionsContained)
            ? RuntimeState::Inactive
            : RuntimeState::Degraded;
        result.runtime = runtime_;
        result.ok = runtime_ == RuntimeState::Inactive;
        result.detail = networkOk
            ? "incident cleared"
            : "incident cleared but network quarantine removal failed: " +
                networkDiagnostic;
        return result;
    }

    // Network quarantine: applied as early as possible for ISOLATE.
    if (severity == IncidentSeverity::Isolate) {
        std::string networkDiagnostic;
        const bool networkOk =
            network_->applyQuarantine(true, networkDiagnostic);
        status.networkQuarantined = networkOk;
        if (!networkOk) failures.emplace_back("network quarantine failed: " + networkDiagnostic);
    }

    // Session containment. SOFT does not touch existing sessions.
    if (severity >= IncidentSeverity::Standard && sessions_ != nullptr) {
        const auto inventory = sessions_->listSessions();
        std::vector<LoginSession> toTerminate;
        if (!inventory.proven) {
            failures.emplace_back("session inventory is unproven: " +
                                  inventory.diagnostic);
        }
        if (inventory.proven) for (const LoginSession& session : inventory.sessions) {
            if (!isOrdinaryTarget(session)) {
                if (!session.recovery && !session.serviceAccount &&
                    session.uid != 0) {
                    failures.emplace_back("session target identity is unproven: " +
                                          session.id);
                }
                continue;
            }
            const SessionKind kind = sessions_->classifySession(session);
            if (severity == IncidentSeverity::Standard &&
                kind == SessionKind::Graphical) {
                // A successful LockSession() call is NOT a proven lock, so the
                // lock is verified independently. An unverifiable lock escalates
                // to session termination rather than assuming success.
                const session::ContainmentOutcome lockOutcome =
                    sessions_->lockSession(session);
                std::string verifyDiagnostic;
                if (lockOutcome.performed &&
                    sessions_->verifySessionLocked(session, verifyDiagnostic)) {
                    continue;
                }
                toTerminate.push_back(session);
                continue;
            }
            // HARD/ISOLATE terminate everything; at STANDARD a terminal session
            // (ssh/tty) cannot be locked, so it is terminated as well.
            toTerminate.push_back(session);
        }

        for (const LoginSession& session : toTerminate) {
            const session::ContainmentOutcome outcome =
                sessions_->terminateSession(session);
            if (!outcome.performed) failures.emplace_back(
                "session termination request failed for " + session.id + ": " + outcome.diagnostic);
        }

        std::string goneDiagnostic = inventory.proven ? "" : inventory.diagnostic;
        const bool sessionsGone = inventory.proven && (toTerminate.empty() ||
            sessions_->verifySessionsGone(toTerminate, goneDiagnostic));
        status.sessionsContained = sessionsGone;
        if (!sessionsGone) {
            failures.emplace_back("session containment could not be proven: " + goneDiagnostic);
        }
    } else if (severity >= IncidentSeverity::Standard && sessions_ == nullptr) {
        // No containment backend wired: containment cannot be claimed.
        status.sessionsContained = false;
        failures.emplace_back("session containment backend is unavailable");
    } else {
        status.sessionsContained = true;
    }

    // ISOLATE additionally terminates the affected ordinary user runtime,
    // including lingering user managers, so a contained attacker cannot keep a
    // foothold outside any login session.
    if (severity == IncidentSeverity::Isolate && sessions_ != nullptr) {
        const auto inventory = sessions_->listUsers();
        bool usersProven = inventory.proven;
        if (!inventory.proven) {
            failures.emplace_back("user inventory is unproven: " +
                                  inventory.diagnostic);
        }
        if (inventory.proven) for (const LoginUser& user : inventory.users) {
            // Service accounts and recovery identities are never terminated,
            // and the target set comes from logind - never from /etc/passwd or
            // from a bare UID >= UID_MIN test.
            if (user.recovery || user.serviceAccount || user.uid == 0) {
                continue;
            }
            if (!user.ordinary) {
                usersProven = false;
                failures.emplace_back("user target identity is unproven: " +
                                      std::to_string(user.uid));
                continue;
            }
            const session::ContainmentOutcome outcome =
                sessions_->terminateUser(user);
            if (!outcome.performed) {
                failures.emplace_back("user runtime termination failed for uid " +
                    std::to_string(user.uid) + ": " + outcome.diagnostic);
            }
            std::string runtimeDiagnostic;
            if (!sessions_->verifyUserRuntimeGone(user, runtimeDiagnostic)) {
                usersProven = false;
                failures.emplace_back("user runtime containment could not be proven: " + runtimeDiagnostic);
            }
        }
        status.userRuntimeContained = usersProven;
    } else if (severity == IncidentSeverity::Isolate) {
        status.userRuntimeContained = false;
        failures.emplace_back("user runtime containment backend is unavailable");
    } else {
        status.userRuntimeContained = true;
    }

    containment_ = status;
    const bool complete = failures.empty() &&
        (severity < IncidentSeverity::Standard ||
         (status.pamGateActive && status.sessionsContained)) &&
        (severity != IncidentSeverity::Isolate ||
         (status.networkQuarantined && status.userRuntimeContained));
    runtime_ = complete ? RuntimeState::Active : RuntimeState::Degraded;
    result.runtime = runtime_;
    result.ok = complete;
    result.detail = reason;
    for (const std::string& failure : failures) {
        result.detail += "; " + failure;
    }
    return result;
}

// Public operations.

IncidentResult IncidentController::raise(
    IncidentSeverity requested,
    const IncidentSource& source,
    const std::string& reason) {
    // Transitions are serialised so two concurrent detectors cannot interleave
    // their read/compute/write cycles.
    std::lock_guard<std::mutex> guard(transitionMutex_);

    const auto mode = resolveMode();
    if (mode.mode == IncidentResponseMode::Off) {
        const auto current = stateStore_.read();
        IncidentResult ignored = settleNonActiveMode(
            mode.mode, current.provenance == IncidentStateStore::Provenance::Proven
                           ? current.severity : IncidentSeverity::Isolate);
        ignored.previousSeverity = ignored.effectiveSeverity;
        ignored.persistentStateBroken =
            current.provenance != IncidentStateStore::Provenance::Proven;
        ignored.ignoredByMode = true;
        ignored.detail = "incident ignored in OFF mode";
        // OFF acknowledges the event WITHOUT any write, so no NEW persistence
        // obligation exists for this event. persistenceConfirmed describes the
        // outcome of THIS raise call, not the provenance of the historical
        // lockstatus: proving that the old state was readable is not a
        // proof that this event's severity was (or needed to be) durably
        // recorded. A detector may therefore rely on
        // (acknowledged, persistence_confirmed) = (true, false) here.
        ignored.persistenceConfirmed = false;
        return ignored;
    }

    const IncidentStateStore::ReadResult before = stateStore_.read();
    IncidentResult result;
    result.previousSeverity =
        before.provenance == IncidentStateStore::Provenance::Proven
            ? before.severity
            : IncidentSeverity::Isolate;

    const IncidentStateStore::RaiseResult raised =
        stateStore_.raiseToAtLeast(requested);
    result.ok = raised.durable;
    result.effectiveSeverity = raised.durable
        ? raised.effectiveSeverity
        : IncidentSeverity::Isolate;
    result.escalated = raised.escalated;
    // The persistence acknowledgement comes from the ACTUAL store outcome, not
    // from containment or from a severity comparison.
    result.persistenceConfirmed = raised.durable;
    result.persistentStateBroken =
        stateStore_.read().provenance != IncidentStateStore::Provenance::Proven;
    result.detail = raised.detail;

    if (!raised.durable) {
        if (mode.mode == IncidentResponseMode::Passive) {
            IncidentResult passive = settleNonActiveMode(mode.mode, IncidentSeverity::Isolate);
            passive.ok = false;
            passive.previousSeverity = result.previousSeverity;
            passive.escalated = result.escalated;
            passive.persistentStateBroken = true;
            passive.detail = "incident state could not be persisted in PASSIVE mode";
            recordAudit("incident_persistence_failed", passive, source, reason);
            notifySeverity(IncidentSeverity::Isolate, reason);
            return passive;
        }
        // Neither the requested severity nor a durable absence could be
        // established. The persistent witness may still claim a lower severity,
        // so the runtime containment is escalated to ISOLATE and the runtime
        // state becomes DEGRADED: the system is contained, but FIC cannot prove
        // the containment is the recorded one.
        // Audit is a bounded observability concern: a failure to record one
        // must never cancel or delay the containment itself.
        IncidentResult contained = applyContainment(
            IncidentSeverity::Isolate,
            "incident state could not be persisted; containing at ISOLATE");
        contained.previousSeverity = result.previousSeverity;
        contained.escalated = result.escalated;
        contained.persistentStateBroken = result.persistentStateBroken;
        contained.ok = false;
        contained.runtime = RuntimeState::Degraded;
        runtime_ = RuntimeState::Degraded;
        contained.effectiveSeverity = IncidentSeverity::Isolate;
        recordAudit("incident_persistence_failed", contained, source, reason);
        recordAudit("incident_action_failed", contained, source, reason);
        notifySeverity(IncidentSeverity::Isolate, reason);
        return contained;
    }

    if (mode.mode == IncidentResponseMode::Passive) {
        IncidentResult passive = settleNonActiveMode(mode.mode, result.effectiveSeverity);
        result.ok = result.ok && passive.ok;
        result.runtime = passive.runtime;
        result.detail = passive.detail.empty() ? raised.detail : passive.detail;
        recordAudit("incident_raise", result, source, reason);
        if (result.escalated) notifySeverity(result.effectiveSeverity, reason);
        return result;
    }
    lastMode_ = IncidentResponseMode::Active;

    const IncidentResult contained = applyContainment(
        result.effectiveSeverity, reason);
    result.runtime = contained.runtime;
    result.detail = contained.detail.empty() ? result.detail : contained.detail;
    // The incident is only fully established when BOTH halves succeeded: the
    // severity is durably persisted AND its containment is proven. A proven
    // persistence with failed containment is DEGRADED, never "ok".
    result.ok = result.ok && contained.ok;
    recordAudit(contained.ok ? "incident_raise" : "incident_action_failed",
                result, source, reason);
    // Notification is a UX concern and must never gate containment: it is
    // emitted only for a genuine escalation, so a repeated raise of the same
    // level does not spam identical desktop notifications.
    if (result.escalated) {
        notifySeverity(result.effectiveSeverity, reason);
    }
    return result;
}

IncidentResult IncidentController::clear(const std::string& actor) {
    std::lock_guard<std::mutex> guard(transitionMutex_);
    const auto mode = resolveMode();
    runtime_ = RuntimeState::Clearing;

    const IncidentStateStore::ReadResult before = stateStore_.read();
    IncidentResult result;
    result.previousSeverity =
        before.provenance == IncidentStateStore::Provenance::Proven
            ? before.severity
            : IncidentSeverity::Isolate;

    const IncidentStateStore::ClearResult cleared = stateStore_.clear();
    result.ok = cleared.ok;
    result.effectiveSeverity = cleared.effectiveSeverity;
    result.persistentStateBroken =
        stateStore_.read().provenance != IncidentStateStore::Provenance::Proven;
    result.detail = cleared.detail;

    if (!cleared.ok) {
        // Compensation may have replaced the previous incident with
        // BROKEN/ISOLATE. Reconcile that effective severity instead of
        // preserving an obsolete runtime proof from before the clear.
        const IncidentResult contained = mode.mode == IncidentResponseMode::Active
            ? applyContainment(cleared.effectiveSeverity, "failed administrative clear")
            : settleNonActiveMode(mode.mode, cleared.effectiveSeverity);
        result.runtime = contained.runtime;
        if (cleared.persistence !=
            IncidentStateStore::PersistenceResult::DurableConfirmed) {
            runtime_ = RuntimeState::Degraded;
            result.runtime = runtime_;
        }
        result.detail += "; " + contained.detail;
        IncidentSource source;
        source.name = "administrator";
        recordAudit("incident_clear", result, source,
                    "clear refused for actor " + actor);
        return result;
    }

    // The persistent state is now a durably proven UNLOCKED, so the reversible
    // containment state is removed. No desktop session is unlocked.
    const IncidentResult contained = mode.mode == IncidentResponseMode::Active
        ? applyContainment(IncidentSeverity::Unlocked, "incident cleared by " + actor)
        : settleNonActiveMode(mode.mode, IncidentSeverity::Unlocked);
    result.runtime = contained.runtime;
    result.detail = contained.detail;
    result.ok = result.ok && contained.ok;

    lastNotified_.reset();
    IncidentSource source;
    source.name = "administrator";
    recordAudit("incident_clear", result, source,
                "cleared by " + actor);
    if (result.ok && result.previousSeverity != IncidentSeverity::Unlocked &&
        notifySink_) {
        try {
            notifySink_(IncidentSeverity::Unlocked, "incident cleared by " + actor);
        } catch (...) {
            // Notification cannot invalidate a completed clear.
        }
    }
    return result;
}

IncidentStatus IncidentController::status() {
    std::lock_guard<std::mutex> guard(transitionMutex_);
    const IncidentStateStore::ReadResult read = stateStore_.read();
    IncidentStatus status;
    status.responseMode = resolveMode();
    status.stateProven = read.provenance == IncidentStateStore::Provenance::Proven;
    status.provenance = read.provenance;
    // Only a positively proven UNLOCKED means "no incident". Everything else -
    // including a missing, corrupt or unprovable state file - is ISOLATE.
    status.severity = status.stateProven
        ? read.severity
        : IncidentSeverity::Isolate;
    status.runtime = runtime_;
    status.containment = containment_;
    status.detail = read.detail;
    return status;
}

IncidentResult IncidentController::reconcile() {
    std::lock_guard<std::mutex> guard(transitionMutex_);
    // The status is derived inline rather than through status(): the public
    // accessor takes the same lock, and re-entering it here would deadlock.
    const IncidentStateStore::ReadResult read = stateStore_.read();
    IncidentResult result;
    result.previousSeverity =
        read.provenance == IncidentStateStore::Provenance::Proven
            ? read.severity
            : IncidentSeverity::Isolate;
    result.effectiveSeverity = result.previousSeverity;
    result.persistentStateBroken =
        read.provenance != IncidentStateStore::Provenance::Proven;
    result.runtime = runtime_;

    // Reconciliation NEVER changes the severity: it only re-proves the
    // containment that the persisted severity requires.
    const auto mode = resolveMode();
    const IncidentResult contained = mode.mode == IncidentResponseMode::Active
        ? applyContainment(result.effectiveSeverity, "startup reconciliation")
        : settleNonActiveMode(mode.mode, result.effectiveSeverity);
    if (mode.mode == IncidentResponseMode::Active)
        lastMode_ = IncidentResponseMode::Active;
    result.runtime = contained.runtime;
    result.ok = contained.ok &&
        (mode.mode == IncidentResponseMode::Off ||
         read.provenance == IncidentStateStore::Provenance::Proven);
    if (!result.ok) {
        runtime_ = RuntimeState::Degraded;
        result.runtime = runtime_;
    }
    result.detail = contained.detail;
    return result;
}

void IncidentController::recordAudit(
    const std::string& event,
    const IncidentResult& result,
    const IncidentSource& source,
    const std::string& reason) const {
    if (!auditSink_) {
        return;
    }
    // The controller never decides WHERE the audit trail lives: it hands the
    // structured event to the injected sink, which the daemon wires to the
    // security audit trail. A sink failure is swallowed on purpose - audit and
    // notification must never cancel or delay containment.
    try {
        auditSink_(::fic::core::security_audit::serializeJsonLine(
            ::fic::core::security_audit::makeEvent("fic", json{
                {"event", event},
                {"previous_severity",
                 ::fic::core::incidentSeverityToken(result.previousSeverity)},
                {"effective_severity",
                 ::fic::core::incidentSeverityToken(result.effectiveSeverity)},
                {"escalated", result.escalated},
                {"persistent_state_broken", result.persistentStateBroken},
                {"runtime_state", runtimeStateToString(result.runtime)},
                {"source", source.name},
                {"reason", reason},
                {"detail", result.detail},
                {"policy", {
                    {"module", source.policyModule},
                    {"submodule", source.policySubmodule},
                    {"policy", source.policyName}
                }},
                {"device_id", source.deviceId},
                {"failure_origin", source.failureOrigin}
            })));
    } catch (...) {
        // An audit failure must never cancel containment.
    }
}

void IncidentController::notifySeverity(
    IncidentSeverity severity,
    const std::string& reason) const {
    // Deduplicate: the same severity must not produce repeated identical
    // desktop notifications. A new, higher severity always notifies.
    if (lastNotified_.has_value() &&
        !::fic::core::incidentSeverityLess(*lastNotified_, severity)) {
        return;
    }
    lastNotified_ = severity;
    if (!notifySink_) {
        return;
    }
    try {
        notifySink_(severity, reason);
    } catch (...) {
        // A notification failure must never cancel or delay containment.
    }
}

} // namespace fic::incident
