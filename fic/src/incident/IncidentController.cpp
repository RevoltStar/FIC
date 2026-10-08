#include "incident/IncidentController.h"

#include <fic/core/logging/Logger.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/runtime/SystemBootInfo.h>
#include <fic/core/logging/SecurityAudit.h>
#include <fic/core/notification/NotifyUser.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <limits>
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
      targetStore_(IncidentSessionTargetStore::forTesting({})),
      sessions_(nullptr),
      network_(std::make_shared<NullIncidentNetworkBackend>()) {
}

IncidentController::IncidentController(
    IncidentStateStore stateStore,
    std::shared_ptr<session::SessionContainmentBackend> sessions,
    std::shared_ptr<IncidentNetworkBackend> network)
    : IncidentController(std::move(stateStore),
          // Model A default: the durable target store lives beside the
          // lockstatus file, under the same root-owned security boundary.
          IncidentSessionTargetStore(stateStore.path()),
          std::move(sessions), std::move(network)) {
}

IncidentController::IncidentController(
    IncidentStateStore stateStore,
    IncidentSessionTargetStore targetStore,
    std::shared_ptr<session::SessionContainmentBackend> sessions,
    std::shared_ptr<IncidentNetworkBackend> network)
    : stateStore_(std::move(stateStore)),
      targetStore_(std::move(targetStore)),
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
    const std::string& reason,
    bool allowTargetMutation) {
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

    // The marker is required for EVERY active severity, including SOFT.
    // A broken lockstatus or missing/unproven target store cannot authorize
    // any session or user action, even if a stale target file still exists.
    const auto lifecycle = allowTargetMutation
        ? prepareActiveTargetStore()
        : TargetRegistration{false, "incident lifecycle is unproven"};
    if (!lifecycle.ok)
        failures.emplace_back("incident target lifecycle is unproven: " +
                              lifecycle.detail);

    // Session containment. SOFT does not touch existing sessions.
    // Model A: every ordinary login session FIC is about to act on is FIRST
    // registered in the durable target store, because TerminateSession
    // destroys the very evidence that selected the user. A failed durable
    // registration must prevent the destructive action.
    bool targetsUsable = false;
    if (severity >= IncidentSeverity::Standard && sessions_ != nullptr &&
        lifecycle.ok) {
        const auto inventory = sessions_->listSessions();
        std::vector<LoginSession> toTerminate;
        if (!inventory.proven) {
            failures.emplace_back("session inventory is unproven: " +
                                  inventory.diagnostic);
        }
        std::vector<IncidentSessionTarget> newTargets;
        if (inventory.proven) for (const LoginSession& session : inventory.sessions) {
            if (!isOrdinaryTarget(session)) {
                // Protected classes (greeter, lock-screen, manager-early),
                // recovery identities, root, and the manager/background
                // runtime sessions of already-selected ordinary users are not
                // session-level targets. Unknown classes never reach here:
                // the backend already marked the inventory unproven.
                continue;
            }
            IncidentSessionTarget target;
            target.uid = session.uid;
            target.canonicalName = session.user;
            target.sessionId = session.id;
            target.sessionStartTimestamp = session.startTimestamp;
            target.sessionClass = session.className;
            target.runtimeObligation =
                IncidentSessionTarget::RuntimeObligation::Pending;
            newTargets.push_back(std::move(target));

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

        // Durable registration BEFORE any destructive action. The merge keeps
        // previously selected targets; the incident fence already established
        // an empty current generation, even when there are no login sessions.
        if (inventory.proven) {
            const auto registration =
                registerSessionTargets(std::move(newTargets));
            targetsUsable = registration.ok;
            if (!registration.ok) {
                failures.emplace_back(
                    "durable session target registration failed: " +
                    registration.detail);
            }
        }
        // If the inventory was unproven, targetsUsable stays false: no
        // destructive action below, because selection itself is unproven.

        // Never destroy the proving session of a target whose durable
        // registration did not succeed.
        if (!targetsUsable) toTerminate.clear();

        for (const LoginSession& session : toTerminate) {
            const session::ContainmentOutcome outcome =
                sessions_->terminateSession(session);
            if (!outcome.performed) failures.emplace_back(
                "session termination request failed for " + session.id + ": " + outcome.diagnostic);
        }

        std::string goneDiagnostic = inventory.proven ? "" : inventory.diagnostic;
        const bool sessionsGone = inventory.proven && targetsUsable &&
            (toTerminate.empty() ||
            sessions_->verifySessionsGone(toTerminate, goneDiagnostic));
        status.sessionsContained = sessionsGone;
        if (!sessionsGone) {
            failures.emplace_back("session containment could not be proven: " + goneDiagnostic);
        }
    } else if (severity >= IncidentSeverity::Standard) {
        // No containment backend wired: containment cannot be claimed.
        status.sessionsContained = false;
        if (sessions_ == nullptr)
            failures.emplace_back("session containment backend is unavailable");
    } else {
        status.sessionsContained = true;
    }

    // ISOLATE additionally terminates the user runtime of the users that were
    // DURABLY selected by ordinary login sessions during this incident
    // (Model A). ListUsers is never a source of new targets: a lingering-only
    // service without a previously qualifying login session is NOT a target.
    if (severity == IncidentSeverity::Isolate && sessions_ != nullptr &&
        lifecycle.ok) {
        bool usersProven = false;
        // The durable target provenance is loaded fresh from the store: it
        // must survive session termination, partial failures and restarts,
        // so it is never taken from the in-memory session pass alone.
        IncidentSessionTargetStore::ReadResult store =
            targetStore_.read();
        std::vector<IncidentSessionTarget> obligations =
            store.targets;
        bool storeUsable = false;
        if (store.provenance ==
            IncidentSessionTargetStore::ReadProvenance::Proven) {
            const std::string bootId = currentIncidentBootId();
            storeUsable = !bootId.empty() && store.bootId == bootId &&
                incidentGeneration_.has_value() &&
                *incidentGeneration_ == store.incidentGeneration;
            if (!storeUsable)
                failures.emplace_back("incident target store changed during containment");
        } else if (store.provenance ==
                   IncidentSessionTargetStore::ReadProvenance::Absent) {
            // An active incident with a missing store is NOT a proven empty
            // target set: degrade instead of guessing.
            failures.emplace_back(
                "incident session target store is absent while the incident "
                "is unresolved");
        } else {
            failures.emplace_back(
                "incident session target store is unprovable: " +
                store.detail);
        }

        if (!storeUsable || !targetsUsable) {
            // No unsafe action and never a false success.
            if (!targetsUsable)
                failures.emplace_back("session target registration is unproven");
        } else {
            usersProven = true;
            // Discharged records are past observations, not permanent proof.
            // A proven logind user is a reactivated runtime of an already
            // selected identity. Re-arm all such targets in ONE durable
            // snapshot before ANY user-runtime mutation in this pass.
            bool rearmChanged = false;
            for (IncidentSessionTarget& target : obligations) {
                if (target.runtimeObligation !=
                    IncidentSessionTarget::RuntimeObligation::Discharged)
                    continue;
                const auto lookup = sessions_->lookupProvenUser(
                    target.uid, target.canonicalName);
                if (lookup.status == session::SessionContainmentBackend::
                                         RegisteredUserLookup::Status::Unproven) {
                    usersProven = false;
                    failures.emplace_back(
                        "discharged user target is unproven for uid " +
                        std::to_string(target.uid) + ": " + lookup.diagnostic);
                    continue;
                }
                if (lookup.status == session::SessionContainmentBackend::
                                         RegisteredUserLookup::Status::Found) {
                    target.runtimeObligation =
                        IncidentSessionTarget::RuntimeObligation::Pending;
                    rearmChanged = true;
                    continue;
                }
                LoginUser user;
                user.uid = target.uid;
                user.name = target.canonicalName;
                std::string diagnostic;
                if (!sessions_->verifyUserRuntimeGone(user, diagnostic)) {
                    usersProven = false;
                    failures.emplace_back(
                        "discharged user runtime absence is unproven for uid " +
                        std::to_string(target.uid) + ": " + diagnostic);
                }
            }
            bool rearmDurable = true;
            if (rearmChanged) {
                const auto written = targetStore_.writeIfCurrent(
                    store, store.bootId, store.incidentGeneration, obligations);
                if (!written.durable) {
                    rearmDurable = false;
                    usersProven = false;
                    failures.emplace_back(
                        "re-arming user-runtime obligations could not be "
                        "made durable: " + written.detail);
                } else {
                    store = targetStore_.read();
                    rearmDurable = store.provenance ==
                            IncidentSessionTargetStore::ReadProvenance::Proven &&
                        store.bootId == currentIncidentBootId() &&
                        incidentGeneration_.has_value() &&
                        store.incidentGeneration == *incidentGeneration_ &&
                        store.targets.size() == obligations.size();
                    if (rearmDurable) {
                        for (std::size_t i = 0; i < obligations.size(); ++i) {
                            const auto& actual = store.targets[i];
                            const auto& expected = obligations[i];
                            if (actual.uid != expected.uid ||
                                actual.canonicalName != expected.canonicalName ||
                                actual.sessionId != expected.sessionId ||
                                actual.sessionStartTimestamp !=
                                    expected.sessionStartTimestamp ||
                                actual.sessionClass != expected.sessionClass ||
                                actual.runtimeObligation !=
                                    expected.runtimeObligation) {
                                rearmDurable = false;
                                break;
                            }
                        }
                    }
                    if (!rearmDurable) {
                        usersProven = false;
                        failures.emplace_back(
                            "target store changed after durable re-arm");
                    }
                }
            }
            bool obligationsChanged = false;
            for (IncidentSessionTarget& target : obligations) {
                if (!rearmDurable) break;
                if (target.runtimeObligation ==
                    IncidentSessionTarget::RuntimeObligation::Discharged) {
                    continue;
                }
                const auto lookup = sessions_->lookupProvenUser(
                    target.uid, target.canonicalName);
                if (lookup.status ==
                    session::SessionContainmentBackend::RegisteredUserLookup::
                        Status::Unproven) {
                    // UID reuse, identity change or logind failure: no unsafe
                    // action, the obligation stays pending.
                    usersProven = false;
                    failures.emplace_back(
                        "registered user target is unproven for uid " +
                        std::to_string(target.uid) + ": " + lookup.diagnostic);
                    continue;
                }
                LoginUser user = lookup.status ==
                        session::SessionContainmentBackend::
                            RegisteredUserLookup::Status::Found
                    ? lookup.user
                    : LoginUser{};
                user.uid = target.uid;
                user.name = target.canonicalName;
                const session::ContainmentOutcome outcome =
                    sessions_->terminateUser(user);
                if (!outcome.performed &&
                    lookup.status == session::SessionContainmentBackend::
                                         RegisteredUserLookup::Status::Found) {
                    failures.emplace_back(
                        "user runtime termination failed for uid " +
                        std::to_string(target.uid) + ": " +
                        outcome.diagnostic);
                }
                std::string runtimeDiagnostic;
                if (sessions_->verifyUserRuntimeGone(user, runtimeDiagnostic)) {
                    // Proven gone (or already absent with the manager proved
                    // stopped): the obligation is discharged durably.
                    target.runtimeObligation =
                        IncidentSessionTarget::RuntimeObligation::Discharged;
                    obligationsChanged = true;
                } else {
                    usersProven = false;
                    failures.emplace_back(
                        "user runtime containment could not be proven for uid " +
                        std::to_string(target.uid) + ": " + runtimeDiagnostic);
                }
            }
            // Persist discharged obligations so a restart does not redo them;
            // a failed durable write keeps everything pending and degrades.
            if (obligationsChanged) {
                const std::string bootId = currentIncidentBootId();
                const IncidentSessionTargetStore::WriteResult persisted =
                    targetStore_.writeIfCurrent(
                        store, bootId, store.incidentGeneration, obligations);
                if (!persisted.durable) {
                    usersProven = false;
                    failures.emplace_back(
                        "discharging user-runtime obligations could not be "
                        "made durable: " + persisted.detail);
                    for (IncidentSessionTarget& target : obligations) {
                        target.runtimeObligation =
                            IncidentSessionTarget::RuntimeObligation::Pending;
                    }
                }
            }
        }
        status.userRuntimeContained = usersProven;
    } else if (severity == IncidentSeverity::Isolate) {
        status.userRuntimeContained = false;
        if (sessions_ == nullptr)
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
    // A raise from a durably proven UNLOCKED starts a NEW incident: the
    // durable target store is then replaced (generation+1) so targets of a
    // previous incident can never authorize actions here.
    const bool newIncident =
        before.provenance == IncidentStateStore::Provenance::Proven &&
        before.severity == IncidentSeverity::Unlocked;

    if (newIncident && !incidentSeverityIsUnlocked(requested)) {
        const TargetRegistration fenced = fenceNewIncident();
        if (!fenced.ok) {
            const auto broken = stateStore_.encodeDurableBrokenState();
            result.ok = false;
            result.effectiveSeverity = IncidentSeverity::Isolate;
            result.persistenceConfirmed = false;
            result.persistentStateBroken = true;
            result.detail = "new incident generation could not be fenced: " +
                fenced.detail + "; BROKEN_STATE fallback: " + broken.detail;
            const auto contained = mode.mode == IncidentResponseMode::Active
                ? applyContainment(IncidentSeverity::Isolate,
                    "incident generation fencing failed", false)
                : settleNonActiveMode(mode.mode, IncidentSeverity::Isolate);
            result.runtime = runtime_ = RuntimeState::Degraded;
            result.detail += "; " + contained.detail;
            recordAudit("incident_persistence_failed", result, source, reason);
            notifySeverity(IncidentSeverity::Isolate, reason);
            return result;
        }
    }

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
            "incident state could not be persisted; containing at ISOLATE",
            false);
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
    result.persistenceConfirmed = cleared.ok;
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
    // Model A: the durable targets of the finished incident are cleared so
    // they can never authorize actions in a future incident. A failed cleanup
    // is tolerable here (lockstatus is authoritative and the next raise
    // replaces the whole store with a new generation), but it is reported.
    bool targetCleanupDurable = false;
    {
        const std::string bootId = currentIncidentBootId();
        const IncidentSessionTargetStore::ReadResult store =
            targetStore_.read();
        IncidentSessionTargetStore::WriteResult cleaned;
        if (bootId.empty())
            cleaned.detail = "kernel boot id is unprovable";
        else if (store.provenance == IncidentSessionTargetStore::ReadProvenance::Unprovable)
            cleaned.detail = "target store is unprovable: " + store.detail;
        else if (store.provenance == IncidentSessionTargetStore::ReadProvenance::Proven &&
                 store.incidentGeneration == std::numeric_limits<std::uint64_t>::max())
            cleaned.detail = "incident generation overflow";
        else {
            const std::uint64_t nextGeneration =
                store.provenance == IncidentSessionTargetStore::ReadProvenance::Proven
                    ? store.incidentGeneration + 1 : 1;
            cleaned = targetStore_.writeIfCurrent(store, bootId, nextGeneration, {});
        }
        targetCleanupDurable = cleaned.durable;
        if (!cleaned.durable) {
            result.detail += "; incident session target cleanup failed: " +
                             cleaned.detail;
        }
        incidentGeneration_.reset();
    }
    const IncidentResult contained = mode.mode == IncidentResponseMode::Active
        ? applyContainment(IncidentSeverity::Unlocked, "incident cleared by " + actor)
        : settleNonActiveMode(mode.mode, IncidentSeverity::Unlocked);
    result.runtime = contained.runtime;
    result.detail += "; " + contained.detail;
    result.ok = result.ok && contained.ok && targetCleanupDurable;
    if (!targetCleanupDurable) result.runtime = runtime_ = RuntimeState::Degraded;

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

// Model A helpers ------------------------------------------------------------
//
// The durable target store is bound to the current incident by a generation
// counter: every new incident (raise from a durably proven UNLOCKED) replaces
// the store with generation+1 and only its own targets. A stale record from a
// previous incident (e.g. its cleanup write failed) can therefore never
// authorize user-runtime actions in a new incident: the ISOLATE phase requires
// the store generation to match the controller's known generation for the
// current incident, and degrades on any mismatch instead of guessing.

std::string IncidentController::currentIncidentBootId() const {
    return bootIdProvider_ ? bootIdProvider_() : SystemBootInfo::get_boot_id();
}

IncidentController::TargetRegistration
IncidentController::fenceNewIncident() {
    const std::string bootId = currentIncidentBootId();
    if (bootId.empty()) return {false, "kernel boot id is unprovable"};
    const IncidentSessionTargetStore::ReadResult store = targetStore_.read();
    if (store.provenance == IncidentSessionTargetStore::ReadProvenance::Unprovable)
        return {false, "target store is unprovable: " + store.detail};
    if (store.provenance == IncidentSessionTargetStore::ReadProvenance::Proven &&
        store.incidentGeneration == std::numeric_limits<std::uint64_t>::max())
        return {false, "incident generation overflow"};
    const std::uint64_t generation =
        store.provenance == IncidentSessionTargetStore::ReadProvenance::Proven
            ? store.incidentGeneration + 1 : 1;
    const auto written = targetStore_.writeIfCurrent(store, bootId, generation, {});
    if (!written.durable) return {false, written.detail};
    incidentGeneration_ = generation;
    return {true, ""};
}

IncidentController::TargetRegistration
IncidentController::prepareActiveTargetStore() {
    const auto state = stateStore_.read();
    if (state.provenance != IncidentStateStore::Provenance::Proven ||
        incidentSeverityIsUnlocked(state.severity))
        return {false, "active lockstatus is not proven"};
    const std::string bootId = currentIncidentBootId();
    if (bootId.empty()) return {false, "kernel boot id is unprovable"};
    const auto store = targetStore_.read();
    if (store.provenance != IncidentSessionTargetStore::ReadProvenance::Proven)
        return {false, store.provenance ==
            IncidentSessionTargetStore::ReadProvenance::Absent
                ? "target store is absent during an active incident"
                : "target store is unprovable: " + store.detail};
    if (incidentGeneration_.has_value() &&
        *incidentGeneration_ != store.incidentGeneration)
        return {false, "target generation differs from current incident"};
    // On restart there is no in-memory generation. Schema 2's marker is a
    // durable witness of the new writer's fence-before-severity protocol;
    // a proven active lockstatus can only have been published after it.
    // Schema 1 is rejected by the store parser, never silently adopted.
    if (store.bootId != bootId) {
        // A new kernel boot discharges all prior runtime obligations. Drop
        // prior login authorizations before reading new-boot sessions.
        const auto rebased = targetStore_.writeIfCurrent(
            store, bootId, store.incidentGeneration, {});
        if (!rebased.durable)
            return {false, "previous-boot target rebase failed: " + rebased.detail};
    }
    incidentGeneration_ = store.incidentGeneration;
    return {true, ""};
}

IncidentController::TargetRegistration
IncidentController::registerSessionTargets(
    std::vector<IncidentSessionTarget> newTargets) {
    const std::string bootId = currentIncidentBootId();
    if (bootId.empty()) return {false, "kernel boot id is unprovable"};
    const auto store = targetStore_.read();
    if (store.provenance != IncidentSessionTargetStore::ReadProvenance::Proven ||
        store.bootId != bootId || !incidentGeneration_.has_value() ||
        *incidentGeneration_ != store.incidentGeneration)
        return {false, "current incident target store is unproven"};
    std::vector<IncidentSessionTarget> merged = store.targets;
    bool changed = false;
    for (IncidentSessionTarget& target : newTargets) {
        const auto existing = std::find_if(merged.begin(), merged.end(),
            [&](const auto& item) { return item.uid == target.uid; });
        if (existing != merged.end()) {
            if (existing->canonicalName != target.canonicalName)
                return {false, "target UID identity changed during incident"};
            if (existing->runtimeObligation ==
                IncidentSessionTarget::RuntimeObligation::Discharged) {
                // Inventory already proved this NEW ordinary login session.
                // Preserve its evidence and durably re-arm before the session
                // that proved selection may be terminated.
                existing->sessionId = target.sessionId;
                existing->sessionStartTimestamp = target.sessionStartTimestamp;
                existing->sessionClass = target.sessionClass;
                existing->runtimeObligation =
                    IncidentSessionTarget::RuntimeObligation::Pending;
                changed = true;
            }
            continue;
        }
        merged.push_back(std::move(target));
        changed = true;
    }
    // Reconciliation with no new session requires no write/fsync.
    if (!changed) return {true, ""};
    const auto written = targetStore_.writeIfCurrent(
        store, bootId, store.incidentGeneration, merged);
    return {written.durable, written.detail};
}

} // namespace fic::incident
