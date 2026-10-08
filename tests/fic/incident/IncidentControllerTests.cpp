#include "incident/IncidentController.h"

#include "incident/IncidentStateStore.h"
#include "incident/IncidentSessionTargetStore.h"
#include "incident/IncidentNotificationLevel.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/incident/IncidentSeverity.h>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using ::AtomicFileWriter;
using ::fic::core::IncidentSeverity;
using ::fic::incident::IncidentController;
using ::fic::incident::IncidentResult;
using ::fic::incident::IncidentSource;
using ::fic::incident::IncidentStateStore;
using ::fic::incident::IncidentSessionTargetStore;
using ::fic::incident::IncidentResponseMode;
using ::fic::incident::IncidentResponseModeResult;
using ::fic::incident::RuntimeState;
using ::fic::incident::incidentNotificationLevel;
using ::fic::session::LoginSession;
using ::fic::session::LoginUser;
using ::fic::session::SessionContainmentBackend;
using ::fic::session::SessionKind;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempTree {
public:
    TempTree() {
        char pattern[] = "/tmp/fic-incident-controller-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = created;
        std::filesystem::create_directories(root / "config");
        std::filesystem::create_directories(root / "log");
        statePath = root / "lockstatus";
    }
    ~TempTree() {
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }
    std::filesystem::path root;
    std::filesystem::path statePath;
};

void writeState(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::trunc);
    output << content;
    output.close();
    ::chmod(path.c_str(), 0640);
}

// Fake containment backend that records every action, so the decision logic
// can be proven without touching the host's real sessions.
class FakeSessions final : public SessionContainmentBackend {
public:
    std::vector<LoginSession> sessions{
        {"c1", 1000, "user1", "x11", SessionKind::Graphical, false,
         "user", "active", false, false, false, "", "", 12345},
        {"c2", 1000, "user1", "tty", SessionKind::Terminal, false,
         "user", "active", false, false, false, "", "", 12346},
        {"c3", 0, "root", "tty", SessionKind::Terminal, true,
         "user", "active", false, false, false, "", "", 12347},
    };
    std::vector<LoginUser> users{
        {1000, "user1", false, false, true},
        {0, "root", false, true, true},
        {999, "sshd", true, false, false},
    };

    // Knobs the tests turn to model unprovable actions.
    bool lockActuallyLocks = true;
    // The call is accepted (returns performed=true) but the object survives.
    // This models a backend that reports success without effect, and is the
    // case a "successful call == proven action" implementation would miss.
    bool sessionsActuallyRemoved = true;
    bool terminationPerformed = true;

    std::vector<std::string> actions;

    bool sessionsProven = true;
    bool usersProven = true;
    bool exposePartialInventory = false;
    ::fic::session::SessionInventoryResult listSessions() override {
        auto result = ::fic::session::SessionInventoryResult{
            sessionsProven, (sessionsProven || exposePartialInventory)
                ? sessions : std::vector<LoginSession>{},
            sessionsProven ? "" : "logind unavailable"};
        for (auto& session : result.sessions) session.ordinary = !session.recovery;
        return result;
    }
    ::fic::session::UserInventoryResult listUsers() override {
        auto result = ::fic::session::UserInventoryResult{
            usersProven, (usersProven || exposePartialInventory)
                ? users : std::vector<LoginUser>{},
            usersProven ? "" : "logind unavailable"};
        for (auto& user : result.users)
            user.ordinary = !user.recovery && !user.serviceAccount;
        return result;
    }

    SessionKind classifySession(const LoginSession& session) override {
        return session.kind;
    }

    ::fic::session::ContainmentOutcome lockSession(
        const LoginSession& session) override {
        actions.push_back("lock:" + session.id);
        return {true, ""};
    }

    bool verifySessionLocked(const LoginSession& session,
                             std::string& diagnostic) override {
        actions.push_back("verify-locked:" + session.id);
        if (!lockActuallyLocks) {
            diagnostic = "lock could not be proven";
            return false;
        }
        return true;
    }

    ::fic::session::ContainmentOutcome terminateSession(
        const LoginSession& session) override {
        actions.push_back("terminate-session:" + session.id);
        if (terminationPerformed && sessionsActuallyRemoved) {
            // Model the effect: a terminated session leaves the inventory, so
            // a later reconciliation finds nothing left to contain.
            sessions.erase(std::remove_if(
                sessions.begin(), sessions.end(),
                [&](const LoginSession& candidate) {
                    return candidate.id == session.id;
                }),
                sessions.end());
        }
        return {terminationPerformed, terminationPerformed ? "" : "refused"};
    }

    ::fic::session::ContainmentOutcome terminateUser(
        const LoginUser& user) override {
        actions.push_back("terminate-user:" + std::to_string(user.uid));
        users.erase(std::remove_if(
            users.begin(), users.end(),
            [&](const LoginUser& candidate) {
                return candidate.uid == user.uid;
            }),
            users.end());
        return {true, ""};
    }

    // The verification answer is independent of whether the call was
    // accepted: a backend may report success and still fail to remove the
    // session, which is exactly the case the controller must not confuse with
    // a proven containment.
    bool verifySessionsGone(const std::vector<LoginSession>& gone,
                            std::string& diagnostic) override {
        for (const LoginSession& session : gone) {
            actions.push_back("verify-gone:" + session.id);
        }
        for (const LoginSession& target : gone) {
            if (std::any_of(sessions.begin(), sessions.end(),
                            [&](const LoginSession& current) {
                                return current.id == target.id;
                            })) {
                diagnostic = "sessions are still present";
                return false;
            }
        }
        return true;
    }

    bool verifyUserRuntimeGone(const LoginUser& user,
                               std::string& diagnostic) override {
        actions.push_back("verify-user-runtime:" + std::to_string(user.uid));
        return true;
    }

    // Model A seam: the controller looks up only ALREADY-REGISTERED target
    // UIDs. The fake proves the recorded canonical name against the user
    // inventory and reports Absent once the runtime is gone.
    RegisteredUserLookup lookupProvenUser(
        uid_t uid, const std::string& expectedCanonicalName) override {
        RegisteredUserLookup result;
        const auto it = std::find_if(
            users.begin(), users.end(),
            [&](const LoginUser& candidate) { return candidate.uid == uid; });
        if (!usersProven) {
            result.diagnostic = "logind unavailable";
            return result;
        }
        if (it == users.end()) {
            result.status = RegisteredUserLookup::Status::Absent;
            return result;
        }
        if (it->name != expectedCanonicalName) {
            result.diagnostic = "registered UID now maps to a different account";
            return result;
        }
        result.status = RegisteredUserLookup::Status::Found;
        result.user = *it;
        return result;
    }

    bool acted(const std::string& action) const {
        return std::find(actions.begin(), actions.end(), action) != actions.end();
    }
};

class FakeNetwork final : public ::fic::incident::IncidentNetworkBackend {
public:
    bool quarantineActive = false;
    int applications = 0;
    bool succeed = true;

    bool applyQuarantine(bool enabled, std::string& diagnostic) override {
        ++applications;
        if (!succeed) {
            diagnostic = "nft refused the incident overlay";
            return false;
        }
        quarantineActive = enabled;
        return true;
    }
};

struct Harness {
    std::shared_ptr<FakeSessions> sessions = std::make_shared<FakeSessions>();
    std::shared_ptr<FakeNetwork> network = std::make_shared<FakeNetwork>();
    IncidentController controller;

    explicit Harness(const std::filesystem::path& statePath)
        : controller(IncidentStateStore(statePath), sessions, network) {
        if (!std::filesystem::exists(statePath)) {
            writeState(statePath, "UNLOCKED\n");
        }
    }
};

IncidentSource policySource(const std::string& name);

void testResponseModes(const TempTree& tree) {
    Harness harness(tree.statePath);
    IncidentResponseMode mode = IncidentResponseMode::Off;
    harness.controller.setModeResolver([&] {
        return IncidentResponseModeResult{mode, true, "test"};
    });
    int audits = 0, notifications = 0;
    harness.controller.setAuditSink([&](const std::string&) { ++audits; });
    harness.controller.setNotifySink([&](IncidentSeverity, const std::string&) {
        ++notifications;
    });
    const auto source = policySource("mode-test");
    const auto off = harness.controller.raise(IncidentSeverity::Hard, source, "off");
    require(off.ignoredByMode && off.ok, "OFF must report ignored incident");
    require(harness.controller.status().severity == IncidentSeverity::Unlocked,
            "OFF must preserve lockstatus");
    require(audits == 0 && notifications == 0 && harness.sessions->actions.empty() &&
            harness.network->applications == 0, "OFF must have no response effects");

    mode = IncidentResponseMode::Passive;
    const auto passive = harness.controller.raise(IncidentSeverity::Hard, source, "passive");
    require(passive.ok && harness.controller.status().severity == IncidentSeverity::Hard,
            "PASSIVE must persist HARD");
    require(audits == 1 && notifications == 1 && harness.sessions->actions.empty() &&
            harness.network->applications == 0, "PASSIVE must audit and notify without containment");

    mode = IncidentResponseMode::Active;
    const auto active = harness.controller.reconcile();
    require(!active.ok && active.runtime == RuntimeState::Degraded &&
            !harness.sessions->actions.empty(),
            "ACTIVE must immediately reconcile retained HARD");
    mode = IncidentResponseMode::Passive;
    harness.controller.reconcile();
    require(harness.controller.status().severity == IncidentSeverity::Hard &&
            harness.controller.status().runtime == RuntimeState::Inactive,
            "ACTIVE to PASSIVE must retain HARD and remove runtime containment");
    mode = IncidentResponseMode::Off;
    require(harness.controller.clear("admin").ok &&
            harness.controller.status().severity == IncidentSeverity::Unlocked,
            "OFF must allow explicit clear");
    writeState(tree.statePath, "BROKEN STATE\n");
    const auto brokenOff = harness.controller.reconcile();
    require(brokenOff.ok && brokenOff.persistentStateBroken &&
            brokenOff.runtime == RuntimeState::Inactive,
            "OFF must stay neutral even when historical lockstatus is broken");
}

IncidentSource policySource(const std::string& name) {
    IncidentSource source;
    source.name = "policy";
    source.policyModule = "AUDIT";
    source.policySubmodule = "test";
    source.policyName = name;
    source.failureOrigin = "own_apply_failure";
    return source;
}

// ---------------------------------------------------------------------------
// Invariant 4: IncidentController is the only runtime owner of the state, and
// severity is monotonic through it.
// ---------------------------------------------------------------------------

void testRaiseIsMonotonicThroughTheController(const TempTree& tree) {
    Harness harness(tree.statePath);
    IncidentSource source = policySource("a");

    const IncidentResult first =
        harness.controller.raise(IncidentSeverity::Hard, source, "policy failed");
    require(!first.ok && first.escalated, "the first raise persists but PAM gate is unavailable");
    require(first.effectiveSeverity == IncidentSeverity::Hard,
            "the effective severity must be HARD");
    require(first.runtime == RuntimeState::Degraded,
            "missing PAM gate must keep runtime DEGRADED");

    // A lower severity must never lower the persisted state.
    const IncidentResult second = harness.controller.raise(
        IncidentSeverity::Soft, source, "policy failed again");
    require(second.effectiveSeverity == IncidentSeverity::Hard,
            "the controller must not lower the severity");
    require(!second.escalated, "a lower raise must not count as escalation");

    const IncidentResult repeat = harness.controller.raise(
        IncidentSeverity::Hard, source, "same level");
    require(!repeat.escalated, "a repeated raise must be idempotent");

    require(harness.controller.status().severity == IncidentSeverity::Hard,
            "the status must report the raised severity");
}

// A repeated raise must not re-notify: notification deduplication lives in the
// controller so detectors never spam the desktop themselves.
void testNotificationIsDeduplicatedBySeverity(const TempTree& tree) {
    Harness harness(tree.statePath);
    IncidentSource source = policySource("a");
    std::vector<IncidentSeverity> notifications;
    harness.controller.setNotifySink(
        [&](IncidentSeverity severity, const std::string&) {
            notifications.push_back(severity);
        });

    harness.controller.raise(IncidentSeverity::Standard, source, "first");
    // Two more raises at the same level must not escalate, which is the
    // precondition for the notification being skipped.
    harness.controller.raise(IncidentSeverity::Standard, source, "second");
    harness.controller.raise(IncidentSeverity::Standard, source, "third");

    // Escalating to a higher severity is a real change and is the only thing
    // that re-notifies.
    harness.controller.raise(IncidentSeverity::Hard, source, "worse");
    harness.controller.raise(IncidentSeverity::Hard, source, "repeat hard");
    harness.controller.raise(IncidentSeverity::Isolate, source, "isolate");
    require(notifications == std::vector<IncidentSeverity>{
                IncidentSeverity::Standard, IncidentSeverity::Hard,
                IncidentSeverity::Isolate},
            "only genuine severity escalations must notify");
    require(harness.controller.status().severity == IncidentSeverity::Isolate,
            "the escalation must be recorded");
    harness.controller.clear("admin");
    harness.controller.raise(IncidentSeverity::Standard, source, "new incident");
    require(notifications.size() == 5 &&
                notifications[3] == IncidentSeverity::Unlocked &&
                notifications.back() == IncidentSeverity::Standard,
            "successful clear must reset notification deduplication");
}

void testNotificationLevelsAndRepeatedClear(const TempTree& tree) {
    require(incidentNotificationLevel(IncidentSeverity::Unlocked) == notifyLevel::INFO &&
            incidentNotificationLevel(IncidentSeverity::Soft) == notifyLevel::WARN &&
            incidentNotificationLevel(IncidentSeverity::Standard) == notifyLevel::WARN &&
            incidentNotificationLevel(IncidentSeverity::Hard) == notifyLevel::ERROR &&
            incidentNotificationLevel(IncidentSeverity::Isolate) == notifyLevel::FATAL,
            "incident notification levels must match severity");
    Harness harness(tree.statePath);
    std::vector<IncidentSeverity> notifications;
    harness.controller.setNotifySink([&](IncidentSeverity severity, const std::string&) {
        notifications.push_back(severity);
    });
    harness.controller.raise(IncidentSeverity::Soft, policySource("a"), "soft");
    require(harness.controller.clear("admin").ok, "first clear must succeed");
    require(harness.controller.clear("admin").ok, "repeated clear must succeed");
    require(notifications == std::vector<IncidentSeverity>{
                IncidentSeverity::Soft, IncidentSeverity::Unlocked},
            "successful transition to UNLOCKED must notify exactly once");
}

void testPersistenceFailureAuditsAfterContainment(const TempTree& tree) {
    Harness harness(tree.statePath);
    bool audited = false;
    bool containedAtAudit = false;
    harness.controller.setAuditSink([&](const std::string& line) {
        if (line.find("incident_persistence_failed") != std::string::npos) {
            audited = true;
            containedAtAudit = harness.sessions->acted("terminate-session:c1");
        }
    });
    // Break ONLY the lockstatus durability: the Model A target store must
    // keep working, because without a durably proven target set FIC would
    // (correctly) refuse to destroy the proving login sessions.
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string& target) {
            return target.find("lockstatus") == std::string::npos;
        });
    harness.controller.raise(IncidentSeverity::Hard, policySource("a"), "hard");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(audited, "persistence failure must be audited");
    require(containedAtAudit, "emergency containment must precede persistence audit");
}

void testUnavailableBackendsRemainUnproven(const TempTree& tree) {
    writeState(tree.statePath, "UNLOCKED\n");
    IncidentController controller(IncidentStateStore(tree.statePath), nullptr, nullptr);
    const IncidentResult result = controller.raise(
        IncidentSeverity::Isolate, policySource("a"), "isolate");
    const auto status = controller.status();
    require(!result.ok && result.runtime == RuntimeState::Degraded,
            "unavailable backends cannot prove ISOLATE containment");
    require(!status.containment.pamGateActive &&
                !status.containment.sessionsContained &&
                !status.containment.userRuntimeContained &&
                !status.containment.networkQuarantined,
            "component status must report only proven containment");
}

void testInventoryFailuresAreNotEmptySuccess(const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.controller.setModeResolver([] {
        return IncidentResponseModeResult{IncidentResponseMode::Active, true, "test"};
    });
    harness.controller.setAccessGateVerifier([](std::string&) { return true; });
    harness.sessions->sessionsProven = false;
    harness.sessions->exposePartialInventory = true;
    const auto hard = harness.controller.raise(
        IncidentSeverity::Hard, policySource("inventory-failure"), "hard");
    require(!hard.ok && hard.runtime == RuntimeState::Degraded &&
            !harness.controller.status().containment.sessionsContained,
            "failed session inventory must not prove HARD containment");
    require(!harness.sessions->acted("terminate-session:c1"),
            "partial unproven session inventory must not trigger actions");
    harness.sessions->sessionsProven = true;
    harness.sessions->usersProven = false;
    const auto isolate = harness.controller.raise(
        IncidentSeverity::Isolate, policySource("user-inventory-failure"), "isolate");
    require(!isolate.ok && isolate.runtime == RuntimeState::Degraded &&
            !harness.controller.status().containment.userRuntimeContained,
            "failed user inventory must not prove ISOLATE runtime containment");
    require(!harness.sessions->acted("terminate-user:1000"),
            "partial unproven user inventory must not trigger actions");
}

void testNetworkFailureStillAttemptsSessionsAndUsers(const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.network->succeed = false;
    const auto result = harness.controller.raise(
        IncidentSeverity::Isolate, policySource("a"), "isolate");
    const auto status = harness.controller.status();
    require(!result.ok && result.runtime == RuntimeState::Degraded,
            "network failure must degrade containment");
    require(harness.sessions->acted("terminate-session:c1") &&
                harness.sessions->acted("terminate-user:1000"),
            "independent containment must proceed after network failure");
    require(!status.containment.networkQuarantined &&
                status.containment.sessionsContained &&
                status.containment.userRuntimeContained,
            "per-component status must remain accurate");
}

void testFailedTerminationIsNotSilentlyVerified(const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.sessions->terminationPerformed = false;
    const auto result = harness.controller.raise(
        IncidentSeverity::Hard, policySource("a"), "hard");
    require(!result.ok && !harness.controller.status().containment.sessionsContained,
            "failed termination with live target must not prove sessions gone");
    require(harness.sessions->acted("verify-gone:c1") &&
                harness.sessions->acted("verify-gone:c2"),
            "verification must cover intended targets");
}

void testClearCleanupFailureIsDegraded(const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.controller.raise(IncidentSeverity::Hard, policySource("a"), "hard");
    harness.network->succeed = false;
    const auto result = harness.controller.clear("admin");
    require(!result.ok && result.runtime == RuntimeState::Degraded &&
                result.effectiveSeverity == IncidentSeverity::Unlocked,
            "durable clear with failed cleanup must report UNLOCKED/DEGRADED");
    const auto repeated = harness.controller.clear("admin");
    require(!repeated.ok && repeated.runtime == RuntimeState::Degraded &&
                repeated.effectiveSeverity == IncidentSeverity::Unlocked,
            "proven UNLOCKED must still attempt runtime cleanup");
}

void testAuditAndNotifyFailuresDoNotCancelContainment(const TempTree& tree) {
    Harness harness(tree.statePath);
    int audits = 0;
    int notifications = 0;
    harness.controller.setAuditSink([&](const std::string&) {
        ++audits;
        throw std::runtime_error("audit unavailable");
    });
    harness.controller.setNotifySink(
        [&](IncidentSeverity, const std::string&) {
            ++notifications;
            throw std::runtime_error("notify unavailable");
        });
    const auto result = harness.controller.raise(
        IncidentSeverity::Hard, policySource("a"), "hard");
    require(result.effectiveSeverity == IncidentSeverity::Hard &&
                harness.sessions->acted("terminate-session:c1"),
            "sink failure must not cancel containment");
    require(audits == 1 && notifications == 1,
            "controller must call both observability sinks");
}

void testFailedClearKeepsDegradedRuntime(const TempTree& tree) {
    Harness harness(tree.statePath);
    const auto raised = harness.controller.raise(
        IncidentSeverity::Hard, policySource("a"), "hard");
    require(raised.runtime == RuntimeState::Degraded,
            "fixture must start DEGRADED without PAM gate");
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string&) { return false; });
    const auto cleared = harness.controller.clear("admin");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!cleared.ok && cleared.runtime == RuntimeState::Degraded,
            "failed clear must not upgrade DEGRADED to ACTIVE");
    require(cleared.effectiveSeverity == IncidentSeverity::Isolate,
            "failed compensation must report ISOLATE");
}

void testPersistenceFailureNeverReturnsOk(const TempTree& tree) {
    Harness harness(tree.statePath);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string&) { return false; });
    const auto raised = harness.controller.raise(
        IncidentSeverity::Hard, policySource("a"), "hard");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!raised.ok && raised.runtime == RuntimeState::Degraded &&
                raised.effectiveSeverity == IncidentSeverity::Isolate,
            "unproven persistence must override successful runtime actions");
    // Model A: without a durably proven target set FIC must not destroy the
    // proving login sessions (a failed durable registration forbids the
    // destructive action). Containment is still attempted and stays DEGRADED.
    // TerminateSession is withheld: destroying the login session would erase
    // the only evidence that selected the user, and its durable registration
    // just failed.
    require(!harness.sessions->acted("terminate-session:c1"),
            "a failed durable target registration must withhold session "
            "termination");
    // The user-runtime obligation comes from the PREVIOUS incident's store,
    // so its containment runs independently; its own discharge could not be
    // made durable, so the obligation stays pending and everything degrades.
    require(!raised.ok && raised.runtime == RuntimeState::Degraded,
            "the unproven store state must keep containment degraded");
}

void testFailedClearReconcilesNewIsolateState(const TempTree& tree) {
    Harness harness(tree.statePath);
    const auto soft = harness.controller.raise(
        IncidentSeverity::Soft, policySource("a"), "soft");
    require(soft.runtime == RuntimeState::Active, "SOFT fixture must be ACTIVE");
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string&) { return false; });
    const auto cleared = harness.controller.clear("admin");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(!cleared.ok && cleared.persistentStateBroken &&
                cleared.effectiveSeverity == IncidentSeverity::Isolate &&
                cleared.runtime == RuntimeState::Degraded,
            "failed clear must not reuse a SOFT runtime proof for ISOLATE");
    require(harness.network->quarantineActive,
            "failed clear must attempt containment for its new severity");
    // Model A: the fsync failure also broke the durable target registration,
    // so FIC must withhold the destructive session termination that would
    // erase the proving login session.
    require(!harness.sessions->acted("terminate-session:c1"),
            "a broken target store must withhold destructive session actions");
}

// ---------------------------------------------------------------------------
// Invariant 24: a graphical lock must be VERIFIED, and an unverifiable lock
// escalates to session termination.
// ---------------------------------------------------------------------------

void testStandardLocksAndVerifiesGraphicalSessions(const TempTree& tree) {
    Harness harness(tree.statePath);
    const IncidentResult result = harness.controller.raise(
        IncidentSeverity::Standard, policySource("a"), "standard");

    require(!result.ok && result.runtime == RuntimeState::Degraded,
            "STANDARD cannot be fully proven without a PAM gate");
    // The graphical session was locked AND verified.
    require(harness.sessions->acted("lock:c1"),
            "the graphical session must be locked");
    require(harness.sessions->acted("verify-locked:c1"),
            "a successful lock call is not a proof; it must be verified");
    require(!harness.sessions->acted("terminate-session:c1"),
            "a proven lock must not escalate to termination");
    // The terminal session cannot be locked and is terminated instead.
    require(harness.sessions->acted("terminate-session:c2"),
            "an SSH/TTY session must be terminated at STANDARD");
    // The recovery session is never touched.
    require(!harness.sessions->acted("lock:c3") &&
                !harness.sessions->acted("terminate-session:c3"),
            "a recovery identity must never be contained");
}

void testUnverifiableLockEscalatesToTermination(const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.sessions->lockActuallyLocks = false;

    const IncidentResult result = harness.controller.raise(
        IncidentSeverity::Standard, policySource("a"), "standard");

    require(!result.ok, "the PAM gate is still unavailable");
    require(harness.sessions->acted("lock:c1"),
            "the lock must still be attempted first");
    require(harness.sessions->acted("terminate-session:c1"),
            "an unverifiable lock must escalate to session termination");
}

// An unprovable containment must be DEGRADED, and the persistent severity must
// NOT be lowered (invariant 28).
void testFailedContainmentDegradesWithoutLoweringSeverity(
    const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.sessions->sessionsActuallyRemoved = false;

    const IncidentResult result = harness.controller.raise(
        IncidentSeverity::Hard, policySource("a"), "hard");

    require(!result.ok, "an unproven containment must not report success");
    require(result.runtime == RuntimeState::Degraded,
            "an unproven containment must be DEGRADED");
    require(result.effectiveSeverity == IncidentSeverity::Hard,
            "a containment failure must never lower the persisted severity");
    require(harness.controller.status().severity == IncidentSeverity::Hard,
            "the persisted severity must remain HARD");
}

// Invariant 27: ISOLATE quarantines the network instead of stopping the stack.
void testIsolateQuarantinesNetworkAndTerminatesUserRuntime(
    const TempTree& tree) {
    Harness harness(tree.statePath);
    const IncidentResult result = harness.controller.raise(
        IncidentSeverity::Isolate, policySource("a"), "isolate");

    require(!result.ok, "ISOLATE cannot be fully proven without a PAM gate");
    require(harness.network->quarantineActive,
            "ISOLATE must apply the network quarantine");
    require(harness.sessions->acted("terminate-session:c1") &&
                harness.sessions->acted("terminate-session:c2"),
            "ISOLATE must terminate ordinary login sessions");
    // The ordinary user's runtime, including its user manager, is terminated.
    require(harness.sessions->acted("terminate-user:1000"),
            "ISOLATE must terminate the affected ordinary user runtime");
    require(harness.sessions->acted("verify-user-runtime:1000"),
            "user runtime termination must be proven, not assumed");
    // Recovery and service identities survive.
    require(!harness.sessions->acted("terminate-user:0"),
            "a recovery identity must never be terminated");
    require(!harness.sessions->acted("terminate-user:999"),
            "a service account must never be terminated");
    // HARD and below must NOT quarantine the network: the network overlay is
    // the ISOLATE-specific containment. A separate tree is used so the check
    // is not confused by the ISOLATE run above.
    TempTree hardTree;
    Harness hard(hardTree.statePath);
    hard.controller.raise(IncidentSeverity::Hard, policySource("b"), "hard");
    require(!hard.network->quarantineActive,
            "HARD must not apply the network quarantine");
}

// Invariant 8/33/34: clear() must produce a durably proven UNLOCKED, never an
// unlink, and it must never unlock a desktop session.
void testClearRemovesContainmentWithoutUnlockingSessions(
    const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.controller.raise(IncidentSeverity::Hard, policySource("a"), "hard");
    const std::size_t actionsBefore = harness.sessions->actions.size();

    const IncidentResult cleared = harness.controller.clear("admin");

    require(cleared.ok, "a clear from a proven state must succeed");
    require(cleared.effectiveSeverity == IncidentSeverity::Unlocked,
            "a successful clear must be durably UNLOCKED");
    require(harness.network->applications >= 1,
            "the network quarantine must be released");
    // No NEW session action may occur: clearing does not unlock or terminate
    // anything, it only stops the containment from being re-applied.
    require(harness.sessions->actions.size() == actionsBefore,
            "clear must not perform any session containment action");
    require(harness.controller.status().severity == IncidentSeverity::Unlocked,
            "the status must report UNLOCKED after a successful clear");
}

// Invariant 33: an incident never auto-clears. Reconciliation re-proves the
// containment for the CURRENT severity and never lowers it.
void testReconcileNeverLowersSeverity(const TempTree& tree) {
    Harness harness(tree.statePath);
    harness.controller.raise(IncidentSeverity::Hard, policySource("a"), "hard");
    const std::size_t sessionsBefore = harness.sessions->actions.size();

    const IncidentResult reconciled = harness.controller.reconcile();

    require(reconciled.effectiveSeverity == IncidentSeverity::Hard,
            "reconciliation must not lower the severity");
    // Sessions that were terminated are gone, so the re-run finds nothing left
    // to contain: containment is idempotent, not silently cleared.
    require(harness.sessions->actions.size() == sessionsBefore,
            "reconciliation must not re-terminate already contained sessions");
    require(harness.controller.status().severity == IncidentSeverity::Hard,
            "the incident must survive reconciliation");
}

// Invariant 29: startup reconciliation re-applies containment for a persisted
// severity, so a reboot cannot silently drop an incident.
void testReconcileRestoresContainmentAfterRestart(const TempTree& tree) {
    writeState(tree.statePath, "HARD\n");
    Harness harness(tree.statePath);

    const IncidentResult reconciled = harness.controller.reconcile();
    require(!reconciled.ok, "reconciliation lacks a PAM gate proof");
    require(harness.sessions->acted("terminate-session:c1"),
            "reconciliation must re-terminate surviving sessions");
    require(reconciled.effectiveSeverity == IncidentSeverity::Hard,
            "reconciliation must keep the persisted severity");
}

// A persisted ISOLATE (or an unprovable state) must be reconciled back into
// full containment, including the network quarantine.
void testReconcileRestoresIsolateContainment(const TempTree& tree) {
    writeState(tree.statePath, "ISOLATE\n");
    Harness harness(tree.statePath);

    const IncidentResult reconciled = harness.controller.reconcile();
    require(!reconciled.ok, "reconciliation lacks a PAM gate proof");
    require(harness.network->quarantineActive,
            "reconciliation must restore the network quarantine");
}

// Invariant 1/2: an unprovable persisted state reconciles as ISOLATE.
void testReconcileTreatsUnprovableStateAsIsolate(const TempTree& tree) {
    writeState(tree.statePath, "garbage\n");
    Harness harness(tree.statePath);

    const IncidentResult reconciled = harness.controller.reconcile();
    require(reconciled.effectiveSeverity == IncidentSeverity::Isolate,
            "an unprovable state must reconcile as ISOLATE");
    require(reconciled.persistentStateBroken,
            "an unprovable state must be reported as BROKEN_STATE");
    require(harness.network->quarantineActive,
            "a BROKEN_STATE must reconcile into the ISOLATE quarantine");
}

void testPamGateRequiresFreshProof(const TempTree& tree) {
    Harness harness(tree.statePath);
    int probes = 0;
    bool available = false;
    harness.controller.setAccessGateVerifier([&](std::string& diagnostic) {
        ++probes;
        diagnostic = available ? "proven" : "missing hook";
        return available;
    });
    const auto failed = harness.controller.raise(
        IncidentSeverity::Standard, policySource("gate"), "gate test");
    require(!failed.ok && !harness.controller.status().containment.pamGateActive,
            "unproven gate must degrade containment");
    require(probes == 1, "gate verifier must run once per containment pass");
    available = true;
    harness.controller.reconcile();
    require(harness.controller.status().containment.pamGateActive,
            "reconciliation must record freshly proven PAM gate");
    require(probes == 2, "reconciliation must re-prove the gate");
}

void testPersistentBrokenFlagTracksObservation(const TempTree& tree) {
    Harness harness(tree.statePath);
    const auto raised = harness.controller.raise(
        IncidentSeverity::Hard, policySource("broken"), "hard");
    require(!raised.persistentStateBroken,
            "failed containment must not mark proven persistent state broken");
    writeState(tree.statePath, "garbage\n");
    require(harness.controller.reconcile().persistentStateBroken,
            "malformed persistent observation must be marked broken");
    const auto cleared = harness.controller.clear("administrator");
    require(!cleared.persistentStateBroken,
            "successful clear must report freshly proven persistent state");
}

} // namespace

int main() {
    IncidentStateStore::setOwnershipExpectationForTests(::geteuid(), ::geteuid());
    IncidentSessionTargetStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());

    struct Scenario {
        const char* name;
        void (*run)(const TempTree&);
    };
    const Scenario scenarios[] = {
        {"raise_is_monotonic_through_the_controller",
         testRaiseIsMonotonicThroughTheController},
        {"notification_is_deduplicated_by_severity",
         testNotificationIsDeduplicatedBySeverity},
        {"notification_levels_and_repeated_clear", testNotificationLevelsAndRepeatedClear},
        {"persistence_failure_audits_after_containment", testPersistenceFailureAuditsAfterContainment},
        {"unavailable_backends_remain_unproven",
         testUnavailableBackendsRemainUnproven},
        {"inventory_failures_are_not_empty_success",
         testInventoryFailuresAreNotEmptySuccess},
        {"network_failure_still_attempts_sessions_and_users",
         testNetworkFailureStillAttemptsSessionsAndUsers},
        {"failed_termination_is_not_silently_verified",
         testFailedTerminationIsNotSilentlyVerified},
        {"clear_cleanup_failure_is_degraded", testClearCleanupFailureIsDegraded},
        {"audit_and_notify_failures_do_not_cancel_containment",
         testAuditAndNotifyFailuresDoNotCancelContainment},
        {"failed_clear_keeps_degraded_runtime",
         testFailedClearKeepsDegradedRuntime},
        {"persistence_failure_never_returns_ok",
         testPersistenceFailureNeverReturnsOk},
        {"failed_clear_reconciles_new_isolate_state",
         testFailedClearReconcilesNewIsolateState},
        {"standard_locks_and_verifies_graphical_sessions",
         testStandardLocksAndVerifiesGraphicalSessions},
        {"unverifiable_lock_escalates_to_termination",
         testUnverifiableLockEscalatesToTermination},
        {"failed_containment_degrades_without_lowering_severity",
         testFailedContainmentDegradesWithoutLoweringSeverity},
        {"isolate_quarantines_network_and_terminates_user_runtime",
         testIsolateQuarantinesNetworkAndTerminatesUserRuntime},
        {"clear_removes_containment_without_unlocking_sessions",
         testClearRemovesContainmentWithoutUnlockingSessions},
        {"reconcile_never_lowers_severity", testReconcileNeverLowersSeverity},
        {"reconcile_restores_containment_after_restart",
         testReconcileRestoresContainmentAfterRestart},
        {"reconcile_restores_isolate_containment",
         testReconcileRestoresIsolateContainment},
        {"reconcile_treats_unprovable_state_as_isolate",
         testReconcileTreatsUnprovableStateAsIsolate},
        {"pam_gate_requires_fresh_proof", testPamGateRequiresFreshProof},
        {"persistent_broken_flag_tracks_observation",
         testPersistentBrokenFlagTracksObservation},
        {"response_modes", testResponseModes},
    };

    for (const Scenario& scenario : scenarios) {
        try {
            TempTree tree;
            scenario.run(tree);
            std::cout << "ok - " << scenario.name << '\n';
        } catch (const std::exception& exception) {
            std::cerr << "FAIL - " << scenario.name << ": " << exception.what()
                      << '\n';
            return 1;
        }
    }
    std::cout << sizeof(scenarios) / sizeof(scenarios[0])
              << " incident controller scenarios passed\n";
    return 0;
}
