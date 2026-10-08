// Model A (session-derived containment targets) regression suite.
//
// Covers the required incident lifecycle with the PRODUCTION controller, the
// PRODUCTION durable target store and the PRODUCTION logind backend over a
// fake logind transport:
//   R1  — a failed TerminateUser followed by reconcile keeps the pending
//         target and DEGRADES (never a false ACTIVE);
//   R2  — a HARD->ISOLATE escalation uses the durably saved target even
//         after its login session is gone;
//   R3  — a daemon restart (a NEW controller + NEW backend over the same
//         store) recovers pending obligations;
//   R4  — an unprovable store degrades instead of empty-success;
//   R5  — root/recovery identities are never selected;
//   R6  — a lingering-only runtime without a qualifying login session is
//         never a target;
//   R7  — a service identity WITH a genuine login session is a target;
//   R8  — UID reuse (same UID, different account) is refused and DEGRADES.
#include "incident/IncidentController.h"
#include "incident/IncidentSessionTargetStore.h"
#include "session/LogindSessionContainmentBackend.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

using fic::incident::IncidentController;
using fic::incident::IncidentResult;
using fic::incident::IncidentSessionTarget;
using fic::incident::IncidentSessionTargetStore;
using fic::incident::IncidentStateStore;
using fic::incident::RuntimeState;
using fic::incident::IncidentResponseMode;
using fic::incident::NullIncidentNetworkBackend;
using fic::session::LogindClient;
using fic::session::LogindSessionContainmentBackend;
using fic::session::LogindLookup;
using fic::session::LogindSessionRecord;
using fic::session::LogindUserRecord;
using Severity = fic::core::IncidentSeverity;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

namespace {

class FakeLogind final : public LogindClient {
public:
    std::vector<LogindSessionRecord> sessions;
    std::vector<LogindUserRecord> users;
    bool listOk = true;
    bool keepSession = false;
    bool keepUser = false;
    bool acceptTermination = true;
    bool managerStopped = true;
    int terminatedSessions = 0;
    int terminatedUsers = 0;

    bool listSessions(std::vector<LogindSessionRecord>& out,
                      std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return false; }
        out = sessions;
        return true;
    }
    bool listUsers(std::vector<LogindUserRecord>& out,
                   std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return false; }
        out = users;
        return true;
    }
    LogindLookup getSession(const LogindSessionRecord& expected,
                            LogindSessionRecord& out, std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return LogindLookup::Error; }
        const auto it = std::find_if(sessions.begin(), sessions.end(),
            [&](const auto& s) { return s.id == expected.id; });
        if (it == sessions.end()) return LogindLookup::Missing;
        out = *it;
        return LogindLookup::Found;
    }
    LogindLookup getUser(const LogindUserRecord& expected,
                         LogindUserRecord& out, std::string& error) override {
        if (!listOk) { error = "logind unavailable"; return LogindLookup::Error; }
        const auto it = std::find_if(users.begin(), users.end(),
            [&](const auto& u) { return u.uid == expected.uid; });
        if (it == users.end()) return LogindLookup::Missing;
        // A Model A target lookup probes by UID with no pinned owner: the
        // owner recorded at selection time is dead after a logind restart.
        // The empty owner means "fresh lookup"; the CURRENT owner is returned
        // and later verified before any action.
        if (!expected.owner.empty() && it->owner != expected.owner) {
            error = "owner changed";
            return LogindLookup::Error;
        }
        out = *it;
        return LogindLookup::Found;
    }
    bool lockSession(const LogindSessionRecord&, std::string&) override {
        return true;
    }
    bool terminateSession(const LogindSessionRecord& s, std::string&) override {
        ++terminatedSessions;
        if (!acceptTermination) return false;
        if (!keepSession) {
            sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                [&](const auto& c) { return c.id == s.id; }), sessions.end());
        }
        return true;
    }
    bool terminateUser(const LogindUserRecord& u, std::string& error) override {
        ++terminatedUsers;
        if (!acceptTermination) { error = "terminate rejected"; return false; }
        if (!keepUser) {
            users.erase(std::remove_if(users.begin(), users.end(),
                [&](const auto& c) { return c.uid == u.uid; }), users.end());
        }
        return true;
    }
    bool userManagerStopped(uid_t, bool& stopped, std::string&) override {
        stopped = managerStopped;
        return true;
    }
};

LogindSessionContainmentBackend::IdentityClassifier classifier(
    const fic::session::ContainmentIdentityEvidenceReader& reader) {
    return [reader](uid_t uid, const std::string& name,
                    std::string& diagnostic) {
        return fic::session::classifyProductionContainmentIdentity(
            uid, name, reader, diagnostic);
    };
}

LogindSessionRecord loginSession(std::string id, uid_t uid, std::string name,
                                 std::string className = "user",
                                 std::string type = "tty") {
    return {id, uid, name,
            "/org/freedesktop/login1/session/" + id, ":1.42", type,
            className, "active", false, 12345};
}
LogindUserRecord loginUser(uid_t uid, std::string name,
                           std::string state = "active") {
    return {uid, name, "/org/freedesktop/login1/user/_" +
                       std::to_string(uid), ":1.42", state, false};
}

const fic::session::ContainmentIdentityEvidenceReader provenIdentity = [](
    uid_t uid, const std::string& name,
    fic::session::ContainmentIdentityEvidence& evidence, std::string&) {
    evidence = {uid, name, "/bin/bash", false, false};
    return true;
};

// A complete Model A world: production controller + production durable target
// store + production logind backend over the fake transport.
struct World {
    std::filesystem::path root;
    std::filesystem::path statePath;
    std::shared_ptr<FakeLogind> logind = std::make_shared<FakeLogind>();
    std::shared_ptr<LogindSessionContainmentBackend> backend;
    std::unique_ptr<IncidentController> controller;

    explicit World(
        const fic::session::ContainmentIdentityEvidenceReader& reader) {
        char pattern[] = "/tmp/fic-model-a-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) throw std::runtime_error("mkdtemp failed");
        root = created;
        statePath = root / "lockstatus";
        resetState();
        backend = std::make_shared<LogindSessionContainmentBackend>(
            logind, classifier(reader));
        rebuild();
    }

    void resetState() {
        std::ofstream out(statePath, std::ios::trunc);
        out << "UNLOCKED\n";
        out.close();
        ::chmod(statePath.c_str(), 0640);
    }

    // A genuinely NEW controller + NEW backend + NEW store over the same
    // durable paths: the restart-recovery semantics under test.
    void rebuild() {
        controller = std::make_unique<IncidentController>(
            IncidentStateStore(statePath),
            IncidentSessionTargetStore(statePath), backend,
            std::make_shared<NullIncidentNetworkBackend>());
        controller->setModeResolver([] {
            return fic::incident::IncidentResponseModeResult{
                IncidentResponseMode::Active, true, "test ACTIVE"};
        });
        controller->setAccessGateVerifier([](std::string&) { return true; });
    }

    IncidentSessionTargetStore store() const {
        return IncidentSessionTargetStore(statePath);
    }

    ~World() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }
};

} // namespace

int main() {
    IncidentStateStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());
    IncidentSessionTargetStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());

    // ---- R5/A6/A7: root and recovery identities are never selected --------
    {
        World world(
            [](uid_t uid, const std::string& name,
               fic::session::ContainmentIdentityEvidence& evidence,
               std::string&) {
                evidence = {uid, name, "/bin/bash", true, name == "rescue"};
                return true;
            });
        world.logind->sessions = {
            loginSession("root", 0, "root", "user", "tty"),
            loginSession("rec", 200000, "rescue", "user", "tty")};
        world.controller->raise(Severity::Isolate, {"test"}, "protected");
        require(world.logind->terminatedSessions == 0 &&
                    world.logind->terminatedUsers == 0,
                "root and recovery identities are never targets");
    }

    // ---- R6/A3/A4: a lingering-only runtime is never a target -------------
    {
        World world(provenIdentity);
        world.logind->sessions = {
            loginSession("m1", 997, "fic-worker", "manager", "unspecified")};
        world.logind->users = {loginUser(997, "fic-worker", "lingering")};
        world.controller->raise(Severity::Isolate, {"test"}, "lingering only");
        require(world.logind->terminatedUsers == 0 &&
                    world.logind->terminatedSessions == 0,
                "a lingering-only runtime must never become a target");
    }

    // ---- R7/A2: a service identity WITH a login session is a target -------
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("s1", 997, "svc", "user", "ssh")};
        world.logind->users = {loginUser(997, "svc")};
        world.controller->raise(Severity::Isolate, {"test"}, "genuine login");
        require(world.logind->terminatedSessions == 1 &&
                    world.logind->terminatedUsers == 1,
                "a proven login session of a service identity is a target");
    }

    // ---- R1/A13/A14: failed TerminateUser + reconcile keeps pending -------
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice", "user", "ssh")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptTermination = false;
        const auto raised = world.controller->raise(
            Severity::Isolate, {"test"}, "partial failure");
        require(!raised.ok && raised.runtime == RuntimeState::Degraded,
                "a failed TerminateUser must degrade");
        require(world.logind->terminatedUsers == 1,
                "the registered target must be attempted");
        // Reconcile after the login session is gone: the pending target must
        // survive (it lives in the store, not in the session list).
        world.logind->acceptTermination = true;
        world.controller->reconcile();
        require(world.logind->terminatedUsers == 2,
                "reconcile must retry the pending user-runtime obligation");
    }

    // ---- R2/A12: HARD -> ISOLATE escalation uses the saved target ---------
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice", "user", "ssh")};
        world.logind->users = {loginUser(1000, "alice")};
        const auto hard = world.controller->raise(Severity::Hard, {"test"}, "hard");
        require(hard.ok, "HARD must succeed");
        require(world.logind->terminatedSessions == 1 &&
                    world.logind->terminatedUsers == 0,
                "HARD must not run TerminateUser");
        // The login session is gone now; escalate to ISOLATE.
        world.controller->raise(Severity::Isolate, {"test"}, "escalate");
        require(world.logind->terminatedUsers == 1,
                "ISOLATE must use the durably saved target even after the "
                "login session is gone");
    }

    // ---- R3/A15: restart recovers pending obligations ----------------------
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice", "user", "ssh")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "crash soon");
        require(world.logind->terminatedUsers == 1, "target attempted");
        // fic crashes and restarts: NEW controller/backend/store objects; the
        // login session is already gone, the user runtime remains.
        world.logind->sessions.clear();
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptTermination = true;
        world.rebuild();
        world.controller->reconcile();
        require(world.logind->terminatedUsers == 2,
                "a restart must recover the pending target from the durable "
                "store");
    }

    // ---- R4/A17/A18: an unprovable store degrades, never empty-success ----
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice", "user", "ssh")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "seed");
        require(world.logind->terminatedUsers == 1, "seed containment");
        // Corrupt the store.
        {
            std::ofstream corrupt(world.root / "incident_session_targets",
                                  std::ios::trunc);
            corrupt << "{\"schema_version\":1,\"garbage\":true}";
        }
        // A NEW controller instance fails closed on the unprovable store.
        world.rebuild();
        const auto after = world.controller->reconcile();
        require(after.runtime == RuntimeState::Degraded,
                "an unprovable store must degrade instead of empty-success");
        require(world.logind->terminatedUsers == 1,
                "an unprovable store must not authorize unsafe actions");
    }

    // ---- R8/A30: UID reuse is refused --------------------------------------
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice", "user", "ssh")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "uid reuse seed");
        // The account behind UID 1000 is replaced by a different one.
        world.logind->users = {loginUser(1000, "svc")};
        world.logind->sessions.clear();
        world.logind->acceptTermination = true;
        const auto reused = world.controller->reconcile();
        require(world.logind->terminatedUsers == 1,
                "a reused UID must never inherit the old authority");
        require(reused.runtime == RuntimeState::Degraded,
                "UID reuse must degrade instead of claiming success");
    }

    // ---- A25/A27: clear removes old incident obligations -------------------
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice", "user", "ssh")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "incident one");
        const auto cleared = world.controller->clear("admin");
        require(cleared.ok, "clear must succeed");
        // A NEW incident with NO ordinary login session (only the lingering
        // runtime): the old target must never authorize an action.
        world.logind->sessions.clear();
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        world.logind->acceptTermination = true;
        world.controller->raise(Severity::Isolate, {"test"}, "incident two");
        require(world.logind->terminatedUsers == 1,
                "the old incident target must not fire in the new incident");
    }

    std::cout << "Model A session-derived containment targets proven\n";
    return 0;
}