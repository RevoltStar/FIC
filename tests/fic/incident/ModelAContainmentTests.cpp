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
#include <optional>
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
    bool getUserOk = true;
    std::optional<uid_t> failLookupUid;
    bool keepSession = false;
    bool keepUser = false;
    bool acceptSessionTermination = true;
    bool acceptUserTermination = true;
    bool crashBeforeSessionTermination = false;
    bool crashBeforeUserTermination = false;
    bool crashDuringUserVerification = false;
    std::optional<uid_t> rejectUserUid;
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
        if (!getUserOk || failLookupUid == expected.uid) {
            error = "logind user lookup unavailable";
            return LogindLookup::Error;
        }
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
        if (crashBeforeSessionTermination)
            throw std::runtime_error("simulated crash before TerminateSession");
        ++terminatedSessions;
        if (!acceptSessionTermination) return false;
        if (!keepSession) {
            sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                [&](const auto& c) { return c.id == s.id; }), sessions.end());
        }
        return true;
    }
    bool terminateUser(const LogindUserRecord& u, std::string& error) override {
        if (crashBeforeUserTermination)
            throw std::runtime_error("simulated crash before TerminateUser");
        ++terminatedUsers;
        if (!acceptUserTermination || rejectUserUid == u.uid) {
            error = "terminate rejected";
            return false;
        }
        if (!keepUser) {
            users.erase(std::remove_if(users.begin(), users.end(),
                [&](const auto& c) { return c.uid == u.uid; }), users.end());
        }
        return true;
    }
    bool userManagerStopped(uid_t, bool& stopped, std::string&) override {
        if (crashDuringUserVerification)
            throw std::runtime_error("simulated crash before runtime proof");
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
    fic::session::ContainmentIdentityEvidenceReader identityReader;
    std::string bootId;

    explicit World(
        const fic::session::ContainmentIdentityEvidenceReader& reader)
        : identityReader(reader) {
        char pattern[] = "/tmp/fic-model-a-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) throw std::runtime_error("mkdtemp failed");
        root = created;
        statePath = root / "lockstatus";
        resetState();
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
        backend = std::make_shared<LogindSessionContainmentBackend>(
            logind, classifier(identityReader));
        controller = std::make_unique<IncidentController>(
            IncidentStateStore(statePath),
            IncidentSessionTargetStore(statePath), backend,
            std::make_shared<NullIncidentNetworkBackend>());
        controller->setModeResolver([] {
            return fic::incident::IncidentResponseModeResult{
                IncidentResponseMode::Active, true, "test ACTIVE"};
        });
        controller->setAccessGateVerifier([](std::string&) { return true; });
        if (!bootId.empty())
            controller->setBootIdProviderForTests([this] { return bootId; });
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

int main(int argc, char** argv) {
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
        world.logind->acceptUserTermination = false;
        const auto raised = world.controller->raise(
            Severity::Isolate, {"test"}, "partial failure");
        require(!raised.ok && raised.runtime == RuntimeState::Degraded,
                "a failed TerminateUser must degrade");
        require(world.logind->terminatedUsers == 1,
                "the registered target must be attempted");
        // Reconcile after the login session is gone: the pending target must
        // survive (it lives in the store, not in the session list).
        world.logind->acceptUserTermination = true;
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
        world.logind->acceptUserTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "crash soon");
        require(world.logind->terminatedUsers == 1, "target attempted");
        // fic crashes and restarts: NEW controller/backend/store objects; the
        // login session is already gone, the user runtime remains.
        world.logind->sessions.clear();
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptUserTermination = true;
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
        world.logind->acceptUserTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "uid reuse seed");
        // The account behind UID 1000 is replaced by a different one.
        world.logind->users = {loginUser(1000, "svc")};
        world.logind->sessions.clear();
        world.logind->acceptUserTermination = true;
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
        world.logind->acceptUserTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "incident one");
        const auto cleared = world.controller->clear("admin");
        require(cleared.ok, "clear must succeed");
        // A NEW incident with NO ordinary login session (only the lingering
        // runtime): the old target must never authorize an action.
        world.logind->sessions.clear();
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        world.logind->acceptUserTermination = true;
        world.controller->raise(Severity::Isolate, {"test"}, "incident two");
        require(world.logind->terminatedUsers == 1,
                "the old incident target must not fire in the new incident");
    }

    // ---- Lifecycle RED R1: crash after UNLOCKED, before target cleanup ----
    if (argc < 2 || std::string(argv[1]) == "R1") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptUserTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "old incident");
        require(world.logind->terminatedSessions == 1 &&
                    world.logind->terminatedUsers == 1 &&
                    world.logind->sessions.empty(),
                "session succeeds while user runtime stays pending");
        const auto unlocked = world.controller->stateStore().clear();
        require(unlocked.ok, "durable UNLOCKED before simulated crash");
        world.rebuild();
        world.controller->raise(Severity::Soft, {"test"}, "new SOFT");
        world.logind->acceptUserTermination = true;
        world.controller->raise(Severity::Isolate, {"test"}, "new ISOLATE");
        require(world.logind->terminatedUsers == 1,
                "old incident target must not survive clear-crash-SOFT boundary");
    }

    // ---- Lifecycle RED R2: HARD must rebase a proved previous boot --------
    if (argc < 2 || std::string(argv[1]) == "R2") {
        for (const Severity level : {Severity::Standard, Severity::Hard}) {
            World world(provenIdentity);
            world.logind->sessions = {loginSession("old", 1000, "alice")};
            world.controller->raise(level, {"test"}, "old boot");
            const auto saved = world.store().read();
            require(saved.provenance ==
                        IncidentSessionTargetStore::ReadProvenance::Proven,
                    "old boot target store exists");
            require(world.store().write(
                        "00000000-0000-4000-8000-000000000001",
                        saved.incidentGeneration, saved.targets).durable,
                    "simulate previous kernel boot ID");
            world.logind->sessions = {loginSession("new", 1001, "bob")};
            world.rebuild();
            world.controller->reconcile();
            require(world.logind->terminatedSessions == 2 &&
                        world.store().read().bootId !=
                            "00000000-0000-4000-8000-000000000001",
                    "STANDARD/HARD must rebase and terminate new-boot login session");
        }
    }

    // ---- Lifecycle RED R3: active target store loss is not empty success --
    if (argc < 2 || std::string(argv[1]) == "R3") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptUserTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "pending");
        require(world.logind->sessions.empty(), "proving login session is gone");
        std::filesystem::remove(world.store().path());
        world.rebuild();
        const auto reconciled = world.controller->reconcile();
        require(reconciled.runtime == RuntimeState::Degraded &&
                    !world.controller->status().containment.userRuntimeContained,
                "missing store with active incident must remain unproven");
    }

    // ---- Lifecycle RED R4: unknown obligation cannot parse as pending -----
    if (argc < 2 || std::string(argv[1]) == "R4") {
        World world(provenIdentity);
        const IncidentSessionTarget target{1000, "alice", "c1", 12345,
            "user", IncidentSessionTarget::RuntimeObligation::Pending};
        require(world.store().write("00000000-0000-4000-8000-000000000001",
                                    1, {target}).durable, "seed target store");
        std::ifstream in(world.store().path());
        std::string content((std::istreambuf_iterator<char>(in)), {});
        const auto token = content.find("\"pending\"");
        require(token != std::string::npos, "seed contains pending token");
        content.replace(token, 9, "\"invalid\"");
        std::ofstream out(world.store().path(), std::ios::trunc);
        out << content;
        out.close();
        require(world.store().read().provenance ==
                    IncidentSessionTargetStore::ReadProvenance::Unprovable,
                "unknown obligation token must be unprovable");
    }

    // ---- Lifecycle RED R5: cleanup failure remains in clear response ------
    if (argc < 2 || std::string(argv[1]) == "R5") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("c1", 1000, "alice")};
        world.controller->raise(Severity::Hard, {"test"}, "seed");
        ::AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string& path) {
                return path.find("incident_session_targets") == std::string::npos;
            });
        const auto cleared = world.controller->clear("admin");
        ::AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(cleared.effectiveSeverity == Severity::Unlocked &&
                    cleared.detail.find("target cleanup failed") != std::string::npos,
                "durable UNLOCKED must retain target cleanup diagnostic");
        const auto before = world.store().read();
        world.rebuild();
        const auto next = world.controller->raise(
            Severity::Soft, {"test"}, "after failed cleanup");
        const auto after = world.store().read();
        require(next.persistenceConfirmed &&
                    after.incidentGeneration > before.incidentGeneration &&
                    after.targets.empty(),
                "new SOFT must fence even after failed clear cleanup");
    }

    // An installed target write with an unproven directory fsync cannot
    // publish a new severity or authorize a user action.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("s1", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        ::AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string& path) {
                return path.find("incident_session_targets") == std::string::npos;
            });
        const auto failed = world.controller->raise(
            Severity::Isolate, {"test"}, "fence durability failure");
        ::AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(!failed.ok && !failed.persistenceConfirmed &&
                    failed.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedSessions == 0 &&
                    world.logind->terminatedUsers == 0,
                "unproven fence must forbid destructive actions");
    }

    // Fence is committed before severity. A severity durability failure
    // leaves a safe BROKEN_STATE/UNLOCKED observation after restart, never a
    // usable active severity with unfenced targets.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("s1", 1000, "alice")};
        ::AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string& path) {
                return path.find("lockstatus") == std::string::npos;
            });
        const auto failed = world.controller->raise(
            Severity::Hard, {"test"}, "severity durability failure");
        ::AtomicFileWriter::setDirectoryFsyncHookForTests({});
        const auto fenced = world.store().read();
        require(!failed.persistenceConfirmed &&
                    fenced.provenance ==
                        IncidentSessionTargetStore::ReadProvenance::Proven &&
                    fenced.targets.empty() &&
                    world.logind->terminatedSessions == 0,
                "durable empty fence must precede failed severity");
        world.rebuild();
        const auto restarted = world.controller->reconcile();
        require(restarted.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedSessions == 0,
                "severity failure must remain fail-closed after restart");
    }

    // A proved kernel boot change clears old runtime obligations before
    // processing the current boot. An unavailable boot ID does neither.
    {
        World world(provenIdentity);
        world.bootId = "00000000-0000-4000-8000-000000000001";
        world.rebuild();
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->acceptUserTermination = false;
        world.controller->raise(Severity::Isolate, {"test"}, "old boot");
        world.logind->sessions.clear();
        world.bootId = "00000000-0000-4000-8000-000000000002";
        world.logind->acceptUserTermination = true;
        world.rebuild();
        world.controller->reconcile();
        require(world.logind->terminatedUsers == 1 &&
                    world.store().read().targets.empty(),
                "ISOLATE reboot must discharge old-boot obligations");
        world.bootId.clear();
        world.rebuild();
        world.controller->setBootIdProviderForTests([] { return std::string{}; });
        world.logind->sessions = {loginSession("new", 1001, "bob")};
        const auto unknown = world.controller->reconcile();
        require(unknown.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedSessions == 1,
                "unknown kernel boot ID must prohibit destructive actions");
    }

    // Strict parsing never truncates an out-of-range UID.
    {
        World world(provenIdentity);
        const IncidentSessionTarget target{1000, "alice", "c1", 12345,
            "user", IncidentSessionTarget::RuntimeObligation::Pending};
        require(world.store().write("00000000-0000-4000-8000-000000000001",
                                    1, {target}).durable, "seed strict parser");
        std::ifstream in(world.store().path());
        std::string content((std::istreambuf_iterator<char>(in)), {});
        const auto uid = content.find("\"uid\":1000");
        require(uid != std::string::npos, "seed UID serialized");
        content.replace(uid, 10, "\"uid\":4294967296");
        std::ofstream out(world.store().path(), std::ios::trunc);
        out << content;
        out.close();
        require(world.store().read().provenance ==
                    IncidentSessionTargetStore::ReadProvenance::Unprovable,
                "overflow UID must be unprovable");
        const auto assertInvalid = [&](std::string invalid,
                                       const std::string& diagnostic) {
            std::ofstream replacement(world.store().path(), std::ios::trunc);
            replacement << invalid;
            replacement.close();
            require(world.store().read().provenance ==
                        IncidentSessionTargetStore::ReadProvenance::Unprovable,
                    diagnostic);
        };
        // Restore the valid seed through the production writer, then mutate
        // each independent field without relying on a parser-only mock.
        require(world.store().write("00000000-0000-4000-8000-000000000001",
                                    1, {target}).durable, "restore parser seed");
        std::ifstream validInput(world.store().path());
        const std::string valid((std::istreambuf_iterator<char>(validInput)), {});
        auto changed = valid;
        const auto classAt = changed.find("\"session_class\":\"user\"");
        require(classAt != std::string::npos, "seed class serialized");
        changed.replace(classAt, 22, "\"session_class\":\"manager\"");
        assertInvalid(changed, "invalid session class must be unprovable");
        changed = valid;
        const auto startAt = changed.find("\"session_start\":12345");
        require(startAt != std::string::npos, "seed timestamp serialized");
        changed.replace(startAt, 21, "\"session_start\":0");
        assertInvalid(changed, "zero timestamp must be unprovable");
        changed = valid;
        changed.insert(changed.size() - 1, ",\"extra\":true");
        assertInvalid(changed, "extra schema field must be unprovable");
        assertInvalid("{", "malformed JSON must be unprovable");
    }

    // An unexpected generation replacement in the same controller cannot
    // turn a saved UID into a fresh user-runtime authorization.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Hard, {"test"}, "seed generation");
        const auto saved = world.store().read();
        require(saved.provenance ==
                    IncidentSessionTargetStore::ReadProvenance::Proven,
                "generation seed is proven");
        require(world.store().writeIfCurrent(
                    saved, saved.bootId, saved.incidentGeneration + 1,
                    saved.targets).durable, "replace generation");
        const auto stale = world.controller->raise(
            Severity::Isolate, {"test"}, "stale generation");
        require(stale.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedUsers == 0,
                "stale generation must not authorize TerminateUser");
    }

    // Reconciliation of an unchanged same-boot target set is read-only.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("s1", 1000, "alice")};
        world.controller->raise(Severity::Hard, {"test"}, "seed read-only reconcile");
        struct stat before{};
        struct stat after{};
        require(::stat(world.store().path().c_str(), &before) == 0,
                "read-only reconcile seed exists");
        world.rebuild();
        world.controller->reconcile();
        require(::stat(world.store().path().c_str(), &after) == 0 &&
                    before.st_ino == after.st_ino,
                "unchanged same-boot reconcile must not rewrite target store");
    }

    // One discharged user must not erase the other user's pending obligation.
    {
        World world(provenIdentity);
        world.logind->sessions = {
            loginSession("a", 1000, "alice"),
            loginSession("b", 1001, "bob")};
        world.logind->users = {
            loginUser(1000, "alice"), loginUser(1001, "bob")};
        world.logind->rejectUserUid = 1001;
        world.controller->raise(Severity::Isolate, {"test"}, "partial discharge");
        const auto saved = world.store().read();
        require(saved.provenance ==
                    IncidentSessionTargetStore::ReadProvenance::Proven &&
                    saved.targets.size() == 2 &&
                    saved.targets[0].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Discharged &&
                    saved.targets[1].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Pending,
                "partial discharge must persist both outcomes");
        world.logind->rejectUserUid.reset();
        world.rebuild();
        world.controller->reconcile();
        require(world.logind->terminatedUsers == 3 &&
                    world.store().read().targets[1].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Discharged,
                "restart must retry only the pending user");
    }

    // Discharged is a past observation. A selected lingering runtime can
    // reappear without another qualifying login session.
    if (argc < 2 || std::string(argv[1]) == "D1") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        require(world.store().read().targets[0].runtimeObligation ==
                    IncidentSessionTarget::RuntimeObligation::Discharged,
                "initial runtime obligation discharged");
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        world.controller->reconcile();
        require(world.logind->terminatedUsers == 2 &&
                    world.store().read().targets[0].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Discharged,
                "reactivated selected lingering runtime must be contained");
    }

    // A new ordinary login must re-arm before its proving session is removed.
    if (argc < 2 || std::string(argv[1]) == "D2") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->sessions = {loginSession("new", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->reconcile();
        require(world.logind->terminatedSessions == 2 &&
                    world.logind->terminatedUsers == 2 &&
                    world.store().read().targets[0].sessionId == "new",
                "new login must re-arm and refresh selection evidence");
    }

    // Failed durable re-arm must preserve the proving login session.
    if (argc < 2 || std::string(argv[1]) == "D3") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->sessions = {loginSession("new", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        ::AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string& path) {
                return path.find("incident_session_targets") == std::string::npos;
            });
        const auto failed = world.controller->reconcile();
        ::AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(failed.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedSessions == 1 &&
                    world.logind->terminatedUsers == 1,
                "failed re-arm must forbid session and user termination");
    }

    // Simulate process loss exactly after durable re-arm and before the
    // backend receives TerminateSession; new production objects recover it.
    if (argc < 2 || std::string(argv[1]) == "D4") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->sessions = {loginSession("new", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->crashBeforeSessionTermination = true;
        try {
            world.controller->reconcile();
            require(false, "injected crash must be observed");
        } catch (const std::runtime_error&) {}
        require(world.store().read().targets[0].runtimeObligation ==
                    IncidentSessionTarget::RuntimeObligation::Pending,
                "re-arm must be durable before simulated crash");
        world.logind->crashBeforeSessionTermination = false;
        world.rebuild();
        world.controller->reconcile();
        require(world.logind->terminatedUsers == 2,
                "pending re-arm must recover after restart");
    }

    // UID reuse and unavailable logind proof cannot be treated as a fresh
    // discharge, even with no qualifying login session.
    if (argc < 2 || std::string(argv[1]) == "D5") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->users = {loginUser(1000, "service")};
        const auto reused = world.controller->reconcile();
        require(reused.runtime == RuntimeState::Degraded &&
                    !world.controller->status().containment.userRuntimeContained &&
                    world.logind->terminatedUsers == 1,
                "reused UID must not inherit discharged authorization");
    }
    if (argc < 2 || std::string(argv[1]) == "D6") {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->getUserOk = false;
        const auto unavailable = world.controller->reconcile();
        require(unavailable.runtime == RuntimeState::Degraded &&
                    !world.controller->status().containment.userRuntimeContained &&
                    world.logind->terminatedUsers == 1,
                "unavailable proof must not retain false runtime containment");
    }

    // Crash after the re-armed proving session is gone still leaves a
    // durable Pending obligation for the new controller.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->sessions = {loginSession("new", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.logind->crashBeforeUserTermination = true;
        try {
            world.controller->reconcile();
            require(false, "injected user crash must be observed");
        } catch (const std::runtime_error&) {}
        require(world.logind->sessions.empty() &&
                    world.store().read().targets[0].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Pending,
                "Pending must survive crash after TerminateSession");
        world.logind->crashBeforeUserTermination = false;
        world.rebuild();
        world.controller->reconcile();
        require(world.logind->terminatedUsers == 2,
                "pending user runtime must be retried after restart");
    }

    // Re-arm of a historically selected lingering runtime has the same
    // durability gate as re-arm caused by a new login session.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        ::AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string& path) {
                return path.find("incident_session_targets") == std::string::npos;
            });
        const auto failed = world.controller->reconcile();
        ::AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(failed.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedUsers == 1,
                "failed lingering re-arm must forbid TerminateUser");
    }

    // TerminateUser may succeed immediately before a crash. Pending survives
    // until a new controller independently proves runtime disappearance.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        world.logind->crashDuringUserVerification = true;
        try {
            world.controller->reconcile();
            require(false, "verification crash must be observed");
        } catch (const std::runtime_error&) {}
        require(world.logind->terminatedUsers == 2 &&
                    world.store().read().targets[0].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Pending,
                "Pending must survive crash after TerminateUser");
        world.logind->crashDuringUserVerification = false;
        world.rebuild();
        world.controller->reconcile();
        require(world.store().read().targets[0].runtimeObligation ==
                    IncidentSessionTarget::RuntimeObligation::Discharged,
                "new controller must independently prove discharge");
    }

    // Crash after independent absence proof but before the Discharged write
    // leaves the already durable Pending marker for restart recovery.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        int targetWrites = 0;
        ::AtomicFileWriter::setPreInstallHookForTests(
            [&targetWrites](const std::string& path) {
                if (path.find("incident_session_targets") == std::string::npos)
                    return;
                if (++targetWrites == 2)
                    throw std::runtime_error("crash before Discharged install");
            });
        try {
            world.controller->reconcile();
            require(false, "discharge write crash must be observed");
        } catch (const std::runtime_error&) {}
        ::AtomicFileWriter::setPreInstallHookForTests({});
        require(world.logind->terminatedUsers == 2 &&
                    world.store().read().targets[0].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Pending,
                "Pending remains durable when Discharged was not installed");
        world.rebuild();
        world.controller->reconcile();
        require(world.store().read().targets[0].runtimeObligation ==
                    IncidentSessionTarget::RuntimeObligation::Discharged,
                "restart re-verifies and durably discharges Pending");
    }

    // A competing target-store replacement between proof and conditional
    // install must make re-arm fail before any user action.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        bool competing = false;
        ::AtomicFileWriter::setPreInstallHookForTests(
            [&world, &competing](const std::string& path) {
                if (competing ||
                    path.find("incident_session_targets") == std::string::npos)
                    return;
                competing = true;
                const auto current = world.store().read();
                require(world.store().write(
                            current.bootId, current.incidentGeneration + 1,
                            current.targets).durable,
                        "competing target replacement");
            });
        const auto stale = world.controller->reconcile();
        ::AtomicFileWriter::setPreInstallHookForTests({});
        require(stale.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedUsers == 1,
                "stale conditional re-arm must forbid TerminateUser");
    }

    // An accepted TerminateUser is not proof of disappearance. A re-armed
    // runtime that remains visible stays Pending for the next reconciliation.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        world.logind->keepUser = true;
        const auto persistent = world.controller->reconcile();
        require(persistent.runtime == RuntimeState::Degraded &&
                    !world.controller->status().containment.userRuntimeContained &&
                    world.store().read().targets[0].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Pending,
                "accepted TerminateUser with surviving runtime remains pending");
    }

    // A single unproven Discharged identity must not erase another user's
    // Pending obligation or prevent its independent safe completion.
    {
        World world(provenIdentity);
        world.logind->sessions = {
            loginSession("a", 1000, "alice"),
            loginSession("b", 1001, "bob"),
            loginSession("c", 1002, "carol")};
        world.logind->users = {
            loginUser(1000, "alice"),
            loginUser(1001, "bob"),
            loginUser(1002, "carol")};
        world.logind->rejectUserUid = 1001;
        world.controller->raise(Severity::Isolate, {"test"}, "mixed obligations");
        world.logind->rejectUserUid.reset();
        world.logind->failLookupUid = 1002;
        world.rebuild();
        const auto mixed = world.controller->reconcile();
        const auto saved = world.store().read();
        require(mixed.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedUsers == 4 &&
                    saved.targets.size() == 3 &&
                    saved.targets[1].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Discharged &&
                    saved.targets[2].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Discharged,
                "pending and unproven discharged users stay independent");
    }

    // Fresh absence proof for Discharged is read-only, even on repeated
    // ISOLATE reconciliation; it does not call TerminateUser again.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        struct stat before{};
        struct stat after{};
        require(::stat(world.store().path().c_str(), &before) == 0,
                "discharged target exists");
        world.rebuild();
        world.controller->reconcile();
        require(::stat(world.store().path().c_str(), &after) == 0 &&
                    before.st_ino == after.st_ino &&
                    world.logind->terminatedUsers == 1 &&
                    world.controller->status().containment.userRuntimeContained,
                "fresh absent proof must not rewrite or reterminate");
    }

    // Each selected UID is checked independently: one reactivation cannot
    // erase a different user's discharged state.
    {
        World world(provenIdentity);
        world.logind->sessions = {
            loginSession("a", 1000, "alice"),
            loginSession("b", 1001, "bob")};
        world.logind->users = {
            loginUser(1000, "alice"), loginUser(1001, "bob")};
        world.controller->raise(Severity::Isolate, {"test"}, "two discharged");
        world.logind->users = {loginUser(1001, "bob", "lingering")};
        world.rebuild();
        world.controller->reconcile();
        const auto saved = world.store().read();
        require(world.logind->terminatedUsers == 3 &&
                    saved.targets.size() == 2 &&
                    saved.targets[0].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Discharged &&
                    saved.targets[1].runtimeObligation ==
                        IncidentSessionTarget::RuntimeObligation::Discharged,
                "only reactivated selected user is terminated");
    }

    // A missing logind user object alone cannot prove that user@UID.service
    // stopped; unavailable manager proof is DEGRADED without mutation.
    {
        World world(provenIdentity);
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        world.logind->managerStopped = false;
        const auto uncertain = world.controller->reconcile();
        require(uncertain.runtime == RuntimeState::Degraded &&
                    !world.controller->status().containment.userRuntimeContained &&
                    world.logind->terminatedUsers == 1,
                "unproven user manager absence must not trigger termination");
    }

    // Recovery membership can change after selection. A discharged target
    // must be re-proved before any reactivated runtime is terminated.
    {
        auto protectedIdentity = std::make_shared<bool>(false);
        World world([protectedIdentity](uid_t uid, const std::string& name,
              fic::session::ContainmentIdentityEvidence& evidence,
              std::string&) {
            evidence = {uid, name, "/bin/bash", true, *protectedIdentity};
            return true;
        });
        world.logind->sessions = {loginSession("old", 1000, "alice")};
        world.logind->users = {loginUser(1000, "alice")};
        world.controller->raise(Severity::Isolate, {"test"}, "initial isolate");
        *protectedIdentity = true;
        world.logind->users = {loginUser(1000, "alice", "lingering")};
        const auto protectedResult = world.controller->reconcile();
        require(protectedResult.runtime == RuntimeState::Degraded &&
                    world.logind->terminatedUsers == 1,
                "recovery identity must not be reterminated");
    }

    std::cout << "Model A session-derived containment targets proven\n";
    return 0;
}
