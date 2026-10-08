#include "session/LogindSessionContainmentBackend.h"
#include "incident/IncidentController.h"
#include "incident/IncidentSessionTargetStore.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using namespace fic::session;
namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

class FakeLogind final : public LogindClient {
public:
    std::vector<LogindSessionRecord> sessions;
    std::vector<LogindUserRecord> users;
    bool listSessionsOk = true;
    bool listUsersOk = true;
    bool keepSession = false;
    bool keepUser = false;
    bool acceptLock = true;
    bool acceptTermination = true;
    int locks = 0;
    int terminatedSessions = 0;
    int terminatedUsers = 0;
    bool managerStopped = true;

    bool listSessions(std::vector<LogindSessionRecord>& out,
                      std::string& error) override {
        if (!listSessionsOk) { error = "ListSessions unavailable"; return false; }
        out = sessions; return true;
    }
    bool listUsers(std::vector<LogindUserRecord>& out,
                   std::string& error) override {
        if (!listUsersOk) { error = "ListUsers unavailable"; return false; }
        out = users; return true;
    }
    LogindLookup getSession(const LogindSessionRecord& expected,
                            LogindSessionRecord& out, std::string& error) override {
        if (!listSessionsOk) { error = "logind unavailable"; return LogindLookup::Error; }
        const auto it = std::find_if(sessions.begin(), sessions.end(),
            [&](const auto& s) { return s.id == expected.id; });
        if (it == sessions.end()) return LogindLookup::Missing;
        if (it->owner != expected.owner) { error = "owner changed"; return LogindLookup::Error; }
        out = *it; return LogindLookup::Found;
    }
    LogindLookup getUser(const LogindUserRecord& expected,
                         LogindUserRecord& out, std::string& error) override {
        if (!listUsersOk) { error = "logind unavailable"; return LogindLookup::Error; }
        const auto it = std::find_if(users.begin(), users.end(),
            [&](const auto& u) { return u.uid == expected.uid; });
        if (it == users.end()) return LogindLookup::Missing;
        // A Model A target lookup probes by UID with no pinned D-Bus owner
        // (the owner recorded at selection time is dead after a logind
        // restart). The EMPTY owner means "fresh lookup": the CURRENT owner
        // is returned and later verified before any action.
        if (!expected.owner.empty() && it->owner != expected.owner) {
            error = "owner changed";
            return LogindLookup::Error;
        }
        out = *it; return LogindLookup::Found;
    }
    bool lockSession(const LogindSessionRecord&, std::string& error) override {
        ++locks;
        if (!acceptLock) error = "lock rejected";
        return acceptLock;
    }
    bool terminateSession(const LogindSessionRecord& s,
                          std::string& error) override {
        ++terminatedSessions;
        if (!acceptTermination) { error = "terminate rejected"; return false; }
        if (!keepSession) sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
            [&](const auto& current) { return current.id == s.id; }), sessions.end());
        return true;
    }
    bool terminateUser(const LogindUserRecord& u,
                       std::string& error) override {
        ++terminatedUsers;
        if (!acceptTermination) { error = "terminate rejected"; return false; }
        if (!keepUser) {
            users.erase(std::remove_if(users.begin(), users.end(),
                [&](const auto& current) { return current.uid == u.uid; }), users.end());
            sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                [&](const auto& current) { return current.uid == u.uid; }), sessions.end());
        }
        return true;
    }
    bool userManagerStopped(uid_t, bool& stopped, std::string&) override {
        stopped = managerStopped;
        return true;
    }
};

LogindSessionRecord session(std::string id = "c1", uid_t uid = 1000,
                            std::string name = "alice", std::string type = "wayland",
                            std::string className = "user") {
    return {id, uid, name, "/org/freedesktop/login1/session/" + id,
            ":1.42", type, className, "active", false, 12345};
}
LogindUserRecord user(uid_t uid = 1000, std::string name = "alice") {
    return {uid, name, "/org/freedesktop/login1/user/_" + std::to_string(uid),
            ":1.42", "active", false};
}
ContainmentIdentity identity(uid_t uid, const std::string&, std::string&) {
    if (uid == 0 || uid == 1001) return ContainmentIdentity::Recovery;
    if (uid == 999) return ContainmentIdentity::Service;
    if (uid == 1000) return ContainmentIdentity::Ordinary;
    return ContainmentIdentity::Unknown;
}
}

int main() {
    const ContainmentIdentityEvidenceReader highUidEvidence = [](
        uid_t uid, const std::string& name,
        ContainmentIdentityEvidence& evidence, std::string&) {
        evidence = {uid, name, "/bin/bash", false, false};
        return true;
    };
    std::string highUidDiagnostic;
    require(classifyProductionContainmentIdentity(
                200000, "alice", highUidEvidence, highUidDiagnostic) ==
                ContainmentIdentity::Ordinary,
            "proven high-UID login identity must be ordinary");
    require(classifyProductionContainmentIdentity(
                100001, "alice", highUidEvidence, highUidDiagnostic) ==
                ContainmentIdentity::Ordinary,
            "ordinary account classification must not have a UID ceiling");
    const auto evidenceClassifier = [&](uid_t uid, const std::string& name,
                                        std::string& diagnostic) {
        return classifyProductionContainmentIdentity(
            uid, name, highUidEvidence, diagnostic);
    };
    const ContainmentIdentityEvidenceReader recoveryEvidence = [](
        uid_t uid, const std::string& name,
        ContainmentIdentityEvidence& evidence, std::string&) {
        evidence = {uid, name, "/bin/bash", true, true};
        return true;
    };
    require(classifyProductionContainmentIdentity(
                200000, "rescue", recoveryEvidence, highUidDiagnostic) ==
                ContainmentIdentity::Recovery,
            "proved recovery membership protects high-UID users");
    const ContainmentIdentityEvidenceReader serviceEvidence = [](
        uid_t uid, const std::string& name,
        ContainmentIdentityEvidence& evidence, std::string&) {
        evidence = {uid, name, "/usr/sbin/nologin", false, false};
        return true;
    };
    // Model A: the login shell is NOT an account-purpose authority. A proven
    // non-recovery identity is eligible; whether it becomes a target is
    // decided by its logind sessions (a genuine login session makes even a
    // nologin-shell account a target; a lingering-only runtime does not).
    require(classifyProductionContainmentIdentity(
                200000, "svc", serviceEvidence, highUidDiagnostic) ==
                ContainmentIdentity::Ordinary,
            "Model A must not classify by login shell");
    const ContainmentIdentityEvidenceReader mismatchEvidence = [](
        uid_t, const std::string&,
        ContainmentIdentityEvidence& evidence, std::string&) {
        evidence = {200001, "alice", "/bin/bash", false, false};
        return true;
    };
    require(classifyProductionContainmentIdentity(
                200000, "alice", mismatchEvidence, highUidDiagnostic) ==
                ContainmentIdentity::Unknown,
            "NSS UID mismatch is Unknown, never Service");
    const ContainmentIdentityEvidenceReader failedEvidence = [](
        uid_t, const std::string&,
        ContainmentIdentityEvidence&, std::string& diagnostic) {
        diagnostic = "NSS unavailable";
        return false;
    };
    require(classifyProductionContainmentIdentity(
                200000, "alice", failedEvidence, highUidDiagnostic) ==
                ContainmentIdentity::Unknown,
            "failed NSS proof is Unknown, never Service");
    // Model A: the login shell is not consulted at all, so a missing shell
    // field no longer changes the decision for a proven identity.
    std::string nssDiagnostic;
    require(classifyProductionContainmentIdentity(0, "root", nssDiagnostic) ==
                ContainmentIdentity::Recovery,
            "root is always protected");
    require(classifyProductionContainmentIdentity(12345, "root", nssDiagnostic) ==
                ContainmentIdentity::Unknown,
            "NSS UID mismatch must not authorize termination");
    auto client = std::make_shared<FakeLogind>();
    LogindSessionContainmentBackend backend(client, identity);
    require(backend.listSessions().proven && backend.listSessions().sessions.empty(),
            "proven empty session inventory");
    client->listSessionsOk = false;
    require(!backend.listSessions().proven, "failed ListSessions must not mean empty");
    client->listSessionsOk = true;
    require(backend.listUsers().proven && backend.listUsers().users.empty(),
            "proven empty user inventory");
    client->listUsersOk = false;
    require(!backend.listUsers().proven, "failed ListUsers must not mean empty");
    client->listUsersOk = true;

    client->sessions = {session(), session("r1", 0, "root", "tty"),
        session("r2", 1001, "rescue", "tty"),
        session("g1", 999, "display", "wayland", "greeter")};
    auto inventory = backend.listSessions();
    require(inventory.proven && inventory.sessions.size() == 4,
            "session inventory must retain protected identities");
    require(inventory.sessions[0].ordinary && inventory.sessions[0].kind == SessionKind::Graphical,
            "ordinary graphical classification");
    for (std::size_t i = 1; i < inventory.sessions.size(); ++i)
        require(!backend.terminateSession(inventory.sessions[i]).performed,
                "protected session must never terminate");
    require(client->terminatedSessions == 0, "protected session reached logind action");
    std::string diagnostic;
    require(backend.lockSession(inventory.sessions[0]).performed && client->locks == 1,
            "graphical lock request");
    require(!backend.verifySessionLocked(inventory.sessions[0], diagnostic),
            "LockSession reply is not lock proof");
    client->keepSession = true;
    require(backend.terminateSession(inventory.sessions[0]).performed,
            "termination request accepted");
    require(!backend.verifySessionsGone({inventory.sessions[0]}, diagnostic),
            "accepted termination is not disappearance proof");
    client->keepSession = false;
    require(backend.terminateSession(inventory.sessions[0]).performed &&
            backend.verifySessionsGone({inventory.sessions[0]}, diagnostic),
            "actual disappearance proves termination");

    client->sessions = {session()};
    inventory = backend.listSessions();
    client->acceptTermination = false;
    require(!backend.terminateSession(inventory.sessions[0]).performed,
            "negative TerminateSession reply must fail");
    client->acceptTermination = true;
    client->listSessionsOk = false;
    require(!backend.verifySessionsGone({inventory.sessions[0]}, diagnostic),
            "logind failure during verification must fail closed");
    client->listSessionsOk = true;

    client->sessions = {session()};
    inventory = backend.listSessions();
    client->sessions[0].uid = 1001;
    require(!backend.terminateSession(inventory.sessions[0]).performed,
            "reused session ID with different UID must fail closed");
    client->sessions[0] = session();
    client->sessions[0].owner = ":1.43";
    require(!backend.terminateSession(inventory.sessions[0]).performed,
            "logind restart must fail closed");
    require(!backend.verifySessionsGone({inventory.sessions[0]}, diagnostic),
            "logind restart during verification must not prove disappearance");
    client->sessions.clear();
    require(backend.terminateSession(inventory.sessions[0]).performed &&
            backend.verifySessionsGone({inventory.sessions[0]}, diagnostic),
            "session already absent is idempotent after logind proof");
    client->sessions = {session("unknown", 1002, "mystery", "tty")};
    const auto unproven = backend.listSessions();
    require(!unproven.proven &&
            !backend.terminateSession(unproven.sessions[0]).performed,
            "unknown identity must not become a termination target");
    client->sessions = {session("dup"), session("dup")};
    require(!backend.listSessions().proven,
            "duplicate session IDs must invalidate inventory");
    client->sessions = {session("light", 1000, "alice", "tty", "user-early-light")};
    require(backend.listSessions().proven && backend.listSessions().sessions[0].ordinary,
            "known user-early-light class is an ordinary login session");
    client->sessions.clear();

    client->users = {user(), user(0, "root"), user(1001, "rescue"),
                     user(999, "display")};
    auto users = backend.listUsers();
    require(users.proven && users.users.size() == 4, "user inventory");
    for (std::size_t i = 1; i < users.users.size(); ++i)
        require(!backend.terminateUser(users.users[i]).performed,
                "protected user must never terminate");
    require(client->terminatedUsers == 0, "protected user reached logind action");
    client->users[0].name = "intruder";
    require(!backend.terminateUser(users.users[0]).performed,
            "changed user identity must block TerminateUser");
    client->users[0] = user();
    client->sessions = {session("x1", 1000, "alice", "tty", "greeter")};
    require(!backend.terminateUser(users.users[0]).performed,
            "protected same-UID session blocks TerminateUser");
    for (const char* className : {"manager", "background", "background-light"}) {
        client->sessions = {session("runtime", 1000, "alice", "unspecified", className)};
        client->keepUser = true;
        const int before = client->terminatedUsers;
        require(backend.terminateUser(users.users[0]).performed &&
                client->terminatedUsers == before + 1,
                "ordinary user runtime class must permit TerminateUser");
    }
    client->sessions.clear();
    client->keepUser = true;
    client->acceptTermination = false;
    require(!backend.terminateUser(users.users[0]).performed,
            "negative TerminateUser reply must fail");
    client->acceptTermination = true;
    require(backend.terminateUser(users.users[0]).performed &&
            !backend.verifyUserRuntimeGone(users.users[0], diagnostic),
            "accepted TerminateUser is not runtime proof");
    client->keepUser = false;
    require(backend.terminateUser(users.users[0]).performed &&
            backend.verifyUserRuntimeGone(users.users[0], diagnostic),
            "disappeared user runtime proves containment");
    client->managerStopped = false;
    require(!backend.verifyUserRuntimeGone(users.users[0], diagnostic),
            "active user manager prevents runtime proof");

    // Controller -> production backend -> fake logind: mode gates and
    // persistence stay in the real orchestration path.
    fic::incident::IncidentStateStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());
    fic::incident::IncidentSessionTargetStore::setOwnershipExpectationForTests(
        ::geteuid(), ::geteuid());
    char pattern[] = "/tmp/fic-logind-containment-XXXXXX";
    char* root = ::mkdtemp(pattern);
    require(root != nullptr, "test directory creation failed");
    const std::filesystem::path state = std::filesystem::path(root) / "lockstatus";
    const auto resetState = [&] {
        std::ofstream out(state, std::ios::trunc);
        out << "UNLOCKED\n";
        out.close();
        ::chmod(state.c_str(), 0640);
    };
    fic::incident::ContainmentStatus lastContainment;
    const auto runController = [&](fic::incident::IncidentResponseMode mode,
                                   fic::core::IncidentSeverity severity,
                                   const std::string& type,
                                   bool inventoryOk,
                                   uid_t targetUid = 1000,
                                   LogindSessionContainmentBackend::IdentityClassifier
                                       classify = identity,
                                   std::vector<LogindSessionRecord> extraSessions = {}) {
        resetState();
        client->sessions = {session("c1", targetUid, "alice", type)};
        client->sessions.insert(client->sessions.end(),
                                extraSessions.begin(), extraSessions.end());
        client->users = {user(targetUid)};
        client->listSessionsOk = inventoryOk;
        client->locks = client->terminatedSessions = client->terminatedUsers = 0;
        auto production = std::make_shared<LogindSessionContainmentBackend>(
            client, classify);
        fic::incident::IncidentController controller(
            fic::incident::IncidentStateStore(state),
            fic::incident::IncidentSessionTargetStore(state.parent_path() /
                "incident_session_targets"),
            production,
            std::make_shared<fic::incident::NullIncidentNetworkBackend>());
        controller.setModeResolver([mode] {
            return fic::incident::IncidentResponseModeResult{mode, true, "test"};
        });
        controller.setAccessGateVerifier([](std::string&) { return true; });
        const auto result = controller.raise(
            severity, {"test"}, "session containment");
        lastContainment = controller.status().containment;
        return result;
    };
    using fic::core::IncidentSeverity;
    runController(fic::incident::IncidentResponseMode::Off,
                  IncidentSeverity::Standard, "wayland", true);
    require(client->locks == 0 && client->terminatedSessions == 0,
            "OFF must not mutate sessions");
    runController(fic::incident::IncidentResponseMode::Passive,
                  IncidentSeverity::Standard, "wayland", true);
    require(client->locks == 0 && client->terminatedSessions == 0,
            "PASSIVE must not mutate sessions");
    const auto active = runController(fic::incident::IncidentResponseMode::Active,
                                      IncidentSeverity::Standard, "wayland", true);
    require(active.ok && client->locks == 1 && client->terminatedSessions == 1,
            "ACTIVE STANDARD must lock then terminate when lock is unproven");
    client->acceptLock = false;
    const auto rejectedLock = runController(fic::incident::IncidentResponseMode::Active,
                                             IncidentSeverity::Standard, "wayland", true);
    require(rejectedLock.ok && client->terminatedSessions == 1,
            "rejected lock must fall back to termination");
    client->acceptLock = true;
    const auto terminal = runController(fic::incident::IncidentResponseMode::Active,
                                         IncidentSeverity::Standard, "tty", true);
    require(terminal.ok && client->locks == 0 && client->terminatedSessions == 1,
            "terminal session must terminate without lock");
    const auto ssh = runController(fic::incident::IncidentResponseMode::Active,
                                    IncidentSeverity::Standard, "ssh", true);
    require(ssh.ok && client->locks == 0 && client->terminatedSessions == 1,
            "SSH session must terminate without lock");
    client->keepSession = true;
    const auto remaining = runController(fic::incident::IncidentResponseMode::Active,
                                          IncidentSeverity::Hard, "wayland", true);
    require(!remaining.ok && remaining.runtime == fic::incident::RuntimeState::Degraded &&
            client->locks == 0 && client->terminatedUsers == 0,
            "HARD must terminate sessions only, and surviving session degrades");
    client->keepSession = false;
    client->users = {user()};
    client->managerStopped = true;
    client->keepSession = false;
    const auto isolated = runController(fic::incident::IncidentResponseMode::Active,
                                         IncidentSeverity::Isolate, "tty", true);
    require(!isolated.ok && client->terminatedSessions == 1 &&
            client->terminatedUsers == 1,
            "ISOLATE must contain session and user despite missing network backend");

    const auto failed = runController(fic::incident::IncidentResponseMode::Active,
                                      IncidentSeverity::Standard, "wayland", false);
    require(!failed.ok && failed.runtime == fic::incident::RuntimeState::Degraded &&
            client->terminatedSessions == 0,
            "failed logind inventory must degrade without mutation");
    const auto highHard = runController(fic::incident::IncidentResponseMode::Active,
        IncidentSeverity::Hard, "wayland", true, 200000, evidenceClassifier);
    require(highHard.ok && client->terminatedSessions == 1 &&
            client->terminatedUsers == 0,
            "HARD must terminate and verify high-UID ordinary login session");
    const auto highTty = runController(fic::incident::IncidentResponseMode::Active,
        IncidentSeverity::Hard, "tty", true, 100001, evidenceClassifier);
    require(highTty.ok && client->terminatedSessions == 1,
            "HARD must terminate high-UID terminal login session");
    const auto highIsolate = runController(fic::incident::IncidentResponseMode::Active,
        IncidentSeverity::Isolate, "wayland", true, 200000, evidenceClassifier);
    require(!highIsolate.ok && client->terminatedSessions == 1 &&
            client->terminatedUsers == 1 &&
            lastContainment.userRuntimeContained,
            "ISOLATE must terminate and verify high-UID ordinary user runtime");
    const auto unavailableClassifier = [&](uid_t uid, const std::string& name,
                                           std::string& diagnostic) {
        return classifyProductionContainmentIdentity(
            uid, name, failedEvidence, diagnostic);
    };
    const auto unknownIdentity = runController(
        fic::incident::IncidentResponseMode::Active,
        IncidentSeverity::Hard, "wayland", true, 200000, unavailableClassifier);
    require(!unknownIdentity.ok && unknownIdentity.runtime ==
                fic::incident::RuntimeState::Degraded &&
            client->terminatedSessions == 0,
            "failed production identity proof must not produce false ACTIVE");
    const auto recoveryClassifier = [&](uid_t uid, const std::string& name,
                                        std::string& diagnostic) {
        return classifyProductionContainmentIdentity(
            uid, name, recoveryEvidence, diagnostic);
    };
    runController(fic::incident::IncidentResponseMode::Active,
        IncidentSeverity::Isolate, "wayland", true, 200000, recoveryClassifier);
    require(client->terminatedSessions == 0 && client->terminatedUsers == 0,
            "proved recovery member must survive ISOLATE");
    const auto serviceClassifier = [&](uid_t uid, const std::string& name,
                                       std::string& diagnostic) {
        return classifyProductionContainmentIdentity(
            uid, name, serviceEvidence, diagnostic);
    };
    // Model A R7: a service identity with a GENUINE ordinary login session is
    // a conscious target.
    runController(fic::incident::IncidentResponseMode::Active,
        IncidentSeverity::Isolate, "wayland", true, 200000, serviceClassifier);
    require(client->terminatedSessions == 1 && client->terminatedUsers == 1,
            "Model A: a service identity with a genuine login session is a "
            "target");
    // Model A R6: the same identity with ONLY a manager session (no ordinary
    // login session) is never selected.
    {
        client->sessions = {session("svc-runtime", 200000, "svc",
                                    "unspecified", "manager")};
        client->users = {user(200000, "svc")};
        client->terminatedSessions = client->terminatedUsers = 0;
        auto production = std::make_shared<LogindSessionContainmentBackend>(
            client, serviceClassifier);
        fic::incident::IncidentController controller(
            fic::incident::IncidentStateStore(state),
            fic::incident::IncidentSessionTargetStore(state.parent_path() /
                "incident_session_targets"),
            production,
            std::make_shared<fic::incident::NullIncidentNetworkBackend>());
        controller.setModeResolver([] {
            return fic::incident::IncidentResponseModeResult{
                fic::incident::IncidentResponseMode::Active, true, "test"};
        });
        controller.setAccessGateVerifier([](std::string&) { return true; });
        const auto result = controller.raise(
            IncidentSeverity::Isolate, {"test"}, "lingering only");
        require(client->terminatedSessions == 0 && client->terminatedUsers == 0,
                "Model A: a manager-only runtime is never a target");
        (void)result;
    }
    for (const char* className : {"manager", "background", "background-light"}) {
        const auto withRuntime = runController(
            fic::incident::IncidentResponseMode::Active, IncidentSeverity::Isolate,
            "wayland", true, 1000, evidenceClassifier,
            {session("runtime", 1000, "alice", "unspecified", className)});
        require(!withRuntime.ok && client->terminatedSessions == 1 &&
                client->terminatedUsers == 1 &&
                lastContainment.userRuntimeContained,
                "ISOLATE must terminate ordinary runtime with manager/background");
    }
    const auto withGreeter = runController(
        fic::incident::IncidentResponseMode::Active, IncidentSeverity::Isolate,
        "wayland", true, 1000, evidenceClassifier,
        {session("greeter", 1000, "alice", "wayland", "greeter")});
    require(!withGreeter.ok && client->terminatedUsers == 0,
            "ISOLATE must preserve same-UID greeter");
    const auto withLockScreen = runController(
        fic::incident::IncidentResponseMode::Active, IncidentSeverity::Isolate,
        "wayland", true, 1000, evidenceClassifier,
        {session("lock", 1000, "alice", "wayland", "lock-screen")});
    require(!withLockScreen.ok && client->terminatedUsers == 0,
            "ISOLATE must preserve same-UID lock-screen");
    const auto withManagerEarly = runController(
        fic::incident::IncidentResponseMode::Active, IncidentSeverity::Isolate,
        "wayland", true, 1000, evidenceClassifier,
        {session("early", 1000, "alice", "unspecified", "manager-early")});
    require(!withManagerEarly.ok && client->terminatedUsers == 0,
            "root-oriented manager-early must not authorize ordinary user termination");
    const auto withUnknownClass = runController(
        fic::incident::IncidentResponseMode::Active, IncidentSeverity::Isolate,
        "wayland", true, 1000, evidenceClassifier,
        {session("unknown", 1000, "alice", "unspecified", "future-class")});
    require(!withUnknownClass.ok && withUnknownClass.runtime ==
                fic::incident::RuntimeState::Degraded &&
            client->terminatedSessions == 0 && client->terminatedUsers == 0,
            "unknown logind class must fail closed without false ACTIVE");
    std::filesystem::remove_all(root);
}
