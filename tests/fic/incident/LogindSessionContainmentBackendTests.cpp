#include "session/LogindSessionContainmentBackend.h"
#include "incident/IncidentController.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
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
        if (it->owner != expected.owner) { error = "owner changed"; return LogindLookup::Error; }
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
        if (!keepUser) users.erase(std::remove_if(users.begin(), users.end(),
            [&](const auto& current) { return current.uid == u.uid; }), users.end());
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
    client->sessions.clear();

    client->users = {user(), user(0, "root"), user(1001, "rescue"),
                     user(999, "display")};
    auto users = backend.listUsers();
    require(users.proven && users.users.size() == 4, "user inventory");
    for (std::size_t i = 1; i < users.users.size(); ++i)
        require(!backend.terminateUser(users.users[i]).performed,
                "protected user must never terminate");
    require(client->terminatedUsers == 0, "protected user reached logind action");
    client->sessions = {session("x1", 1000, "alice", "tty", "greeter")};
    require(!backend.terminateUser(users.users[0]).performed,
            "protected same-UID session blocks TerminateUser");
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
    const auto runController = [&](fic::incident::IncidentResponseMode mode,
                                   fic::core::IncidentSeverity severity,
                                   const std::string& type,
                                   bool inventoryOk) {
        resetState();
        client->sessions = {session("c1", 1000, "alice", type)};
        client->listSessionsOk = inventoryOk;
        client->locks = client->terminatedSessions = client->terminatedUsers = 0;
        auto production = std::make_shared<LogindSessionContainmentBackend>(
            client, identity);
        fic::incident::IncidentController controller(
            fic::incident::IncidentStateStore(state), production,
            std::make_shared<fic::incident::NullIncidentNetworkBackend>());
        controller.setModeResolver([mode] {
            return fic::incident::IncidentResponseModeResult{mode, true, "test"};
        });
        controller.setAccessGateVerifier([](std::string&) { return true; });
        return controller.raise(severity,
                                {"test"}, "session containment");
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
    std::filesystem::remove_all(root);
}
