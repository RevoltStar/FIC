#include "session/LogindSessionContainmentBackend.h"

#include "incident/IncidentRecoveryConfigReader.h"
#include "modules/identity_access/pam/PamEffectiveGroupMembership.h"
#include "platform/PlatformProfile.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <pwd.h>
#include <set>
#include <thread>
#include <vector>

namespace fic::session {
namespace {

bool ordinaryClass(const std::string& name) {
    return name == "user" || name == "user-early" ||
           name == "user-light" || name == "user-early-light";
}

bool userRuntimeClass(const std::string& name) {
    return ordinaryClass(name) || name == "manager" ||
           name == "background" || name == "background-light";
}

bool protectedSessionClass(const std::string& name) {
    return name == "greeter" || name == "lock-screen" ||
           name == "manager" || name == "manager-early" ||
           name == "background" || name == "background-light";
}

bool knownSessionState(const std::string& state) {
    return state == "online" || state == "active" || state == "closing";
}

bool knownUserState(const std::string& state) {
    return state == "offline" || state == "lingering" ||
           state == "online" || state == "active" || state == "closing";
}

bool sameSession(const LogindSessionRecord& a, const LogindSessionRecord& b) {
    return a.id == b.id && a.uid == b.uid && a.name == b.name &&
           a.path == b.path && a.owner == b.owner && a.type == b.type &&
           a.className == b.className && a.timestamp == b.timestamp;
}

bool sameUser(const LogindUserRecord& a, const LogindUserRecord& b) {
    return a.uid == b.uid && a.name == b.name && a.path == b.path &&
           a.owner == b.owner;
}

} // namespace

bool readProductionIdentityEvidence(
    uid_t uid, const std::string& name,
    ContainmentIdentityEvidence& evidence, std::string& diagnostic) {
    ::fic::identity::pam::PamUserIdentity identity;
    if (name.empty() ||
        !::fic::identity::pam::resolvePamUserIdentity(name, identity, diagnostic) ||
        identity.uid != uid || identity.canonicalName != name) {
        if (diagnostic.empty()) diagnostic = "NSS identity does not match logind";
        return false;
    }
    const auto profile = ::fic::platform::makeBuildPlatformProfile();
    const auto exemption =
        ::fic::incident::IncidentRecoveryConfigReader::ficMemberExemptionStatus(diagnostic);
    if (!exemption) return false;
    bool member = false;
    if (*exemption) {
        if (!::fic::identity::pam::isPamUserMemberOfGroup(
                identity, profile.pam.incidentAccessGate.recoveryGroup,
                member, diagnostic))
            return false;
    }
    std::vector<char> buffer(16384);
    struct passwd record {};
    struct passwd* found = nullptr;
    int lookup = 0;
    do {
        lookup = ::getpwnam_r(name.c_str(), &record, buffer.data(),
                              buffer.size(), &found);
        if (lookup == ERANGE && buffer.size() < 4U * 1024U * 1024U)
            buffer.resize(buffer.size() * 2U);
        else break;
    } while (true);
    if (lookup != 0 || found == nullptr || found->pw_uid != uid ||
        found->pw_name == nullptr || name != found->pw_name ||
        found->pw_shell == nullptr) {
        diagnostic = "NSS login account proof failed";
        return false;
    }
    evidence = {uid, identity.canonicalName, found->pw_shell, *exemption, member};
    return true;
}

static ContainmentIdentity classifyContainmentIdentityWithEvidence(
    uid_t uid, const std::string& name,
    const ContainmentIdentityEvidenceReader& readEvidence,
    std::string& diagnostic) {
    if (uid == 0) return ContainmentIdentity::Recovery;
    ContainmentIdentityEvidence evidence;
    if (!readEvidence(uid, name, evidence, diagnostic) ||
        evidence.uid != uid || evidence.canonicalName != name) {
        if (diagnostic.empty()) diagnostic = "NSS identity does not match logind";
        return ContainmentIdentity::Unknown;
    }
    if (evidence.recoveryExemptionEnabled && evidence.recoveryMember)
        return ContainmentIdentity::Recovery;
    const std::string& shell = evidence.shell;
    if (shell.empty() || shell.front() != '/') {
        diagnostic = "NSS login shell is not proven";
        return ContainmentIdentity::Unknown;
    }
    const std::string shellName = shell.substr(shell.find_last_of('/') + 1);
    if (shellName.empty()) {
        diagnostic = "NSS login shell is not proven";
        return ContainmentIdentity::Unknown;
    }
    if (shellName == "nologin" || shellName == "false" || shellName == "true")
        return ContainmentIdentity::Service;
    return ContainmentIdentity::Ordinary;
}

static ContainmentIdentity classifyProductionContainmentIdentitySync(
    uid_t uid, const std::string& name,
    const ContainmentIdentityEvidenceReader& readEvidence,
    std::string& diagnostic) {
    return classifyContainmentIdentityWithEvidence(
        uid, name, readEvidence, diagnostic);
}

ContainmentIdentity classifyProductionContainmentIdentity(
    uid_t uid, const std::string& name, std::string& diagnostic) {
    return classifyProductionContainmentIdentity(
        uid, name, readProductionIdentityEvidence, diagnostic);
}

ContainmentIdentity classifyProductionContainmentIdentity(
    uid_t uid, const std::string& name,
    const ContainmentIdentityEvidenceReader& readEvidence,
    std::string& diagnostic) {
    struct Answer {
        ContainmentIdentity identity = ContainmentIdentity::Unknown;
        std::string diagnostic;
    };
    // NSS providers can be remote. Keep at most one potentially stalled
    // classifier worker; a timeout is an unknown identity, never permission
    // to terminate. The detached worker owns all of its inputs and result.
    static std::atomic_bool workerBusy{false};
    if (workerBusy.exchange(true)) {
        diagnostic = "identity verifier is still busy";
        return ContainmentIdentity::Unknown;
    }
    auto promise = std::make_shared<std::promise<Answer>>();
    auto result = promise->get_future();
    try {
        std::thread([uid, name, readEvidence, promise] {
            Answer answer;
            try {
                answer.identity = classifyProductionContainmentIdentitySync(
                    uid, name, readEvidence, answer.diagnostic);
            } catch (...) {
                answer.diagnostic = "identity verifier failed";
            }
            workerBusy.store(false);
            promise->set_value(std::move(answer));
        }).detach();
    } catch (...) {
        workerBusy.store(false);
        diagnostic = "identity verifier could not start";
        return ContainmentIdentity::Unknown;
    }
    if (result.wait_for(std::chrono::seconds(2)) != std::future_status::ready) {
        diagnostic = "identity verification timed out";
        return ContainmentIdentity::Unknown;
    }
    Answer answer = result.get();
    diagnostic = std::move(answer.diagnostic);
    return answer.identity;
}

LogindSessionContainmentBackend::LogindSessionContainmentBackend()
    : LogindSessionContainmentBackend(makeSystemLogindClient(),
        [](uid_t uid, const std::string& name, std::string& diagnostic) {
            return classifyProductionContainmentIdentity(uid, name, diagnostic);
        }) {}

LogindSessionContainmentBackend::LogindSessionContainmentBackend(
    std::shared_ptr<LogindClient> client, IdentityClassifier classify)
    : client_(std::move(client)), classify_(std::move(classify)) {}

LogindSessionRecord LogindSessionContainmentBackend::asRecord(
    const LoginSession& s) const {
    return {s.id, s.uid, s.user, s.objectPath, s.logindOwner,
            s.type, s.className, s.state, s.remote, s.startTimestamp};
}
LogindUserRecord LogindSessionContainmentBackend::asRecord(
    const LoginUser& u) const {
    return {u.uid, u.name, u.objectPath, u.logindOwner, "", false};
}

SessionInventoryResult LogindSessionContainmentBackend::listSessions() {
    sessionDeadline_ = std::chrono::steady_clock::now() +
                       std::chrono::seconds(15);
    std::vector<LogindSessionRecord> records;
    std::string diagnostic;
    if (!client_->listSessions(records, diagnostic)) return {false, {}, diagnostic};
    SessionInventoryResult result{true, {}, ""};
    std::set<std::string> seen;
    for (const auto& r : records) {
        if (std::chrono::steady_clock::now() >= sessionDeadline_)
            return {false, {}, "session identity inventory deadline exceeded"};
        if (r.id.empty() || r.name.empty() || r.path.empty() ||
            r.owner.empty() || r.timestamp == 0 || r.className.empty() ||
            r.type.empty() || !knownSessionState(r.state) ||
            !seen.insert(r.id).second)
            return {false, {}, "incomplete logind session identity"};
        const auto identity = classify_(r.uid, r.name, diagnostic);
        LoginSession s;
        s.id = r.id; s.uid = r.uid; s.user = r.name;
        s.type = r.type; s.className = r.className; s.state = r.state;
        s.remote = r.remote; s.objectPath = r.path;
        s.logindOwner = r.owner; s.startTimestamp = r.timestamp;
        s.kind = classifySession(s);
        s.recovery = identity == ContainmentIdentity::Recovery;
        s.ordinary = identity == ContainmentIdentity::Ordinary &&
                     ordinaryClass(r.className);
        s.serviceAccount = identity == ContainmentIdentity::Service ||
            protectedSessionClass(r.className);
        if (identity == ContainmentIdentity::Unknown ||
            (!ordinaryClass(r.className) &&
             !protectedSessionClass(r.className))) {
            result.proven = false;
            result.diagnostic = "session identity/classification is unproven: " + r.id;
        }
        result.sessions.push_back(std::move(s));
    }
    return result;
}

UserInventoryResult LogindSessionContainmentBackend::listUsers() {
    userDeadline_ = std::chrono::steady_clock::now() +
                    std::chrono::seconds(15);
    std::vector<LogindUserRecord> records;
    std::string diagnostic;
    if (!client_->listUsers(records, diagnostic)) return {false, {}, diagnostic};
    UserInventoryResult result{true, {}, ""};
    std::set<uid_t> seen;
    for (const auto& r : records) {
        if (std::chrono::steady_clock::now() >= userDeadline_)
            return {false, {}, "user identity inventory deadline exceeded"};
        if (r.name.empty() || r.path.empty() || r.owner.empty() ||
            !knownUserState(r.state) || !seen.insert(r.uid).second)
            return {false, {}, "incomplete logind user identity"};
        const auto identity = classify_(r.uid, r.name, diagnostic);
        LoginUser u;
        u.uid = r.uid; u.name = r.name; u.objectPath = r.path;
        u.logindOwner = r.owner;
        u.recovery = identity == ContainmentIdentity::Recovery;
        u.serviceAccount = identity == ContainmentIdentity::Service;
        u.ordinary = identity == ContainmentIdentity::Ordinary;
        u.userManagerRunning = r.state != "offline";
        if (identity == ContainmentIdentity::Unknown) {
            result.proven = false;
            result.diagnostic = "user identity is unproven: " + r.name;
        }
        result.users.push_back(std::move(u));
    }
    return result;
}

SessionKind LogindSessionContainmentBackend::classifySession(
    const LoginSession& s) {
    if (s.type == "x11" || s.type == "wayland" || s.type == "mir")
        return SessionKind::Graphical;
    if (s.type == "tty" || s.type == "ssh" || s.type == "console")
        return SessionKind::Terminal;
    return SessionKind::Unknown;
}

bool LogindSessionContainmentBackend::safeSession(
    const LoginSession& session, bool& missing, std::string& diagnostic) {
    if (std::chrono::steady_clock::now() >= sessionDeadline_) {
        diagnostic = "session containment deadline exceeded";
        return false;
    }
    missing = false;
    LogindSessionRecord current;
    const auto expected = asRecord(session);
    const auto status = client_->getSession(expected, current, diagnostic);
    if (status == LogindLookup::Missing) { missing = true; return true; }
    if (status != LogindLookup::Found) return false;
    if (!sameSession(expected, current)) {
        diagnostic = "logind session identity changed";
        return false;
    }
    const auto identity = classify_(current.uid, current.name, diagnostic);
    if (!session.ordinary || session.recovery || current.uid == 0 ||
        identity != ContainmentIdentity::Ordinary ||
        !ordinaryClass(current.className)) {
        diagnostic = "session is not a proven ordinary target";
        return false;
    }
    return true;
}

bool LogindSessionContainmentBackend::safeUser(
    const LoginUser& user, bool& missing, std::string& diagnostic) {
    if (std::chrono::steady_clock::now() >= userDeadline_) {
        diagnostic = "user containment deadline exceeded";
        return false;
    }
    missing = false;
    LogindUserRecord current;
    const auto expected = asRecord(user);
    const auto status = client_->getUser(expected, current, diagnostic);
    if (status == LogindLookup::Missing) { missing = true; return true; }
    if (status != LogindLookup::Found) return false;
    if (!sameUser(expected, current) || !user.ordinary || user.recovery ||
        user.serviceAccount || user.uid == 0 ||
        classify_(current.uid, current.name, diagnostic) !=
            ContainmentIdentity::Ordinary) {
        diagnostic = "user is not a proven ordinary target";
        return false;
    }
    std::vector<LogindSessionRecord> sessions;
    if (!client_->listSessions(sessions, diagnostic)) return false;
    for (const auto& s : sessions) {
        if (s.uid != user.uid) continue;
        if (s.owner != user.logindOwner || s.name != user.name ||
            s.id.empty() || s.path.empty() || s.timestamp == 0 ||
            !knownSessionState(s.state) ||
            classify_(s.uid, s.name, diagnostic) !=
                ContainmentIdentity::Ordinary ||
            !userRuntimeClass(s.className)) {
            diagnostic = "user runtime includes an unproven or protected session";
            return false;
        }
    }
    if (std::chrono::steady_clock::now() >= userDeadline_) {
        diagnostic = "user containment deadline exceeded";
        return false;
    }
    LogindUserRecord refreshed;
    if (client_->getUser(expected, refreshed, diagnostic) != LogindLookup::Found ||
        !sameUser(expected, refreshed) ||
        classify_(refreshed.uid, refreshed.name, diagnostic) !=
            ContainmentIdentity::Ordinary) {
        diagnostic = "user identity changed before termination";
        return false;
    }
    return true;
}

ContainmentOutcome LogindSessionContainmentBackend::lockSession(
    const LoginSession& session) {
    std::string diagnostic;
    bool missing = false;
    if (!safeSession(session, missing, diagnostic)) return {false, diagnostic};
    if (missing) return {false, "session disappeared before lock"};
    if (std::chrono::steady_clock::now() >= sessionDeadline_)
        return {false, "session containment deadline exceeded"};
    if (classifySession(session) != SessionKind::Graphical)
        return {false, "session is not graphical"};
    const bool accepted = client_->lockSession(asRecord(session), diagnostic);
    return {accepted, diagnostic};
}

bool LogindSessionContainmentBackend::verifySessionLocked(
    const LoginSession&, std::string& diagnostic) {
    // LockSession only signals the desktop. LockedHint is supplied by the
    // user's session and is not a trusted proof of an enforced screen lock.
    diagnostic = "no trusted desktop lock proof; terminating session";
    return false;
}

ContainmentOutcome LogindSessionContainmentBackend::terminateSession(
    const LoginSession& session) {
    std::string diagnostic;
    bool missing = false;
    if (!safeSession(session, missing, diagnostic)) return {false, diagnostic};
    if (missing) return {true, "session already absent"};
    if (std::chrono::steady_clock::now() >= sessionDeadline_)
        return {false, "session containment deadline exceeded"};
    const bool accepted = client_->terminateSession(asRecord(session), diagnostic);
    return {accepted, diagnostic};
}

ContainmentOutcome LogindSessionContainmentBackend::terminateUser(
    const LoginUser& user) {
    std::string diagnostic;
    bool missing = false;
    if (!safeUser(user, missing, diagnostic)) return {false, diagnostic};
    if (missing) return {true, "user runtime already absent"};
    if (std::chrono::steady_clock::now() >= userDeadline_)
        return {false, "user containment deadline exceeded"};
    const bool accepted = client_->terminateUser(asRecord(user), diagnostic);
    return {accepted, diagnostic};
}

bool LogindSessionContainmentBackend::verifySessionsGone(
    const std::vector<LoginSession>& sessions, std::string& diagnostic) {
    if (std::chrono::steady_clock::now() >= sessionDeadline_) {
        diagnostic = "session verification deadline exceeded";
        return false;
    }
    for (const auto& session : sessions) {
        if (std::chrono::steady_clock::now() >= sessionDeadline_) {
            diagnostic = "session verification deadline exceeded";
            return false;
        }
        LogindSessionRecord current;
        const auto status = client_->getSession(asRecord(session), current, diagnostic);
        if (status == LogindLookup::Error) return false;
        if (status == LogindLookup::Found) {
            diagnostic = sameSession(asRecord(session), current)
                ? "session remains after termination" :
                  "session ID was reused or identity changed";
            return false;
        }
    }
    return true;
}

bool LogindSessionContainmentBackend::verifyUserRuntimeGone(
    const LoginUser& user, std::string& diagnostic) {
    if (std::chrono::steady_clock::now() >= userDeadline_) {
        diagnostic = "user runtime verification deadline exceeded";
        return false;
    }
    LogindUserRecord current;
    const auto status = client_->getUser(asRecord(user), current, diagnostic);
    if (status == LogindLookup::Error) return false;
    if (status == LogindLookup::Found) {
        diagnostic = "logind user runtime remains or lingering restarted it";
        return false;
    }
    std::vector<LogindSessionRecord> sessions;
    if (!client_->listSessions(sessions, diagnostic)) return false;
    if (std::any_of(sessions.begin(), sessions.end(),
                    [&](const auto& s) { return s.uid == user.uid; })) {
        diagnostic = "user sessions remain";
        return false;
    }
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (std::chrono::steady_clock::now() >= userDeadline_) {
            diagnostic = "user runtime verification deadline exceeded";
            return false;
        }
        bool stopped = false;
        if (!client_->userManagerStopped(user.uid, stopped, diagnostic)) return false;
        if (!stopped) {
            diagnostic = "systemd user manager remains active";
            return false;
        }
        if (attempt == 0) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return true;
}

} // namespace fic::session
