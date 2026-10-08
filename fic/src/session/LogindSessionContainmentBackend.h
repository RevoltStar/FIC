#pragma once

#include "session/SessionContainmentBackend.h"

#include <functional>
#include <chrono>
#include <memory>

namespace fic::session {

struct LogindSessionRecord {
    std::string id;
    uid_t uid = 0;
    std::string name;
    std::string path;
    std::string owner;
    std::string type;
    std::string className;
    std::string state;
    bool remote = false;
    std::uint64_t timestamp = 0;
};

struct LogindUserRecord {
    uid_t uid = 0;
    std::string name;
    std::string path;
    std::string owner;
    std::string state;
    bool linger = false;
};

enum class LogindLookup { Found, Missing, Error };
// Model A identity decision. Service is retained for API compatibility but is
// NEVER produced any more: an account's login shell is not an account-purpose
// authority, and target selection is derived from proven logind login
// sessions, not from /etc/passwd fields.
enum class ContainmentIdentity { Ordinary, Recovery, Service, Unknown };

struct ContainmentIdentityEvidence {
    uid_t uid = 0;
    std::string canonicalName;
    std::string shell;
    bool recoveryExemptionEnabled = false;
    bool recoveryMember = false;
};
using ContainmentIdentityEvidenceReader = std::function<bool(
    uid_t, const std::string&, ContainmentIdentityEvidence&, std::string&)>;

// A deliberately small transport seam. Implementations must pin every
// operation to the unique bus owner recorded in the inventory snapshot.
class LogindClient {
public:
    virtual ~LogindClient() = default;
    virtual bool listSessions(std::vector<LogindSessionRecord>&,
                              std::string&) = 0;
    virtual bool listUsers(std::vector<LogindUserRecord>&,
                           std::string&) = 0;
    virtual LogindLookup getSession(const LogindSessionRecord&,
                                    LogindSessionRecord&, std::string&) = 0;
    virtual LogindLookup getUser(const LogindUserRecord&,
                                 LogindUserRecord&, std::string&) = 0;
    virtual bool lockSession(const LogindSessionRecord&, std::string&) = 0;
    virtual bool terminateSession(const LogindSessionRecord&, std::string&) = 0;
    virtual bool terminateUser(const LogindUserRecord&, std::string&) = 0;
    virtual bool userManagerStopped(uid_t, bool&, std::string&) = 0;
};

std::shared_ptr<LogindClient> makeSystemLogindClient();
ContainmentIdentity classifyProductionContainmentIdentity(
    uid_t uid, const std::string& name, std::string& diagnostic);
// The same production decision path with an injectable raw NSS/recovery
// evidence reader for deterministic tests. Unknown evidence fails closed.
ContainmentIdentity classifyProductionContainmentIdentity(
    uid_t uid, const std::string& name,
    const ContainmentIdentityEvidenceReader& readEvidence,
    std::string& diagnostic);

class LogindSessionContainmentBackend final : public SessionContainmentBackend {
public:
    using IdentityClassifier = std::function<ContainmentIdentity(
        uid_t, const std::string&, std::string&)>;
    LogindSessionContainmentBackend();
    LogindSessionContainmentBackend(std::shared_ptr<LogindClient> client,
                                    IdentityClassifier classify);

    SessionInventoryResult listSessions() override;
    UserInventoryResult listUsers() override;
    SessionKind classifySession(const LoginSession&) override;
    ContainmentOutcome lockSession(const LoginSession&) override;
    bool verifySessionLocked(const LoginSession&, std::string&) override;
    ContainmentOutcome terminateSession(const LoginSession&) override;
    ContainmentOutcome terminateUser(const LoginUser&) override;
    bool verifySessionsGone(const std::vector<LoginSession>&,
                            std::string&) override;
    bool verifyUserRuntimeGone(const LoginUser&, std::string&) override;
    RegisteredUserLookup lookupProvenUser(
        uid_t uid, const std::string& expectedCanonicalName) override;

private:
    std::shared_ptr<LogindClient> client_;
    IdentityClassifier classify_;
    std::chrono::steady_clock::time_point sessionDeadline_{};
    std::chrono::steady_clock::time_point userDeadline_{};
    LogindSessionRecord asRecord(const LoginSession&) const;
    LogindUserRecord asRecord(const LoginUser&) const;
    bool safeSession(const LoginSession&, bool& missing, std::string&);
    bool safeUser(const LoginUser&, bool& missing, std::string&);
};

} // namespace fic::session
