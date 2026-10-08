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
enum class ContainmentIdentity { Ordinary, Recovery, Service, Unknown };

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
