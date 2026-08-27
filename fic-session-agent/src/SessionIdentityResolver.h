#ifndef FIC_SESSION_AGENT_SESSION_IDENTITY_RESOLVER_H
#define FIC_SESSION_AGENT_SESSION_IDENTITY_RESOLVER_H

#include <string>
#include <sys/types.h>

namespace fic::session_agent {

struct LogindSessionInfo {
    uid_t uid = 0;
    std::string sessionClass;
    bool remote = false;
    std::string type;
};

class LogindSessionProvider {
public:
    virtual ~LogindSessionProvider() = default;

    virtual bool currentProcessSession(
        std::string& sessionId,
        std::string& error) const = 0;
    virtual bool sessionInfo(
        const std::string& sessionId,
        LogindSessionInfo& info,
        std::string& error) const = 0;
};

class SessionIdentityResolver {
public:
    static bool resolve(
        const std::string& environmentSessionId,
        uid_t currentUid,
        const LogindSessionProvider& provider,
        std::string& sessionId,
        std::string& error);

    static bool validSessionId(const std::string& sessionId);

private:
    static bool validateSession(
        const std::string& sessionId,
        uid_t currentUid,
        const LogindSessionProvider& provider,
        std::string& error);
};

} // namespace fic::session_agent

#endif // FIC_SESSION_AGENT_SESSION_IDENTITY_RESOLVER_H
