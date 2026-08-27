#ifndef FIC_SESSION_AGENT_SESSION_IDENTITY_RESOLVER_H
#define FIC_SESSION_AGENT_SESSION_IDENTITY_RESOLVER_H

#include <string>
#include <sys/types.h>
#include <vector>

namespace fic::session_agent {

struct LogindSessionInfo {
    uid_t uid = 0;
    std::string sessionClass;
    bool remote = false;
    std::string type;
};

struct AgentSessionContext {
    std::string sessionType;
    std::string desktop;
    std::string display;
    std::string waylandDisplay;
};

enum class ProcessSessionResult {
    Found,
    NotAssociated,
    Error
};

class LogindSessionProvider {
public:
    virtual ~LogindSessionProvider() = default;

    virtual ProcessSessionResult currentProcessSession(
        std::string& sessionId,
        std::string& error) const = 0;
    virtual bool userSessions(
        uid_t uid,
        std::vector<std::string>& sessions,
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
        const AgentSessionContext& agentContext,
        uid_t currentUid,
        const LogindSessionProvider& provider,
        std::string& sessionId,
        std::string& error);

    static bool validSessionId(const std::string& sessionId);

private:
    enum class ValidationResult {
        Valid,
        NotCandidate,
        Error
    };

    static ValidationResult validateSession(
        const std::string& sessionId,
        bool allowGraphicalContextForTty,
        const AgentSessionContext& agentContext,
        uid_t currentUid,
        const LogindSessionProvider& provider,
        std::string& error);
};

} // namespace fic::session_agent

#endif // FIC_SESSION_AGENT_SESSION_IDENTITY_RESOLVER_H
