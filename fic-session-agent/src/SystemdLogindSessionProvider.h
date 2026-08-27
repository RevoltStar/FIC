#ifndef FIC_SESSION_AGENT_SYSTEMD_LOGIND_SESSION_PROVIDER_H
#define FIC_SESSION_AGENT_SYSTEMD_LOGIND_SESSION_PROVIDER_H

#include "SessionIdentityResolver.h"

namespace fic::session_agent {

class SystemdLogindSessionProvider final : public LogindSessionProvider {
public:
    ProcessSessionResult currentProcessSession(
        std::string& sessionId,
        std::string& error) const override;
    bool userSessions(
        uid_t uid,
        std::vector<std::string>& sessions,
        std::string& error) const override;
    bool sessionInfo(
        const std::string& sessionId,
        LogindSessionInfo& info,
        std::string& error) const override;
};

} // namespace fic::session_agent

#endif // FIC_SESSION_AGENT_SYSTEMD_LOGIND_SESSION_PROVIDER_H
