#ifndef SESSION_AGENT_CLIENT_INTERNAL_H
#define SESSION_AGENT_CLIENT_INTERNAL_H

#include "session/UserSession.h"

#include <chrono>
#include <string>

namespace session_agent_client_detail {

bool validateContextIdentity(const UserSession& session,
                             const SessionContext& context,
                             std::string& error);

bool queryAtPath(
    const UserSession& session,
    const std::string& path,
    std::chrono::milliseconds readinessTimeout,
    std::chrono::milliseconds retryInterval,
    SessionContext& context,
    std::string& error);

} // namespace session_agent_client_detail

#endif // SESSION_AGENT_CLIENT_INTERNAL_H
