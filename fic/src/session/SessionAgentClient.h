#ifndef SESSION_AGENT_CLIENT_H
#define SESSION_AGENT_CLIENT_H

#include "session/UserSession.h"

#include <string>

class SessionAgentClient {
public:
    static bool query(const UserSession& session, SessionContext& context, std::string& error);
    static std::string socketPath(const UserSession& session);
};

#endif // SESSION_AGENT_CLIENT_H
