#ifndef SESSION_SELECTION_H
#define SESSION_SELECTION_H

#include "session/UserSession.h"

#include <string>

struct SessionProperties {
    UserSession session;
    std::string sessionClass;
    std::string state;
    bool remote = false;
};

namespace session_selection {

bool graphicalSessionCandidate(const SessionProperties& properties,
                               bool agentEndpointPresent);

} // namespace session_selection

#endif // SESSION_SELECTION_H
