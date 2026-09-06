#include "session/SessionSelection.h"

namespace {

bool graphicalType(const std::string& type)
{
    return type == "x11" || type == "wayland" || type == "mir";
}

} // namespace

namespace session_selection {

bool graphicalSessionCandidate(const SessionProperties& properties,
                               bool agentEndpointPresent)
{
    if (properties.sessionClass != "user" ||
        properties.state == "closing" || properties.state == "dead") {
        return false;
    }
    return graphicalType(properties.session.type) ||
        (properties.session.type == "tty" && agentEndpointPresent);
}

} // namespace session_selection
