#ifndef FIC_SESSION_READY_VALIDATION_H
#define FIC_SESSION_READY_VALIDATION_H

#include <string>
#include <sys/types.h>

namespace session_ready_validation {

inline bool validLogindClaim(uid_t peerUid,
                             uid_t sessionUid,
                             const std::string& sessionClass,
                             const std::string& state,
                             const std::string& type,
                             bool safeAgentEndpointPresent)
{
    if (peerUid != sessionUid || sessionClass != "user" ||
        state == "closing" || state == "dead") return false;
    if (type == "x11" || type == "wayland" || type == "mir") return true;
    return type == "tty" && safeAgentEndpointPresent;
}

} // namespace session_ready_validation

#endif
