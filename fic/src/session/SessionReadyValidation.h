#ifndef FIC_SESSION_READY_VALIDATION_H
#define FIC_SESSION_READY_VALIDATION_H

#include "session/UserSession.h"
#include <pwd.h>
#include <cerrno>
#include <cstring>
#include <vector>
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

// Build only after the caller has successfully read the logind properties.
using UserLookup = int (*)(uid_t, passwd*, char*, std::size_t, passwd**);
inline bool buildSession(uid_t peerUid, uid_t sessionUid,
                         const std::string& sessionId,
                         const std::string& sessionClass,
                         const std::string& state, const std::string& type,
                         bool safeAgentEndpointPresent,
                         UserSession& session, std::string& error,
                         UserLookup lookup = ::getpwuid_r)
{
    session = {};
    if (!validLogindClaim(peerUid, sessionUid, sessionClass, state, type,
                          safeAgentEndpointPresent)) {
        error = "session is not a live graphical user session";
        return false;
    }
    // Match the bounded NSS lookup budget used by session containment.
    constexpr std::size_t MaxBuffer = 4U * 1024U * 1024U;
    std::vector<char> buffer(16384);
    for (;;) {
        passwd record {};
        passwd* found = nullptr;
        const int result = lookup(peerUid, &record, buffer.data(), buffer.size(), &found);
        if (result == ERANGE && buffer.size() < MaxBuffer) {
            buffer.resize(buffer.size() * 2U);
            continue;
        }
        const std::string identity = "session_ready NSS lookup for UID " + std::to_string(peerUid);
        if (result != 0) {
            error = identity + (result == ERANGE ? " exceeded buffer limit: " : " failed: ") +
                std::strerror(result) + " (code=" + std::to_string(result) + ")";
            return false;
        }
        if (found == nullptr) {
            error = identity + ": user not found";
            return false;
        }
        if (found->pw_uid != peerUid || found->pw_name == nullptr || found->pw_name[0] == '\0') {
            error = identity + ": empty username or mismatched UID";
            return false;
        }
        session = {sessionId, peerUid, found->pw_name, type};
        error.clear();
        return true;
    }
}

} // namespace session_ready_validation

#endif
