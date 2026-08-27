#include "SystemdLogindSessionProvider.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <systemd/sd-login.h>

namespace fic::session_agent {
namespace {
std::string systemd_error(int result) {
    return std::strerror(result < 0 ? -result : result);
}

bool read_session_string(
    int (*getter)(const char*, char**),
    const std::string& sessionId,
    const char* property,
    std::string& value,
    std::string& error) {
    char* rawValue = nullptr;
    const int result = getter(sessionId.c_str(), &rawValue);
    if (result < 0) {
        error = std::string("could not read logind ") + property + ": " +
            systemd_error(result);
        return false;
    }
    value = rawValue == nullptr ? std::string() : std::string(rawValue);
    std::free(rawValue);
    return true;
}
} // namespace

bool SystemdLogindSessionProvider::currentProcessSession(
    std::string& sessionId,
    std::string& error) const {
    char* rawSessionId = nullptr;
    const int result = ::sd_pid_get_session(0, &rawSessionId);
    if (result < 0) {
        error = systemd_error(result);
        return false;
    }
    sessionId = rawSessionId == nullptr ? std::string() : std::string(rawSessionId);
    std::free(rawSessionId);
    return true;
}

bool SystemdLogindSessionProvider::sessionInfo(
    const std::string& sessionId,
    LogindSessionInfo& info,
    std::string& error) const {
    const int uidResult = ::sd_session_get_uid(sessionId.c_str(), &info.uid);
    if (uidResult < 0) {
        error = "could not read logind User: " + systemd_error(uidResult);
        return false;
    }
    if (!read_session_string(
            ::sd_session_get_class,
            sessionId,
            "Class",
            info.sessionClass,
            error) ||
        !read_session_string(
            ::sd_session_get_type,
            sessionId,
            "Type",
            info.type,
            error)) {
        return false;
    }

    const int remoteResult = ::sd_session_is_remote(sessionId.c_str());
    if (remoteResult < 0) {
        error = "could not read logind Remote: " + systemd_error(remoteResult);
        return false;
    }
    info.remote = remoteResult > 0;
    return true;
}

} // namespace fic::session_agent
