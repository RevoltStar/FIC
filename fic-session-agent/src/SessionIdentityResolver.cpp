#include "SessionIdentityResolver.h"

namespace fic::session_agent {
namespace {
bool ascii_alphanumeric(unsigned char ch) {
    return (ch >= '0' && ch <= '9') ||
        (ch >= 'A' && ch <= 'Z') ||
        (ch >= 'a' && ch <= 'z');
}

bool graphical_type(const std::string& type) {
    return type == "x11" || type == "wayland" || type == "mir";
}

std::string describe_session(const LogindSessionInfo& info) {
    return "Class=" + info.sessionClass +
        ", Remote=" + (info.remote ? "yes" : "no") +
        ", Type=" + info.type;
}
} // namespace

bool SessionIdentityResolver::validSessionId(const std::string& sessionId) {
    if (sessionId.empty()) {
        return false;
    }
    for (const unsigned char ch : sessionId) {
        if (!ascii_alphanumeric(ch) && ch != '_' && ch != '-') {
            return false;
        }
    }
    return true;
}

bool SessionIdentityResolver::validateSession(
    const std::string& sessionId,
    uid_t currentUid,
    const LogindSessionProvider& provider,
    std::string& error) {
    if (!validSessionId(sessionId)) {
        error = "invalid logind session id: " + sessionId;
        return false;
    }

    LogindSessionInfo info;
    if (!provider.sessionInfo(sessionId, info, error)) {
        error = "could not inspect logind session " + sessionId + ": " + error;
        return false;
    }
    if (info.uid != currentUid) {
        error = "logind session " + sessionId +
            " does not belong to the current uid";
        return false;
    }
    if (info.sessionClass != "user" || info.remote || !graphical_type(info.type)) {
        error = "logind session " + sessionId +
            " is not a local graphical user session (" +
            describe_session(info) + ")";
        return false;
    }
    return true;
}

bool SessionIdentityResolver::resolve(
    const std::string& environmentSessionId,
    uid_t currentUid,
    const LogindSessionProvider& provider,
    std::string& sessionId,
    std::string& error) {
    std::string environmentError;
    if (!environmentSessionId.empty()) {
        if (validateSession(
                environmentSessionId,
                currentUid,
                provider,
                environmentError)) {
            sessionId = environmentSessionId;
            error.clear();
            return true;
        }
    }

    std::string processSessionId;
    std::string processError;
    if (!provider.currentProcessSession(processSessionId, processError)) {
        if (environmentSessionId.empty()) {
            error = "XDG_SESSION_ID is not set and the current process is not "
                "associated with a logind session: " + processError;
        } else {
            error = "XDG_SESSION_ID was rejected (" + environmentError +
                "); the current process is not associated with a logind session: " +
                processError;
        }
        return false;
    }

    if (!validateSession(processSessionId, currentUid, provider, processError)) {
        if (environmentSessionId.empty()) {
            error = "the current process logind session was rejected: " + processError;
        } else {
            error = "XDG_SESSION_ID was rejected (" + environmentError +
                "); the current process logind session was rejected: " + processError;
        }
        return false;
    }

    sessionId = processSessionId;
    error.clear();
    return true;
}

} // namespace fic::session_agent
