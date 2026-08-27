#include "SessionIdentityResolver.h"

#include <sstream>

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

bool graphical_context(const AgentSessionContext& context) {
    if (context.desktop.empty()) {
        return false;
    }
    if (context.sessionType == "wayland") {
        return !context.waylandDisplay.empty();
    }
    if (context.sessionType == "x11" || context.sessionType == "mir") {
        return !context.display.empty();
    }
    return false;
}

std::string describe_session(const LogindSessionInfo& info) {
    return "Class=" + info.sessionClass +
        ", Remote=" + (info.remote ? "yes" : "no") +
        ", Type=" + info.type;
}

std::string environment_prefix(
    const std::string& environmentSessionId,
    const std::string& environmentError) {
    if (environmentSessionId.empty()) {
        return "XDG_SESSION_ID is not set";
    }
    return "XDG_SESSION_ID was rejected (" + environmentError + ")";
}

std::string join_session_ids(const std::vector<std::string>& sessionIds) {
    std::ostringstream output;
    for (size_t index = 0; index < sessionIds.size(); ++index) {
        if (index != 0) {
            output << ", ";
        }
        output << sessionIds[index];
    }
    return output.str();
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

SessionIdentityResolver::ValidationResult SessionIdentityResolver::validateSession(
    const std::string& sessionId,
    bool allowGraphicalContextForTty,
    const AgentSessionContext& agentContext,
    uid_t currentUid,
    const LogindSessionProvider& provider,
    std::string& error) {
    if (!validSessionId(sessionId)) {
        error = "invalid logind session id: " + sessionId;
        return ValidationResult::Error;
    }

    LogindSessionInfo info;
    if (!provider.sessionInfo(sessionId, info, error)) {
        error = "could not inspect logind session " + sessionId + ": " + error;
        return ValidationResult::Error;
    }
    if (info.uid != currentUid) {
        error = "logind session " + sessionId +
            " does not belong to the current uid";
        return ValidationResult::NotCandidate;
    }
    if (info.sessionClass != "user") {
        error = "logind session " + sessionId +
            " is not a user session (" +
            describe_session(info) + ")";
        return ValidationResult::NotCandidate;
    }
    if (!graphical_type(info.type) &&
        !(allowGraphicalContextForTty && info.type == "tty" &&
          graphical_context(agentContext))) {
        error = "logind session " + sessionId +
            " is not graphical and has no matching graphical agent context (" +
            describe_session(info) + ")";
        return ValidationResult::NotCandidate;
    }
    error.clear();
    return ValidationResult::Valid;
}

bool SessionIdentityResolver::resolve(
    const std::string& environmentSessionId,
    const AgentSessionContext& agentContext,
    uid_t currentUid,
    const LogindSessionProvider& provider,
    std::string& sessionId,
    std::string& error) {
    std::string environmentError;
    if (!environmentSessionId.empty()) {
        if (validateSession(
                environmentSessionId,
                true,
                agentContext,
                currentUid,
                provider,
                environmentError) == ValidationResult::Valid) {
            sessionId = environmentSessionId;
            error.clear();
            return true;
        }
    }

    std::string processSessionId;
    std::string processError;
    const ProcessSessionResult processResult =
        provider.currentProcessSession(processSessionId, processError);
    if (processResult == ProcessSessionResult::Error) {
        error = environment_prefix(environmentSessionId, environmentError) +
            "; could not determine the current process logind session: " +
            processError;
        return false;
    }

    if (processResult == ProcessSessionResult::Found) {
        if (validateSession(
                processSessionId,
                true,
                agentContext,
                currentUid,
                provider,
                processError) != ValidationResult::Valid) {
            error = environment_prefix(environmentSessionId, environmentError) +
                "; current process belongs to logind session " +
                processSessionId + ", but that session was rejected: " +
                processError;
            return false;
        }

        sessionId = processSessionId;
        error.clear();
        return true;
    }

    std::vector<std::string> userSessions;
    std::string enumerationError;
    if (!provider.userSessions(currentUid, userSessions, enumerationError)) {
        error = environment_prefix(environmentSessionId, environmentError) +
            "; the current process is not associated with a logind session, "
            "and sessions for uid " + std::to_string(currentUid) +
            " could not be enumerated: " + enumerationError;
        return false;
    }

    std::vector<std::string> graphicalCandidates;
    for (const std::string& candidate : userSessions) {
        std::string candidateError;
        const ValidationResult validation = validateSession(
            candidate, false, agentContext, currentUid, provider,
            candidateError);
        if (validation == ValidationResult::Error) {
            error = environment_prefix(environmentSessionId, environmentError) +
                "; the current process is not associated with a logind session, "
                "and candidate session " + candidate +
                " could not be validated: " + candidateError;
            return false;
        }
        if (validation == ValidationResult::Valid) {
            graphicalCandidates.push_back(candidate);
        }
    }

    if (graphicalCandidates.size() == 1) {
        sessionId = graphicalCandidates.front();
        error.clear();
        return true;
    }

    error = environment_prefix(environmentSessionId, environmentError) +
        "; the current process is not associated with a logind session, and ";
    if (graphicalCandidates.empty()) {
        error += "no local graphical user session exists for uid " +
            std::to_string(currentUid);
    } else {
        error += "multiple local graphical sessions exist for uid " +
            std::to_string(currentUid) + ": " +
            join_session_ids(graphicalCandidates);
    }
    return false;
}

} // namespace fic::session_agent
