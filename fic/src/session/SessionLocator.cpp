#include "session/SessionLocator.h"
#include "session/SessionAgentClient.h"
#include "session/SessionAgentClientInternal.h"
#include "session/SessionSelection.h"

#include <fic/core/process/ProcessExecutor.h>

#include <cctype>
#include <locale>
#include <sstream>
#include <unordered_map>

namespace {
bool valid_session_id(const std::string& id) {
    if (id.empty()) {
        return false;
    }
    for (const unsigned char ch : id) {
        if (!std::isalnum(ch) && ch != '_' && ch != '-') {
            return false;
        }
    }
    return true;
}

std::unordered_map<std::string, std::string> parse_properties(const std::string& text) {
    std::unordered_map<std::string, std::string> properties;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        const size_t separator = line.find('=');
        if (separator != std::string::npos) {
            properties[line.substr(0, separator)] = line.substr(separator + 1);
        }
    }
    return properties;
}
} // namespace

namespace {

enum class SelectionMode {
    ActiveGraphical,
    KdeMediaControls
};

bool agent_endpoint_present(const UserSession& session)
{
    return session_agent_client_detail::safeEndpointPresent(
        SessionAgentClient::socketPath(session), session.uid);
}

bool enumerate_sessions(
    const fic::platform::PlatformExecutableResolver& executables,
    SelectionMode mode,
    std::vector<UserSession>& sessions,
    std::string& error)
{
    sessions.clear();
    std::filesystem::path loginctl;
    if (!executables.resolve(
            fic::platform::ExecutableId::Loginctl, loginctl, error)) {
        error = "loginctl was not found: " + error;
        return false;
    }

    ProcessResult listResult = ProcessExecutor::execute(
        loginctl.string(), {"list-sessions", "--no-legend", "--no-pager"});
    if (!listResult.success()) {
        error = "loginctl list-sessions failed: " + listResult.standardError;
        return false;
    }

    std::istringstream lines(listResult.standardOutput);
    std::string line;
    size_t parsedSessionCount = 0;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        fields.imbue(std::locale::classic());
        SessionProperties properties;
        unsigned long uid = 0;
        if (!(fields >> properties.session.id >> uid >> properties.session.user) ||
            !valid_session_id(properties.session.id)) {
            continue;
        }
        ++parsedSessionCount;
        properties.session.uid = static_cast<uid_t>(uid);

        std::vector<std::string> showArguments{
            "show-session", properties.session.id,
            "--property=Class",
            "--property=Remote"
        };
        if (mode == SelectionMode::KdeMediaControls) {
            showArguments.push_back("--property=State");
        }
        showArguments.insert(
            showArguments.end(), {"--property=Type", "--no-pager"});
        ProcessResult showResult = ProcessExecutor::execute(
            loginctl.string(), showArguments);
        if (!showResult.success()) {
            error = "loginctl show-session failed for session " +
                properties.session.id + ": " + showResult.standardError;
            return false;
        }

        const auto values = parse_properties(showResult.standardOutput);
        const auto value = [&values](const std::string& name) {
            const auto it = values.find(name);
            return it == values.end() ? std::string() : it->second;
        };
        properties.session.type = value("Type");
        properties.sessionClass = value("Class");
        properties.state = value("State");
        properties.remote = value("Remote") == "yes";

        const bool agentEndpointPresent =
            mode == SelectionMode::KdeMediaControls &&
            properties.session.type == "tty" &&
            agent_endpoint_present(properties.session);
        const bool selected = mode == SelectionMode::ActiveGraphical
            ? session_selection::activeGraphicalSession(properties)
            : session_selection::kdeMediaControlsCandidate(
                properties, agentEndpointPresent);
        if (selected) {
            sessions.push_back(properties.session);
        }
    }

    if (!listResult.standardOutput.empty() && parsedSessionCount == 0) {
        error = "failed to parse loginctl list-sessions output";
        return false;
    }
    return true;
}

} // namespace

bool SessionLocator::activeGraphicalSessions(
    const fic::platform::PlatformExecutableResolver& executables,
    std::vector<UserSession>& sessions,
    std::string& error) {
    return enumerate_sessions(
        executables, SelectionMode::ActiveGraphical, sessions, error);
}

bool SessionLocator::kdeMediaControlsCandidates(
    const fic::platform::PlatformExecutableResolver& executables,
    std::vector<UserSession>& sessions,
    std::string& error)
{
    return enumerate_sessions(
        executables, SelectionMode::KdeMediaControls, sessions, error);
}
