#include "session/SessionLocator.h"

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

bool SessionLocator::activeGraphicalSessions(
    const fic::platform::PlatformExecutableResolver& executables,
    std::vector<UserSession>& sessions,
    std::string& error) {
    sessions.clear();
    std::filesystem::path loginctl;
    if (!executables.resolve(
            fic::platform::ExecutableId::Loginctl, loginctl, error)) {
        error = "loginctl was not found: " + error;
        return false;
    }

    ProcessResult listResult = ProcessExecutor::execute(
        loginctl.string(),
        {"list-sessions", "--no-legend", "--no-pager"}
    );
    if (!listResult.success()) {
        error = "loginctl list-sessions failed: " + listResult.standardError;
        return false;
    }

    std::istringstream lines(listResult.standardOutput);
    std::string line;
    size_t parsedSessionCount = 0;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        // loginctl output is a machine-readable table. Parsing its numeric UID
        // must not depend on the daemon's UI locale (for example ru_RU.UTF-8).
        fields.imbue(std::locale::classic());
        UserSession session;
        unsigned long uid = 0;
        if (!(fields >> session.id >> uid >> session.user) || !valid_session_id(session.id)) {
            continue;
        }
        ++parsedSessionCount;
        session.uid = static_cast<uid_t>(uid);

        ProcessResult showResult = ProcessExecutor::execute(
            loginctl.string(),
            {
                "show-session", session.id,
                "--property=Class",
                "--property=Remote",
                "--property=Type",
                "--no-pager"
            }
        );
        if (!showResult.success()) {
            error = "loginctl show-session failed for session " + session.id + ": " +
                    showResult.standardError;
            return false;
        }

        const auto properties = parse_properties(showResult.standardOutput);
        const auto value = [&properties](const std::string& name) {
            const auto it = properties.find(name);
            return it == properties.end() ? std::string() : it->second;
        };

        session.type = value("Type");
        const bool graphical = session.type == "x11" || session.type == "wayland" || session.type == "mir";
        if (value("Class") == "user" && value("Remote") == "no" && graphical) {
            sessions.push_back(session);
        }
    }

    if (!listResult.standardOutput.empty() && parsedSessionCount == 0) {
        error = "failed to parse loginctl list-sessions output";
        return false;
    }
    return true;
}
