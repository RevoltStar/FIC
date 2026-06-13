#include "modules/oss/submodules/DesktopEnvironment/backends/BackendCommand.h"

#include "session/SessionCommandExecutor.h"

#include <algorithm>
#include <cctype>
#include <unistd.h>

namespace desktop_backend {

std::string findExecutable(const std::vector<std::string>& paths) {
    for (const std::string& path : paths) {
        if (::access(path.c_str(), X_OK) == 0) {
            return path;
        }
    }
    return "";
}

bool execute(
    const UserSession& session,
    const SessionContext& context,
    const std::string& executable,
    const std::vector<std::string>& arguments,
    ProcessResult& result,
    std::string& error
) {
    result = SessionCommandExecutor::execute(session, context, executable, arguments);
    if (result.success()) {
        error.clear();
        return true;
    }

    if (!result.error.empty()) {
        error = result.error;
    } else if (result.timedOut) {
        error = "command timed out";
    } else if (result.started) {
        error = "command exited with code " + std::to_string(result.exitCode);
    } else {
        error = "command failed to start";
    }
    if (!result.standardError.empty()) {
        error += ": " + trim(result.standardError);
    }
    return false;
}

std::string trim(std::string value) {
    const auto notSpace = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

std::optional<int> parseInteger(const std::string& value) {
    const size_t firstDigit = value.find_first_of("0123456789");
    if (firstDigit == std::string::npos) {
        return std::nullopt;
    }
    const size_t afterDigits = value.find_first_not_of("0123456789", firstDigit);
    try {
        return std::stoi(value.substr(firstDigit, afterDigits - firstDigit));
    } catch (...) {
        return std::nullopt;
    }
}

bool parseBoolean(const std::string& value, bool& result) {
    std::string normalized = trim(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (normalized == "true" || normalized == "1") {
        result = true;
        return true;
    }
    if (normalized == "false" || normalized == "0") {
        result = false;
        return true;
    }
    return false;
}

} // namespace desktop_backend
