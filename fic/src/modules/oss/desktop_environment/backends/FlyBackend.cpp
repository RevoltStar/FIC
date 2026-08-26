#include "modules/oss/desktop_environment/backends/FlyBackend.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"

#include <cstddef>
#include <fstream>
#include <pwd.h>
#include <vector>

namespace {
constexpr const char* CONFIG_RELATIVE_PATH = "/.fly/theme/current.themerc";
constexpr const char* VARIABLES_GROUP = "[Variables]";

std::string config_path_for(uid_t uid, std::string& error)
{
    const passwd* userInfo = ::getpwuid(uid);
    if (userInfo == nullptr) {
        error = "failed to resolve FLY user home directory";
        return "";
    }
    return std::string(userInfo->pw_dir) + CONFIG_RELATIVE_PATH;
}

std::string trim_copy(const std::string& value)
{
    return desktop_backend::trim(value);
}

bool split_key_value(const std::string& line, std::string& key, std::string& value)
{
    const std::string trimmed = trim_copy(line);
    if (trimmed.empty() || trimmed.front() == ';' || trimmed.front() == '#') {
        return false;
    }

    const size_t separator = trimmed.find('=');
    if (separator == std::string::npos) {
        return false;
    }

    key = trim_copy(trimmed.substr(0, separator));
    value = trim_copy(trimmed.substr(separator + 1));
    return !key.empty();
}

bool read_lines(const std::string& path, std::vector<std::string>& lines, std::string& error)
{
    std::ifstream input(path);
    if (!input.is_open()) {
        error = "failed to open FLY config: " + path;
        return false;
    }

    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    if (input.bad()) {
        error = "failed to read FLY config: " + path;
        return false;
    }
    return true;
}

bool write_lines(const std::string& path, const std::vector<std::string>& lines, std::string& error)
{
    std::ofstream output(path, std::ios::trunc);
    if (!output.is_open()) {
        error = "failed to write FLY config: " + path;
        return false;
    }

    for (const std::string& line : lines) {
        output << line << '\n';
    }
    if (!output.good()) {
        error = "failed to flush FLY config: " + path;
        return false;
    }
    return true;
}

bool update_config_value(
    const std::string& path,
    const std::string& key,
    const std::string& value,
    std::string& error
) {
    std::vector<std::string> lines;
    if (!read_lines(path, lines, error)) {
        return false;
    }

    bool inVariablesGroup = false;
    bool hasVariablesGroup = false;
    size_t insertAfterVariablesGroup = lines.size();
    for (size_t index = 0; index < lines.size(); ++index) {
        std::string& line = lines[index];
        const std::string trimmed = trim_copy(line);
        if (!trimmed.empty() && trimmed.front() == '[' && trimmed.back() == ']') {
            inVariablesGroup = trimmed == VARIABLES_GROUP;
            if (inVariablesGroup) {
                hasVariablesGroup = true;
                insertAfterVariablesGroup = index + 1;
            }
            continue;
        }

        if (!inVariablesGroup) {
            continue;
        }

        std::string lineKey;
        std::string lineValue;
        if (split_key_value(line, lineKey, lineValue) && lineKey == key) {
            line = key + "=" + value;
            return write_lines(path, lines, error);
        }
    }

    const std::string newLine = key + "=" + value;
    if (!hasVariablesGroup) {
        lines.insert(lines.begin(), VARIABLES_GROUP);
        lines.insert(lines.begin() + 1, newLine);
    } else {
        lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(insertAfterVariablesGroup), newLine);
    }
    return write_lines(path, lines, error);
}
} // namespace

FlyBackend::FlyBackend(const UserSession& session, const SessionContext& context)
    : DesktopEnvironmentBackend(session, context),
      session(session)
{
}

bool FlyBackend::setValue(
    const std::string& key,
    const std::string& value,
    std::string& error
) const
{
    const std::string configPath = config_path_for(session.uid, error);
    if (configPath.empty() || !update_config_value(configPath, key, value, error)) {
        return false;
    }

    const std::string flyWmFunc = findExecutable({
        "/usr/bin/fly-wmfunc",
        "/bin/fly-wmfunc"
    });
    if (flyWmFunc.empty()) {
        error = "fly-wmfunc was not found";
        return false;
    }

    std::string output;
    return execute(flyWmFunc, {"FLYWM_UPDATE_VAL", key, value}, output, error);
}

bool FlyBackend::getValue(
    const std::string& key,
    std::string& value,
    std::string& error
) const
{
    const std::string configPath = config_path_for(session.uid, error);
    std::vector<std::string> lines;
    if (configPath.empty() || !read_lines(configPath, lines, error)) {
        return false;
    }

    bool inVariablesGroup = false;
    for (const std::string& line : lines) {
        const std::string trimmed = trim_copy(line);
        if (!trimmed.empty() && trimmed.front() == '[' && trimmed.back() == ']') {
            inVariablesGroup = trimmed == VARIABLES_GROUP;
            continue;
        }

        if (!inVariablesGroup) {
            continue;
        }

        std::string lineKey;
        std::string lineValue;
        if (split_key_value(line, lineKey, lineValue) && lineKey == key) {
            value = lineValue;
            error.clear();
            return true;
        }
    }

    error = "FLY config key was not found: " + key;
    return false;
}
