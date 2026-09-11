#include "session/SessionCommandExecutor.h"
#include "session/SessionCommandExecutorInternal.h"

#include <algorithm>
#include <pwd.h>
#include <set>

ProcessResult SessionCommandExecutor::execute(
    const UserSession& session,
    const SessionContext& context,
    const std::string& executable,
    const std::vector<std::string>& arguments
) {
    return executeWithKdeConfigEnvironment(
        session, context, executable, arguments, {});
}

ProcessResult SessionCommandExecutor::executeWithKdeConfigEnvironment(
    const UserSession& session,
    const SessionContext& context,
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const std::vector<SessionEnvironmentOverride>& environmentOverrides
) {
    ProcessResult result;
    const passwd* userInfo = ::getpwuid(session.uid);
    if (userInfo == nullptr || session.user != userInfo->pw_name) {
        result.error = "failed to resolve graphical session user";
        return result;
    }

    ProcessOptions options = session_command_executor_detail::buildOptions(
        session, context, userInfo->pw_dir, userInfo->pw_gid,
        environmentOverrides, result.error);
    if (!result.error.empty())
        return result;
    return ProcessExecutor::execute(executable, arguments, options);
}

ProcessOptions session_command_executor_detail::buildOptions(
    const UserSession& session,
    const SessionContext& context,
    const std::string& homeDirectory,
    gid_t primaryGroup,
    const std::vector<SessionEnvironmentOverride>& environmentOverrides,
    std::string& error) {
    const std::string runtimeDirectory =
        "/run/user/" + std::to_string(session.uid);
    ProcessOptions options;
    options.timeout = std::chrono::seconds(5);
    options.clearEnvironment = true;
    options.uid = session.uid;
    options.gid = primaryGroup;
    options.user = session.user;
    options.workingDirectory = homeDirectory;
    options.environment = {
        {"HOME", homeDirectory},
        {"USER", session.user},
        {"LOGNAME", session.user},
        {"PATH", "/usr/local/bin:/usr/bin:/bin"},
        {"XDG_RUNTIME_DIR", runtimeDirectory},
        {"DBUS_SESSION_BUS_ADDRESS", "unix:path=" + runtimeDirectory + "/bus"},
        {"XDG_SESSION_ID", session.id},
        {"XDG_SESSION_TYPE", context.sessionType},
        {"XDG_CURRENT_DESKTOP", context.desktop}
    };
    if (!context.display.empty()) {
        options.environment.emplace_back("DISPLAY", context.display);
    }
    if (!context.waylandDisplay.empty()) {
        options.environment.emplace_back("WAYLAND_DISPLAY", context.waylandDisplay);
    }

    static const std::set<std::string> allowedOverrides{
        "HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "KDE_SKIP_KDERC"};
    std::set<std::string> seen;
    for (const auto& override : environmentOverrides) {
        if (allowedOverrides.find(override.name) == allowedOverrides.end() ||
            !seen.insert(override.name).second) {
            error = "unsafe or duplicate session environment override: " +
                override.name;
            return {};
        }
        options.environment.erase(std::remove_if(options.environment.begin(),
            options.environment.end(), [&](const auto& entry) {
                return entry.first == override.name;
            }), options.environment.end());
        if (override.value.has_value())
            options.environment.emplace_back(override.name, *override.value);
    }

    error.clear();
    return options;
}
