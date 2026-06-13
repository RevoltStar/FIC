#include "session/SessionCommandExecutor.h"

#include <pwd.h>

ProcessResult SessionCommandExecutor::execute(
    const UserSession& session,
    const SessionContext& context,
    const std::string& executable,
    const std::vector<std::string>& arguments
) {
    ProcessResult result;
    const passwd* userInfo = ::getpwuid(session.uid);
    if (userInfo == nullptr || session.user != userInfo->pw_name) {
        result.error = "failed to resolve graphical session user";
        return result;
    }

    const std::string runtimeDirectory = "/run/user/" + std::to_string(session.uid);
    ProcessOptions options;
    options.timeout = std::chrono::seconds(5);
    options.clearEnvironment = true;
    options.uid = session.uid;
    options.gid = userInfo->pw_gid;
    options.user = session.user;
    options.workingDirectory = userInfo->pw_dir;
    options.environment = {
        {"HOME", userInfo->pw_dir},
        {"USER", session.user},
        {"LOGNAME", session.user},
        {"PATH", "/usr/local/bin:/usr/bin:/bin"},
        {"XDG_RUNTIME_DIR", runtimeDirectory},
        {"DBUS_SESSION_BUS_ADDRESS", "unix:path=" + runtimeDirectory + "/bus"},
        {"XDG_SESSION_ID", session.id},
        {"XDG_SESSION_TYPE", session.type},
        {"XDG_CURRENT_DESKTOP", context.desktop}
    };
    if (!context.display.empty()) {
        options.environment.emplace_back("DISPLAY", context.display);
    }
    if (!context.waylandDisplay.empty()) {
        options.environment.emplace_back("WAYLAND_DISPLAY", context.waylandDisplay);
    }

    return ProcessExecutor::execute(executable, arguments, options);
}
