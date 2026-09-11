#include "modules/oss/desktop_environment/backends/XfceBackend.h"

#include <utility>

XfceBackend::XfceBackend(const UserSession& session,
                         const SessionContext& context)
    : DesktopEnvironmentBackend(session, context)
{
}

XfceBackend::XfceBackend(const UserSession& session,
                         const SessionContext& context,
                         XfceBackendDependencies dependencies)
    : DesktopEnvironmentBackend(session, context),
      dependencies_(std::move(dependencies))
{
}

std::string XfceBackend::findCommand(
    const std::vector<std::string>& paths) const
{
    return dependencies_.findExecutable
        ? dependencies_.findExecutable(paths)
        : findExecutable(paths);
}

bool XfceBackend::runCommand(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    std::string& output,
    std::string& error) const
{
    return dependencies_.execute
        ? dependencies_.execute(executable, arguments, output, error)
        : execute(executable, arguments, output, error);
}

bool XfceBackend::setProperty(
    const std::string& channel,
    const std::string& property,
    const std::string& type,
    const std::string& value,
    std::string& error
) const
{
    const std::string xfconfQuery = findCommand({
        "/usr/bin/xfconf-query", "/bin/xfconf-query"});
    if (xfconfQuery.empty()) {
        error = "xfconf-query was not found";
        return false;
    }

    std::string output;
    if (runCommand(
            xfconfQuery,
            {"--channel", channel, "--property", property, "--set", value},
            output,
            error)) {
        return true;
    }
    return runCommand(
        xfconfQuery,
        {"--channel", channel, "--property", property, "--create", "--type", type, "--set", value},
        output,
        error
    );
}

bool XfceBackend::getProperty(
    const std::string& channel,
    const std::string& property,
    std::string& value,
    std::string& error
) const
{
    const std::string xfconfQuery = findCommand({
        "/usr/bin/xfconf-query", "/bin/xfconf-query"});
    if (xfconfQuery.empty()) {
        error = "xfconf-query was not found";
        return false;
    }
    return runCommand(
        xfconfQuery,
        {"--channel", channel, "--property", property},
        value,
        error
    );
}

bool XfceBackend::screenSaverAvailable(std::string& error) const
{
    const std::string command = findCommand({
        "/usr/bin/xfce4-screensaver-command",
        "/bin/xfce4-screensaver-command"
    });
    if (command.empty()) {
        error = "xfce4-screensaver-command was not found";
        return false;
    }

    std::string output;
    if (!runCommand(command, {"--query"}, output, error)) {
        if (error.empty()) error = "xfce4-screensaver is not running";
        return false;
    }
    error.clear();
    return true;
}
