#include "modules/oss/desktop_environment/backends/XfceBackend.h"

#include <utility>
#include <vector>

// Canonical trusted helper path from the public FIC session install layout.
// Never resolved from the session PATH: a session user must not be able to
// substitute the helper executable.
#ifndef FIC_XFCONF_INSPECT_PATH
#error "FIC_XFCONF_INSPECT_PATH must be defined by the build configuration"
#endif

namespace {

XfcePropertyType xfcePropertyTypeFromHelperToken(const std::string& token) {
    if (token == "bool") return XfcePropertyType::Bool;
    if (token == "int") return XfcePropertyType::Int;
    if (token == "uint") return XfcePropertyType::UInt;
    if (token == "double") return XfcePropertyType::Double;
    if (token == "string") return XfcePropertyType::String;
    // Policy-unknown storage types (gint64, aggregates, ...) stay Other and
    // are treated as a type mismatch, never as an expected type.
    return XfcePropertyType::Other;
}

bool parseHelperOutput(
    const std::string& output,
    XfcePropertyState& state,
    std::string& error
) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (true) {
        const std::size_t stop = output.find('\n', start);
        if (stop == std::string::npos) {
            lines.push_back(output.substr(start));
            break;
        }
        lines.push_back(output.substr(start, stop - start));
        start = stop + 1;
    }
    while (!lines.empty() && lines.back().empty()) lines.pop_back();

    if (lines.size() < 2 || lines.size() > 3 ||
        lines[0] != "fic-xfconf-inspect-protocol=1") {
        error = "malformed fic-xfconf-inspect output";
        return false;
    }
    if (lines[1].rfind("type=", 0) != 0 || lines[1].size() == 5) {
        error = "malformed fic-xfconf-inspect type record";
        return false;
    }
    if (lines.size() == 3 && lines[2].rfind("value=", 0) != 0) {
        error = "malformed fic-xfconf-inspect value record";
        return false;
    }

    state.type = xfcePropertyTypeFromHelperToken(lines[1].substr(5));
    state.value = lines.size() == 3 ? lines[2].substr(6) : std::string();
    error.clear();
    return true;
}

} // namespace

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

    // Always a typed mutation: `--create --type` rewrites the storage type of
    // an existing property in place, which is the repair primitive for wrong
    // storage types. A plain `--set` preserves the existing type.
    std::string output;
    return runCommand(
        xfconfQuery,
        {"--channel", channel, "--property", property,
         "--create", "--type", type, "--set", value},
        output,
        error
    );
}

bool XfceBackend::getPropertyState(
    const std::string& channel,
    const std::string& property,
    XfcePropertyState& state,
    std::string& error
) const
{
    const std::string helper = findCommand({FIC_XFCONF_INSPECT_PATH});
    if (helper.empty()) {
        error = "fic-xfconf-inspect helper was not found at "
                FIC_XFCONF_INSPECT_PATH;
        return false;
    }

    std::string output;
    if (!runCommand(
            helper,
            {"--channel", channel, "--property", property},
            output,
            error)) {
        return false;
    }
    return parseHelperOutput(output, state, error);
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
