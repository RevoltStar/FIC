#include "modules/oss/submodules/DesktopEnvironment/backends/DesktopEnvironmentBackend.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/BackendCommand.h"

#include <algorithm>
#include <cctype>

DesktopEnvironmentBackend::DesktopEnvironmentBackend(
    const UserSession& session,
    const SessionContext& context
)
    : session(session), context(context)
{
}

DesktopEnvironmentKind DesktopEnvironmentBackend::kindFromName(const std::string& desktop)
{
    const std::string normalized = normalizeName(desktop);
    if (normalized == "GNOME") {
        return DesktopEnvironmentKind::Gnome;
    }
    if (normalized == "KDE") {
        return DesktopEnvironmentKind::Kde;
    }
    if (normalized == "XFCE") {
        return DesktopEnvironmentKind::Xfce;
    }
    return DesktopEnvironmentKind::Unknown;
}

std::string DesktopEnvironmentBackend::normalizeName(std::string desktop)
{
    std::transform(desktop.begin(), desktop.end(), desktop.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });

    size_t tokenStart = 0;
    while (tokenStart <= desktop.size()) {
        const size_t separator = desktop.find_first_of(":;", tokenStart);
        const size_t tokenEnd = separator == std::string::npos ? desktop.size() : separator;
        std::string token = desktop.substr(tokenStart, tokenEnd - tokenStart);
        const size_t first = token.find_first_not_of(" \t");
        const size_t last = token.find_last_not_of(" \t");
        token = first == std::string::npos ? "" : token.substr(first, last - first + 1);

        if (token == "GNOME" || token == "UNITY" || token == "BUDGIE") {
            return "GNOME";
        }
        if (token == "KDE" || token == "PLASMA") {
            return "KDE";
        }
        if (token == "XFCE" || token == "XFCE4") {
            return "XFCE";
        }

        if (separator == std::string::npos) {
            break;
        }
        tokenStart = separator + 1;
    }
    return desktop;
}

std::string DesktopEnvironmentBackend::findExecutable(const std::vector<std::string>& paths)
{
    return desktop_backend::findExecutable(paths);
}

bool DesktopEnvironmentBackend::execute(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    std::string& output,
    std::string& error
) const
{
    ProcessResult result;
    if (!desktop_backend::execute(session, context, executable, arguments, result, error)) {
        return false;
    }
    output = desktop_backend::trim(result.standardOutput);
    return true;
}
