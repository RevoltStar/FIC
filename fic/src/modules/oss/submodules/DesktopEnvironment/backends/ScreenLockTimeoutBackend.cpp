#include "modules/oss/submodules/DesktopEnvironment/backends/ScreenLockTimeoutBackend.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/GnomeBackend.h"
#include "modules/oss/submodules/DesktopEnvironment/backends/KdeBackend.h"
#include "modules/oss/submodules/DesktopEnvironment/backends/XfceBackend.h"

#include <algorithm>
#include <cctype>

std::string ScreenLockTimeoutBackendFactory::normalizeDesktopName(std::string desktop) {
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

std::unique_ptr<ScreenLockTimeoutBackend> ScreenLockTimeoutBackendFactory::create(
    const std::string& desktop
) {
    const std::string normalized = normalizeDesktopName(desktop);
    if (normalized == "GNOME") {
        return std::make_unique<GnomeBackend>();
    }
    if (normalized == "KDE") {
        return std::make_unique<KdeBackend>();
    }
    if (normalized == "XFCE") {
        return std::make_unique<XfceBackend>();
    }
    return nullptr;
}
