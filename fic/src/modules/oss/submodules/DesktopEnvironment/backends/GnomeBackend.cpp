#include "modules/oss/submodules/DesktopEnvironment/backends/GnomeBackend.h"

namespace {
std::string find_gsettings()
{
    return DesktopEnvironmentBackend::findExecutable({
        "/usr/bin/gsettings",
        "/bin/gsettings"
    });
}
} // namespace

bool GnomeBackend::setSetting(
    const std::string& schema,
    const std::string& key,
    const std::string& value,
    std::string& error
) const
{
    const std::string gsettings = find_gsettings();
    if (gsettings.empty()) {
        error = "gsettings was not found";
        return false;
    }
    std::string output;
    return execute(gsettings, {"set", schema, key, value}, output, error);
}

bool GnomeBackend::getSetting(
    const std::string& schema,
    const std::string& key,
    std::string& value,
    std::string& error
) const
{
    const std::string gsettings = find_gsettings();
    if (gsettings.empty()) {
        error = "gsettings was not found";
        return false;
    }
    return execute(gsettings, {"get", schema, key}, value, error);
}
