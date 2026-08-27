#include "modules/oss/desktop_environment/backends/GnomeBackend.h"
#include "modules/oss/desktop_environment/backends/GSettingsValueParser.h"

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

bool GnomeBackend::getUInt32Setting(
    const std::string& schema,
    const std::string& key,
    std::uint32_t& value,
    std::string& error
) const
{
    std::string encoded;
    if (!getSetting(schema, key, encoded, error)) {
        return false;
    }

    const auto parsed = gnome_backend::parseGSettingsUInt32(encoded);
    if (!parsed.has_value()) {
        error = "could not parse GNOME " + key + " value: " + encoded;
        return false;
    }
    value = parsed.value();
    error.clear();
    return true;
}
