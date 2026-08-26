#include "modules/oss/desktop_environment/backends/XfceBackend.h"

namespace {
std::string find_xfconf_query()
{
    return DesktopEnvironmentBackend::findExecutable({
        "/usr/bin/xfconf-query",
        "/bin/xfconf-query"
    });
}
} // namespace

bool XfceBackend::setProperty(
    const std::string& channel,
    const std::string& property,
    const std::string& type,
    const std::string& value,
    std::string& error
) const
{
    const std::string xfconfQuery = find_xfconf_query();
    if (xfconfQuery.empty()) {
        error = "xfconf-query was not found";
        return false;
    }

    std::string output;
    if (execute(
            xfconfQuery,
            {"--channel", channel, "--property", property, "--set", value},
            output,
            error)) {
        return true;
    }
    return execute(
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
    const std::string xfconfQuery = find_xfconf_query();
    if (xfconfQuery.empty()) {
        error = "xfconf-query was not found";
        return false;
    }
    return execute(
        xfconfQuery,
        {"--channel", channel, "--property", property},
        value,
        error
    );
}
