#include "modules/oss/desktop_environment/backends/FlyBackend.h"

FlyBackend::FlyBackend(const UserSession& session, const SessionContext& context)
    : DesktopEnvironmentBackend(session, context)
{
}

bool FlyBackend::setValue(
    const std::string& key,
    const std::string& value,
    std::string& error
) const
{
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
