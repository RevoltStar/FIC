#include "DeviceEnforcer.h"
#include "DeviceEnforcerSysfs.h"

#include <fic/core/Logger.h>

#include <cstdlib>
#include <string>

namespace fic::device_control {

int enforce_udev_device()
{
    const char* action = std::getenv("ACTION");
    const char* subsystem = std::getenv("SUBSYSTEM");
    const char* devpath = std::getenv("DEVPATH");
    const char* level = std::getenv("FIC_CONNECTION_LEVEL");
    if (action == nullptr || subsystem == nullptr || devpath == nullptr || level == nullptr ||
        std::string(level) != "DENY" ||
        (std::string(action) != "add" && std::string(action) != "change")) {
        Logger::log("invalid udev enforcement environment", logLevel::ERROR, "devices");
        return 1;
    }

    std::string details;
    const bool enforced = internal::enforceDenyThroughSysfs(
        subsystem, devpath, internal::DeviceEnforcerSysfsOptions{}, details);
    Logger::log("udev deny enforcement for " + std::string(subsystem) + " " + devpath +
                    (enforced ? " succeeded: " : " failed: ") + details,
                enforced ? logLevel::INFO : logLevel::ERROR,
                "devices");
    return enforced ? 0 : 1;
}

} // namespace fic::device_control
