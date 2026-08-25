#ifndef FIC_DEVICE_ENFORCER_SYSFS_H
#define FIC_DEVICE_ENFORCER_SYSFS_H

#include <filesystem>
#include <string>

namespace fic::device_control::internal {

struct DeviceEnforcerSysfsOptions {
    std::filesystem::path sysfsRoot = "/sys";
};

bool enforceDenyThroughSysfs(const std::string& subsystem,
                             const std::string& devpath,
                             const DeviceEnforcerSysfsOptions& options,
                             std::string& details);

} // namespace fic::device_control::internal

#endif
