#ifndef FIC_DEVICE_PATHS_H
#define FIC_DEVICE_PATHS_H

#include <fic/core/FicRuntimePaths.h>
#include <fic/device-db/DB.h>

#include <filesystem>
#include <string>

namespace fic::device_control {

struct DevicePaths {
    std::filesystem::path databaseFile;
    std::filesystem::path databaseLockFile;
    std::filesystem::path lockDebugLogFile;
    std::filesystem::path logDir;

    static DevicePaths fromProductPaths(const fic::core::FicProductPaths& paths);
    bool validate(std::string& error) const;
    DBOptions databaseOptions() const;
};

class DeviceRuntimePaths {
public:
    static bool initialize(DevicePaths paths, std::string& error);
    static const DevicePaths& get();
};

} // namespace fic::device_control

#endif // FIC_DEVICE_PATHS_H
