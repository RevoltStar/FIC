#include "DevicePaths.h"

#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace fic::device_control {
namespace {
std::mutex devicePathsMutex;
std::unique_ptr<const DevicePaths> devicePaths;

bool validAbsolutePath(const std::filesystem::path& path) {
    if (path.empty() || !path.is_absolute() || path.lexically_normal() != path) {
        return false;
    }
    for (const auto& part : path) {
        if (part == "..") {
            return false;
        }
    }
    return true;
}
} // namespace

DevicePaths DevicePaths::fromProductPaths(const fic::core::FicProductPaths& paths) {
    return {
        paths.deviceDatabaseFile,
        paths.deviceDatabaseLockFile,
        paths.lockDebugLogFile,
        paths.logDir,
        paths.stateDir
    };
}

bool DevicePaths::validate(std::string& error) const {
    if (!validAbsolutePath(databaseFile) ||
        !validAbsolutePath(databaseLockFile) ||
        !validAbsolutePath(lockDebugLogFile) ||
        !validAbsolutePath(logDir) ||
        !validAbsolutePath(stateDir)) {
        error = "device paths must be absolute and lexically normalized";
        return false;
    }
    if (databaseFile == databaseLockFile) {
        error = "device database and lock files must be different";
        return false;
    }
    return true;
}

DBOptions DevicePaths::databaseOptions() const {
    return {databaseFile, databaseLockFile, lockDebugLogFile, true};
}

bool DeviceRuntimePaths::initialize(DevicePaths paths, std::string& error) {
    if (!paths.validate(error)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(devicePathsMutex);
    if (devicePaths != nullptr) {
        error = "device runtime paths have already been initialized";
        return false;
    }
    devicePaths = std::make_unique<const DevicePaths>(std::move(paths));
    return true;
}

const DevicePaths& DeviceRuntimePaths::get() {
    std::lock_guard<std::mutex> lock(devicePathsMutex);
    if (devicePaths == nullptr) {
        throw std::logic_error("device runtime paths have not been initialized");
    }
    return *devicePaths;
}

} // namespace fic::device_control
