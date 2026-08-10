#include "DeviceEnforcer.h"

#include <fic/core/Logger.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>

namespace fic::device_control {
namespace {

bool writeSysfs(const std::filesystem::path& path,
                const std::string& value,
                std::string& error)
{
    std::ofstream output(path);
    if (!output.is_open()) {
        error = "cannot open " + path.string() + ": " + std::strerror(errno);
        return false;
    }
    output << value;
    if (!output.good()) {
        error = "cannot write " + path.string();
        return false;
    }
    return true;
}

bool writeSysfsWithRetry(const std::filesystem::path& path,
                         const std::string& value,
                         std::string& details)
{
    std::string lastError;
    for (const int delayMs : {0, 100, 250}) {
        if (delayMs > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
        if (writeSysfs(path, value, lastError)) {
            details = "wrote " + value + " to " + path.string();
            return true;
        }
    }
    details = lastError;
    return false;
}

std::optional<std::filesystem::path> findParentFile(const std::string& devpath,
                                                    const std::string& filename)
{
    if (devpath.rfind("/devices/", 0) != 0) {
        return std::nullopt;
    }
    std::filesystem::path current =
        (std::filesystem::path("/sys") / devpath.substr(1)).lexically_normal();
    const std::filesystem::path sysDevices("/sys/devices");
    const auto relative = current.lexically_relative(sysDevices);
    if (relative.empty() || relative.is_absolute() ||
        (!relative.empty() && *relative.begin() == "..")) {
        return std::nullopt;
    }
    while (current != "/sys" && current != "/" && !current.empty()) {
        const std::filesystem::path candidate = current / filename;
        std::error_code error;
        if (std::filesystem::is_regular_file(candidate, error) && !error) {
            return candidate;
        }
        current = current.parent_path();
    }
    return std::nullopt;
}

bool enforceDeny(const std::string& subsystem,
                 const std::string& devpath,
                 std::string& details)
{
    if (subsystem == "usb" || subsystem == "usbmisc") {
        const auto authorized = findParentFile(devpath, "authorized");
        if (!authorized.has_value()) {
            details = "USB authorized sysfs file not found";
            return false;
        }
        if (!writeSysfsWithRetry(authorized.value(), "0", details)) {
            return false;
        }
        details = "USB device deauthorized through " + authorized->string();
        return true;
    }

    if (subsystem == "block") {
        const auto scsiDevice = findParentFile(devpath, "delete");
        if (scsiDevice.has_value() && scsiDevice->parent_path().filename() == "device") {
            return writeSysfsWithRetry(scsiDevice.value(), "1", details);
        }
    }

    if (subsystem == "block" || subsystem == "pci") {
        const auto remove = findParentFile(devpath, "remove");
        if (!remove.has_value()) {
            details = "sysfs remove/delete file not found";
            return false;
        }
        return writeSysfsWithRetry(remove.value(), "1", details);
    }

    details = "unsupported subsystem for deny enforcement: " + subsystem;
    return false;
}

} // namespace

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
    const bool enforced = enforceDeny(subsystem, devpath, details);
    Logger::log("udev deny enforcement for " + std::string(subsystem) + " " + devpath +
                    (enforced ? " succeeded: " : " failed: ") + details,
                enforced ? logLevel::WARN : logLevel::ERROR,
                "devices");
    return enforced ? 0 : 1;
}

} // namespace fic::device_control
