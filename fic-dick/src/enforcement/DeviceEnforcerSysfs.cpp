#include "DeviceEnforcerSysfs.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <optional>
#include <thread>

namespace fic::device_control::internal {
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

bool isWithin(const std::filesystem::path& path,
              const std::filesystem::path& root)
{
    const std::filesystem::path relative = path.lexically_relative(root);
    if (relative.empty() || relative.is_absolute()) {
        return false;
    }
    for (const auto& component : relative) {
        if (component == "..") {
            return false;
        }
    }
    return true;
}

std::optional<std::filesystem::path> deviceSysfsPath(
    const std::string& devpath,
    const DeviceEnforcerSysfsOptions& options)
{
    if (devpath.rfind("/devices/", 0) != 0 ||
        options.sysfsRoot.empty() ||
        !options.sysfsRoot.is_absolute()) {
        return std::nullopt;
    }

    const std::filesystem::path sysfsRoot = options.sysfsRoot.lexically_normal();
    const std::filesystem::path sysDevices = sysfsRoot / "devices";
    const std::filesystem::path devicePath =
        (sysfsRoot / devpath.substr(1)).lexically_normal();
    if (!isWithin(devicePath, sysDevices)) {
        return std::nullopt;
    }
    return devicePath;
}

bool sysfsSubsystemMatches(const std::filesystem::path& devicePath,
                           const std::string& expectedSubsystem,
                           const DeviceEnforcerSysfsOptions& options)
{
    std::error_code error;
    const std::filesystem::path subsystemLink = devicePath / "subsystem";
    if (!std::filesystem::is_symlink(subsystemLink, error) || error) {
        return false;
    }

    const std::filesystem::path actual =
        std::filesystem::canonical(subsystemLink, error);
    if (error) {
        return false;
    }
    const std::filesystem::path expected = std::filesystem::canonical(
        options.sysfsRoot / "bus" / expectedSubsystem, error);
    return !error && actual == expected;
}

template <typename Predicate>
std::optional<std::filesystem::path> findAncestorFile(
    const std::string& devpath,
    const std::string& filename,
    const DeviceEnforcerSysfsOptions& options,
    Predicate acceptParent)
{
    const auto devicePath = deviceSysfsPath(devpath, options);
    if (!devicePath.has_value()) {
        return std::nullopt;
    }

    const std::filesystem::path sysDevices =
        options.sysfsRoot.lexically_normal() / "devices";
    std::filesystem::path current = devicePath.value();
    while (isWithin(current, sysDevices)) {
        const std::filesystem::path candidate = current / filename;
        std::error_code error;
        if (std::filesystem::is_regular_file(candidate, error) && !error &&
            acceptParent(current)) {
            return candidate;
        }
        if (current == sysDevices) {
            break;
        }
        current = current.parent_path();
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> findUsbAuthorizationTarget(
    const std::string& devpath,
    const DeviceEnforcerSysfsOptions& options)
{
    return findAncestorFile(devpath, "authorized", options,
                            [](const std::filesystem::path&) { return true; });
}

std::optional<std::filesystem::path> findScsiDeleteTarget(
    const std::string& devpath,
    const DeviceEnforcerSysfsOptions& options)
{
    return findAncestorFile(
        devpath, "delete", options,
        [&options](const std::filesystem::path& parent) {
            return sysfsSubsystemMatches(parent, "scsi", options);
        });
}

std::optional<std::filesystem::path> findPciRemoveTarget(
    const std::string& devpath,
    const DeviceEnforcerSysfsOptions& options)
{
    const auto devicePath = deviceSysfsPath(devpath, options);
    if (!devicePath.has_value() ||
        !sysfsSubsystemMatches(devicePath.value(), "pci", options)) {
        return std::nullopt;
    }

    const std::filesystem::path candidate = devicePath.value() / "remove";
    std::error_code error;
    if (!std::filesystem::is_regular_file(candidate, error) || error) {
        return std::nullopt;
    }
    return candidate;
}

} // namespace

bool enforceDenyThroughSysfs(const std::string& subsystem,
                             const std::string& devpath,
                             const DeviceEnforcerSysfsOptions& options,
                             std::string& details)
{
    if (subsystem == "usb" || subsystem == "usbmisc") {
        const auto authorized = findUsbAuthorizationTarget(devpath, options);
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
        const auto scsiDelete = findScsiDeleteTarget(devpath, options);
        if (!scsiDelete.has_value()) {
            details = "safe SCSI delete target not found for block device; "
                      "PCI remove fallback is prohibited";
            return false;
        }
        if (!writeSysfsWithRetry(scsiDelete.value(), "1", details)) {
            return false;
        }
        details = "SCSI block device deleted through " + scsiDelete->string();
        return true;
    }

    if (subsystem == "pci") {
        const auto remove = findPciRemoveTarget(devpath, options);
        if (!remove.has_value()) {
            details = "PCI remove sysfs target not found";
            return false;
        }
        if (!writeSysfsWithRetry(remove.value(), "1", details)) {
            return false;
        }
        details = "PCI device removed through " + remove->string();
        return true;
    }

    details = "unsupported subsystem for deny enforcement: " + subsystem;
    return false;
}

} // namespace fic::device_control::internal
