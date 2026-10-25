#pragma once
#include <fic/core/fs/SecureStateFile.h>
#include <filesystem>
#include <optional>

namespace fic::core {
// Shared read-only admission for the daemon and auxiliary writers. Only the
// admitted installer/uninstaller publishes this file; absence never means ready.
inline constexpr const char* PACKAGE_STATE_FILE = "/var/lib/fic-lifecycle/status";
enum class PackageState { Installing, Installed, Uninstalling, Removed };
const char* packageStateName(PackageState);
struct PackageStateSnapshot {
    SecureStateReadResult file;
    std::optional<PackageState> state;
};
PackageStateSnapshot readPackageState(const std::filesystem::path& = PACKAGE_STATE_FILE);
bool requireInstalledPackage(std::string& error,
    const std::filesystem::path& = PACKAGE_STATE_FILE);
}
