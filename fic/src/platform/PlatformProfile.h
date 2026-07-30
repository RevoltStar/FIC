#ifndef FIC_PLATFORM_PROFILE_H
#define FIC_PLATFORM_PROFILE_H

#include <filesystem>
#include <string>
#include <vector>

namespace fic::platform {

enum class ExecutableId {
    Sshd,
    Systemctl,
    Loginctl,
    Visudo,
    Lscpu,
    Dmidecode,
    Udevadm
};

struct PlatformExecutableSpec {
    ExecutableId id;
    std::vector<std::filesystem::path> candidates;
    bool required = true;
};

struct PlatformExecutables {
    std::vector<PlatformExecutableSpec> entries;
};

enum class PackageManagerKind {
    Dpkg,
    Rpm
};

struct PackageManagerPlatformConfig {
    PackageManagerKind kind = PackageManagerKind::Dpkg;
    std::vector<std::filesystem::path> queryCandidates;
};

struct HostCompatibility {
    std::vector<std::string> osIds;
    std::vector<std::string> versionIds;
    std::vector<std::string> altBranchIds;
};

struct SshPlatformConfig {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> serviceUnits;
};

struct SudoPlatformConfig {
    std::filesystem::path mainConfigPath;
    std::filesystem::path managedConfigPath;
};

struct PamPlatformConfig {
    std::vector<std::filesystem::path> configDirectories;
    std::vector<std::filesystem::path> moduleDirectories;
    std::vector<std::string> authenticationServices;
    std::vector<std::string> passwordServices;
    std::filesystem::path faillockConfigPath;
    std::filesystem::path passwordQualityConfigPath;
    std::filesystem::path passwordHistoryConfigPath;
};

struct DisplayManagerPlatformConfig {
    std::filesystem::path sddmConfigPath;
    std::filesystem::path lightDmConfigPath;
    std::vector<std::filesystem::path> gdmConfigCandidates;
};

struct FileAccessRule {
    std::filesystem::path path;
    std::string owner;
    std::string group;
    unsigned int permissions = 0;
};

struct DacPlatformConfig {
    std::vector<FileAccessRule> protectedSystemFiles;
    std::vector<FileAccessRule> protectedSystemCommands;
};

struct PlatformProfile {
    std::string id;
    std::string displayName;
    HostCompatibility hostCompatibility;
    PlatformExecutables executables;
    PackageManagerPlatformConfig packageManager;
    SshPlatformConfig ssh;
    SudoPlatformConfig sudo;
    PamPlatformConfig pam;
    DisplayManagerPlatformConfig displayManager;
    DacPlatformConfig dac;
};

// Exactly one distribution-specific implementation is selected by CMake.
PlatformProfile makeBuildPlatformProfile();

} // namespace fic::platform

#endif // FIC_PLATFORM_PROFILE_H
