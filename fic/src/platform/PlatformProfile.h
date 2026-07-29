#ifndef FIC_PLATFORM_PROFILE_H
#define FIC_PLATFORM_PROFILE_H

#include <filesystem>
#include <string>
#include <vector>

namespace fic::platform {

struct HostCompatibility {
    std::vector<std::string> osIds;
    std::vector<std::string> versionIds;
    std::vector<std::string> altBranchIds;
};

struct SshPlatformConfig {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> sshdCandidates;
    std::vector<std::string> serviceUnits;
};

struct SystemToolsPlatformConfig {
    std::vector<std::string> systemctlCandidates;
    std::vector<std::string> loginctlCandidates;
};

struct SudoPlatformConfig {
    std::filesystem::path mainConfigPath;
    std::filesystem::path managedConfigPath;
    std::vector<std::string> visudoCandidates;
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
    SystemToolsPlatformConfig systemTools;
    SshPlatformConfig ssh;
    SudoPlatformConfig sudo;
    DisplayManagerPlatformConfig displayManager;
    DacPlatformConfig dac;
};

// Exactly one distribution-specific implementation is selected by CMake.
PlatformProfile makeBuildPlatformProfile();

} // namespace fic::platform

#endif // FIC_PLATFORM_PROFILE_H
