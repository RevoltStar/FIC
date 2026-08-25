#ifndef FIC_PLATFORM_PROFILE_H
#define FIC_PLATFORM_PROFILE_H

#include "platform/PasswordAgingPolicyDefaultsGenerated.h"
#include "platform/UserCreationPolicyDefaultsGenerated.h"

#include <filesystem>
#include <string>
#include <sys/types.h>
#include <vector>

namespace fic::platform {

enum class ExecutableId {
    Sshd,
    Systemctl,
    Loginctl,
    Visudo,
    Lscpu,
    Dmidecode,
    Udevadm,
    UpdateGrub,
    Nft,
    Chage
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

enum class SysctlLoaderKind {
    SystemdSysctl,
    ProcpsSystem
};

struct SysctlPlatformConfig {
    SysctlLoaderKind loader = SysctlLoaderKind::SystemdSysctl;
    std::filesystem::path managedConfigPath = "/etc/sysctl.d/zzzz-fic.conf";
};

enum class PamTrustedAuthenticationBypassReason {
    AlreadyPrivilegedCaller
};

struct PamTrustedAuthenticationBypassRule {
    std::string service;
    std::string module;
    PamTrustedAuthenticationBypassReason reason =
        PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller;
};

struct PamPlatformConfig {
    std::vector<std::filesystem::path> configDirectories;
    std::vector<std::filesystem::path> moduleDirectories;
    std::vector<std::string> authenticationServices;
    std::vector<std::string> passwordServices;
    std::vector<PamTrustedAuthenticationBypassRule>
        trustedAuthenticationBypasses;
    std::filesystem::path faillockConfigPath;
    std::filesystem::path passwordQualityConfigPath;
    std::filesystem::path passwordHistoryConfigPath;
};

enum class LocalShadowKind {
    ShadowFile,
    TcbDirectory
};

struct PasswordAgingPolicyDefaults {
    long minDays = FIC_PASSWORD_AGING_POLICY_MIN_DAYS_DEFAULT;
    long maxDays = FIC_PASSWORD_AGING_POLICY_MAX_DAYS_DEFAULT;
    long warningDays = FIC_PASSWORD_AGING_POLICY_WARNING_DAYS_DEFAULT;
    uid_t uidMin = FIC_PASSWORD_AGING_POLICY_UID_MIN_DEFAULT;
    uid_t uidMax = FIC_PASSWORD_AGING_POLICY_UID_MAX_DEFAULT;
};

struct PasswordAgingMissingKeySemantics {
    long minDays = -1;
    long maxDays = -1;
    long warningDays = -1;
};

struct PasswordAgingPlatformConfig {
    std::filesystem::path loginDefsPath = "/etc/login.defs";
    std::filesystem::path passwdPath = "/etc/passwd";
    std::filesystem::path shadowPath = "/etc/shadow";
    LocalShadowKind shadowKind = LocalShadowKind::ShadowFile;
    std::filesystem::path tcbDirectory = "/etc/tcb";
    PasswordAgingPolicyDefaults policyDefaults;
    PasswordAgingMissingKeySemantics missingKeySemantics;
};

enum class UserCreationProviderKind {
    ShadowUseradd
};

struct UserCreationPolicyDefaults {
    std::string homeBaseDirectory = FIC_USER_CREATION_HOME_BASE_DEFAULT;
    std::string createHome = FIC_USER_CREATION_CREATE_HOME_DEFAULT;
    std::string skeletonDirectory = FIC_USER_CREATION_SKEL_DEFAULT;
    std::string defaultShell = FIC_USER_CREATION_SHELL_DEFAULT;
    std::string createPrivateGroup = FIC_USER_CREATION_PRIVATE_GROUP_DEFAULT;
    std::string defaultPrimaryGroup = FIC_USER_CREATION_PRIMARY_GROUP_DEFAULT;
};

struct UserCreationPlatformConfig {
    UserCreationProviderKind provider = UserCreationProviderKind::ShadowUseradd;
    std::filesystem::path useraddDefaultsPath = "/etc/default/useradd";
    std::filesystem::path loginDefsPath = "/etc/login.defs";
    std::filesystem::path passwdPath = "/etc/passwd";
    std::filesystem::path groupPath = "/etc/group";
    std::filesystem::path shellsPath = "/etc/shells";
    bool requireListedShellWhenShellsFileExists = true;
    UserCreationPolicyDefaults policyDefaults;
};

struct DisplayManagerPlatformConfig {
    std::filesystem::path sddmConfigPath;
    std::filesystem::path lightDmConfigPath;
    std::vector<std::filesystem::path> gdmConfigCandidates;
};

struct GrubPlatformConfig {
    std::filesystem::path defaultsPath;
    std::vector<std::string> rebuildArguments;
};

struct FileAccessRule {
    std::filesystem::path path;
    std::string owner;
    std::string group;
    unsigned int permissions = 0;
    std::vector<std::filesystem::path> allowedFinalSymlinkTargets;
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
    SysctlPlatformConfig sysctl;
    PamPlatformConfig pam;
    PasswordAgingPlatformConfig passwordAging;
    UserCreationPlatformConfig userCreation;
    DisplayManagerPlatformConfig displayManager;
    GrubPlatformConfig grub;
    DacPlatformConfig dac;
};

// Exactly one distribution-specific implementation is selected by CMake.
PlatformProfile makeBuildPlatformProfile();

} // namespace fic::platform

#endif // FIC_PLATFORM_PROFILE_H
