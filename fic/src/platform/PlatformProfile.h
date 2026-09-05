#ifndef FIC_PLATFORM_PROFILE_H
#define FIC_PLATFORM_PROFILE_H

#include "platform/PasswordAgingPolicyDefaultsGenerated.h"
#include "platform/UserCreationPolicyDefaultsGenerated.h"

#include <filesystem>
#include <optional>
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
    Chage,
    Gpasswd
};

struct PlatformExecutableSpec {
    struct ProviderExecutable {
        std::filesystem::path provider;
        std::filesystem::path executable;
    };

    ExecutableId id;
    std::vector<std::filesystem::path> candidates;
    bool required = true;
    std::filesystem::path activeProviderSelector;
    std::vector<ProviderExecutable> providerExecutables;
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
    AlreadyPrivilegedCaller,
    ExplicitPasswordlessLogin
};

struct PamTrustedAuthenticationBypassRule {
    std::string service;
    std::string module;
    PamTrustedAuthenticationBypassReason reason =
        PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller;
    std::string control;
    std::vector<std::string> arguments;
    std::optional<std::filesystem::path> source;
};

struct PamTrustedServiceAlias {
    std::filesystem::path aliasPath;
    std::vector<std::filesystem::path> allowedTargets;
};

enum class PamCapability {
    AuthenticationLockout,
    PasswordQuality,
    PasswordHistory
};

enum class PamProviderKind {
    PamFaillock,
    PamTally2,
    PamTally,
    PamPwquality,
    PamPasswdqc,
    PamCracklib,
    PamPwhistory,
    PamUnixHistory
};

enum class PamScope {
    EffectiveAuthenticationStack,
    EffectivePasswordStack,
    LocalPasswordChange
};

enum class PamConfigGrammar {
    KeyValue,
    Passwdqc
};

enum class PamTopologyStrategyKind {
    StaticReadOnly,
    ExternalOptIn,
    AltTcbManaged
};

enum class PamConfigPrecedence {
    DropInsThenPrimary
};

enum class PamExplicitConfigSemantics {
    Unsupported,
    ReplacesNativeTopology
};

enum class PamIdentitySubjectScope {
    AllPamSubjects,
    LocalUsersOnly
};

struct PamProviderConfigTopology {
    std::optional<std::filesystem::path> primaryPath;
    std::vector<std::filesystem::path> fallbackPaths;
    std::vector<std::filesystem::path> dropInDirectories;
    PamConfigPrecedence precedence = PamConfigPrecedence::DropInsThenPrimary;
    bool primaryOptionalIfMissing = true;
    PamExplicitConfigSemantics explicitConfig =
        PamExplicitConfigSemantics::Unsupported;
};

enum class PamPolicyFeature {
    PasswordMinLength,
    PasswordMinClasses,
    PasswordCheckUsername,
    PasswordCheckGecos,
    PasswordQualityEnforceForRoot,
    PasswordMinChangedCharacters,
    PasswordMinLowercase,
    PasswordMinUppercase,
    PasswordMinDigits,
    PasswordMinOther,
    PasswdqcStrengthThresholds,
    PasswdqcPassphraseWords,
    PasswdqcMatchLength,
    PasswdqcSimilarPassword,
    PasswdqcRetryCount,
    PasswordHistoryDepth,
    PasswordHistoryEnforceForRoot,
    FailedAuthenticationAttempts,
    FailedAuthenticationCountingPeriod,
    FailedAuthenticationEnforceForRoot,
    FailedAuthenticationUnlockTime
};

enum class PamPolicySupport {
    Unsupported,
    Supported,
    RequiresTopologyActivation,
    ReadOnly
};

struct PamScopeConfig {
    PamScope scope = PamScope::EffectiveAuthenticationStack;
    std::vector<std::string> services;
};

enum class PamCapabilityConfigurationMode {
    ProviderConfigFile,
    ModuleArguments
};

enum class PamManagedTopologyTargetRole {
    Authentication,
    AuthenticationAndAccount
};

struct PamManagedTopologyTarget {
    std::filesystem::path path;
    PamManagedTopologyTargetRole role =
        PamManagedTopologyTargetRole::Authentication;
};

struct PamCapabilityConfig {
    PamCapability capability = PamCapability::AuthenticationLockout;
    PamProviderKind provider = PamProviderKind::PamFaillock;
    PamScope scope = PamScope::EffectiveAuthenticationStack;
    std::filesystem::path configPath;
    PamTopologyStrategyKind topology = PamTopologyStrategyKind::StaticReadOnly;
    std::filesystem::path topologyTarget;
    std::optional<PamProviderConfigTopology> configTopology;
    PamIdentitySubjectScope subjectScope =
        PamIdentitySubjectScope::AllPamSubjects;
    PamCapabilityConfigurationMode configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    std::vector<PamManagedTopologyTarget> managedTopologyTargets;
};

struct PamPlatformConfig {
    std::vector<std::filesystem::path> configDirectories;
    std::vector<std::filesystem::path> moduleDirectories;
    std::vector<PamScopeConfig> scopes;
    std::vector<PamCapabilityConfig> capabilities;
    std::vector<PamTrustedAuthenticationBypassRule>
        trustedAuthenticationBypasses;
    std::vector<PamTrustedServiceAlias> trustedServiceAliases;
    struct PasswordlessLoginControl {
        struct NssServiceContract {
            std::vector<std::vector<std::string>> passwd;
            std::vector<std::vector<std::string>> group;
            std::vector<std::vector<std::string>> initgroups;
        };

        std::string groupName;
        std::filesystem::path passwdPath;
        std::filesystem::path groupPath;
        std::filesystem::path nsswitchPath;
        NssServiceContract supportedNss;
    };
    std::optional<PasswordlessLoginControl> passwordlessLoginControl;
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

enum class UserSupplementaryGroupsProviderKind {
    ShadowUseraddDefaults,
    DebianAdduser,
    Unsupported
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
    UserSupplementaryGroupsProviderKind supplementaryGroupsProvider =
        UserSupplementaryGroupsProviderKind::ShadowUseraddDefaults;
    std::filesystem::path useraddDefaultsPath = "/etc/default/useradd";
    std::filesystem::path adduserConfigPath = "/etc/adduser.conf";
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

enum class ManagedFileProvider {
    SystemdResolved,
    NetworkManager,
    Resolvconf
};

struct ProviderManagedFileTarget {
    std::filesystem::path path;
    ManagedFileProvider provider;
};

struct FileAccessRule {
    std::filesystem::path path;
    std::string owner;
    std::string group;
    unsigned int permissions = 0;
    std::vector<std::filesystem::path> allowedFinalSymlinkTargets;
    std::vector<ProviderManagedFileTarget> providerManagedFinalSymlinkTargets;
};

struct TcbCredentialFileRule {
    std::string name;
    unsigned int permissions = 0;
    bool required = false;
};

struct TcbCredentialStorageConfig {
    std::filesystem::path rootPath;
    std::string rootOwner;
    std::string rootGroup;
    unsigned int rootPermissions = 0;
    std::string entryGroup;
    unsigned int entryDirectoryPermissions = 0;
    std::vector<TcbCredentialFileRule> files;
};

struct DacPlatformConfig {
    std::vector<FileAccessRule> protectedSystemFiles;
    std::vector<FileAccessRule> protectedSystemCommands;
    std::optional<TcbCredentialStorageConfig> tcbCredentialStorage;
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
