#ifndef FIC_PLATFORM_PROFILE_H
#define FIC_PLATFORM_PROFILE_H

#include "platform/PasswordAgingPolicyDefaultsGenerated.h"
#include "platform/SudoSecurePathDefaultGenerated.h"
#include "platform/UserCreationPolicyDefaultsGenerated.h"

#include <filesystem>
#include <optional>
#include <map>
#include <variant>
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
    Gpasswd,
    PamAuthUpdate,
    Dconf,
    Gsettings
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

enum class SshPamServiceRouting {
    Unknown,
    LegacyExecutableName,
    ConfigurablePamServiceName
};

struct SshPlatformConfig {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> serviceUnits;
    std::vector<std::string> socketUnits;
    // Package baseline only; runtime bridge proof probes the trusted sshd.
    SshPamServiceRouting pamServiceRouting = SshPamServiceRouting::Unknown;
};

struct SudoPlatformConfig {
    std::filesystem::path mainConfigPath;
    std::filesystem::path managedConfigPath;
    std::string securePathDefault = FIC_SUDO_SECURE_PATH_DEFAULT;
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

enum class PamTrustedAuthenticationExclusionReason {
    ExplicitSubjectExclusion
};

// A platform-declared authentication gate that only narrows the set of
// subjects allowed to complete a PAM service.  Unlike a trusted bypass it
// never grants authentication by itself.
struct PamTrustedAuthenticationExclusionRule {
    std::string service;
    std::string module;
    PamTrustedAuthenticationExclusionReason reason =
        PamTrustedAuthenticationExclusionReason::ExplicitSubjectExclusion;
    std::string excludedUser;
    std::string control;
    std::vector<std::string> arguments;
    std::optional<std::filesystem::path> source;
    // Optional placement contract used by a policy that manages this rule.
    std::string insertBeforeIncludeTarget;
    // Optional stronger control enforced by the hardening policy. Both the
    // distribution-native control above and this control are understood by
    // the CFG analyzer as the same typed subject exclusion.
    std::string enforcedControl;
};

struct PamTrustedServiceAlias {
    std::filesystem::path aliasPath;
    std::vector<std::filesystem::path> allowedTargets;
};

enum class PamCapability {
    AuthenticationLockout,
    PasswordQuality,
    PasswordHistory,
    IncidentAccessGate
};

enum class PamProviderKind {
    PamFaillock,
    PamTally2,
    PamTally,
    PamPwquality,
    PamPasswdqc,
    PamCracklib,
    PamPwhistory,
    PamUnixHistory,
    FicIncidentAccess
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
    StaticVerifyOnly,
    PamAuthUpdate,
    AltTcbManaged
};

// pam_faillock integration strategies for the AuthenticationLockout
// capability. The strategy selects which control-flow topology FIC builds
// and verifies; it is a persistent policy value, not a runtime toggle.
enum class PamFaillockStrategy {
    PreauthRequisite,
    PreauthRequired,
    Authsucc
};

std::string pamFaillockStrategyName(PamFaillockStrategy strategy);
std::optional<PamFaillockStrategy> parsePamFaillockStrategy(
    const std::string& name);
bool supportsPamFaillockStrategy(
    const struct PamCapabilityConfig& capability,
    PamFaillockStrategy strategy);

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

// Per-strategy activation recipe for topology managers that activate a set
// of platform recipes (pam-auth-update profiles).
struct PamFaillockStrategyActivation {
    PamFaillockStrategy strategy = PamFaillockStrategy::PreauthRequired;
    std::vector<std::string> activationIdentifiers;
};

// Evidence-based support of the FIC-managed pam_pwhistory module
// arguments on this platform (Step 6). A bare option token is rendered
// into the managed history slots and made production-mutable ONLY when
// the platform profile carries this evidence; support is never assumed
// from the writer's rendering ability alone.
struct PamModuleArgumentSupport {
    bool pwhistoryRemember = false;
    bool pwhistoryEnforceForRoot = false;
};

struct PamCapabilityConfig {
    PamCapability capability = PamCapability::AuthenticationLockout;
    PamProviderKind provider = PamProviderKind::PamFaillock;
    PamScope scope = PamScope::EffectiveAuthenticationStack;
    std::filesystem::path configPath;
    PamTopologyStrategyKind topology =
        PamTopologyStrategyKind::StaticVerifyOnly;
    std::filesystem::path topologyTarget;
    std::optional<PamProviderConfigTopology> configTopology;
    PamIdentitySubjectScope subjectScope =
        PamIdentitySubjectScope::AllPamSubjects;
    PamCapabilityConfigurationMode configurationMode =
        PamCapabilityConfigurationMode::ProviderConfigFile;
    std::vector<PamManagedTopologyTarget> managedTopologyTargets;
    std::vector<std::string> activationIdentifiers;
    // pam_faillock strategies this platform supports. Empty means the
    // capability has no strategy-aware integration (fixed topology).
    std::vector<PamFaillockStrategy> supportedFaillockStrategies;
    PamFaillockStrategy defaultFaillockStrategy =
        PamFaillockStrategy::PreauthRequired;
    // Per-strategy activation recipes for topology managers that activate
    // a set of platform recipes (pam-auth-update profiles). Strategies
    // without a recipe cannot be activated on such platforms.
    std::vector<PamFaillockStrategyActivation> strategyActivations;
    // Evidence-based FIC-managed module-argument support of this
    // capability on this platform (Step 6; meaningful for the pwhistory
    // module-arguments capability). Defaults to unsupported: the joint
    // desired-state reader fails closed on configured option values that
    // the platform does not evidence.
    PamModuleArgumentSupport moduleArgumentSupport{};
};

struct PamPlatformConfig {
    struct IncidentAccessGateConfig {
        PamCapability capability = PamCapability::IncidentAccessGate;
        PamProviderKind provider = PamProviderKind::FicIncidentAccess;
        std::vector<std::string> controlledServices;
        std::vector<std::string> trustedLocalRootServices;
        std::string recoveryGroup = "fic";
        std::filesystem::path packageTopologyTarget;
    };
    IncidentAccessGateConfig incidentAccessGate;
    std::vector<std::filesystem::path> configDirectories;
    std::vector<std::filesystem::path> moduleDirectories;
    std::vector<PamScopeConfig> scopes;
    std::vector<PamCapabilityConfig> capabilities;
    std::vector<PamTrustedAuthenticationBypassRule>
        trustedAuthenticationBypasses;
    std::vector<PamTrustedAuthenticationExclusionRule>
        trustedAuthenticationExclusions;
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
        // NSS services whose membership cannot be proven safely by complete
        // enumeration. When one is active, enforcement disables the exact
        // platform-declared PAM bypass rules instead of inspecting members.
        std::vector<std::string> pamBypassNssServices;
    };
    std::optional<PasswordlessLoginControl> passwordlessLoginControl;
    // Joint C2 password topology (quality + history) runtime mutation is
    // VALIDATED on this platform profile: the PamAuthUpdate C2 path passed
    // the real functional gates (executor + policy wiring) on this exact
    // distro. This flag is evidence-based, never set from compile support
    // alone. When false, password quality/history stay PamPolicySupport::
    // ReadOnly on PamAuthUpdate platforms. Quality and history form ONE
    // joint runtime topology domain: the flag is domain-level, not
    // per-capability.
    bool passwordTopologyRuntimeMutable = false;
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

// Native /etc/default/useradd lookup behavior. This remains typed platform
// evidence rather than a parser-side distro switch; every currently supported
// package was probed as exact-key/last-wins.
enum class UseraddDefaultsLookupSemantics {
    ExactKey
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
    UseraddDefaultsLookupSemantics useraddDefaultsLookup =
        UseraddDefaultsLookupSemantics::ExactKey;
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

enum class GrubConfigTopology {
    OwnedDefaultsDropIn,
    SharedDefaultsFile
};

struct GrubPlatformConfig {
    GrubConfigTopology topology = GrubConfigTopology::OwnedDefaultsDropIn;
    std::filesystem::path sharedDefaultsPath;
    std::filesystem::path managedConfigPath;
    std::vector<std::string> rebuildArguments;
    // Validate-only base defaults (Debian/Ubuntu: /etc/default/grub).
    // FIC no longer edits this file under the owned drop-in topology, but
    // update-grub(8) still sources it as root shell code, so every mutation
    // or rebuild of the managed drop-in must first prove it safe. Must stay
    // empty for topologies without base defaults (ALT shared file).
    std::filesystem::path baseDefaultsPath;
};

enum class ManagedFileProvider {
    SystemdResolved,
    NetworkManager,
    Resolvconf
};

// DAC metadata declared by the platform profile for one managed object.
// The profile catalog maps these complete metadata contracts to explicit
// desired-state profiles; disabling the policy never restores either value.
struct FileMetadata {
    std::string owner;
    std::string group;
    mode_t permissions = 0;
};

struct ModeAndOwnerProviderProfileTarget {
    std::filesystem::path path;
    ManagedFileProvider provider;
    // Provider target DAC contract in the same metadata semantics as the
    // Provider-owned targets are always validate-only. The first contract is
    // the verified strict state and the second is the distribution system
    // state used to build explicit profiles.
    FileMetadata strict;
    FileMetadata system;
};

struct ModeAndOwnerPathProfiles {
    std::filesystem::path path;

    FileMetadata strict;
    FileMetadata system;
    // Fail closed when a future catalog entry omits this capability field.
    bool allowMissingVariant = false;

    std::vector<std::filesystem::path> allowedFinalSymlinkTargets;
    std::vector<ModeAndOwnerProviderProfileTarget> providerManagedFinalSymlinkTargets;
};

struct TcbCredentialFileRule {
    std::string name;
    // Verified strict permission set.
    unsigned int permissions = 0;
    // Verified distribution system permission set.
    unsigned int systemPermissions = 0;
    bool required = false;
};

struct TcbCredentialStorageConfig {
    std::filesystem::path rootPath;
    std::string rootOwner;
    std::string rootGroup;
    // Verified strict root-directory metadata.
    unsigned int rootPermissions = 0;
    // Verified distribution system root-directory metadata.
    unsigned int rootSystemPermissions = 0;
    std::string entryGroup;
    // Verified strict per-account entry directory permissions.
    unsigned int entryDirectoryPermissions = 0;
    // Verified distribution system per-account entry directory permissions.
    unsigned int entryDirectorySystemPermissions = 0;
    std::vector<TcbCredentialFileRule> files;
};

struct DacPlatformConfig {
    enum class Profile { System, Minimum, Optimal, Strict };
    enum class PresenceRequirement { MustExist, AllowMissing };
    enum class ObjectType { RegularFile, Directory };
    enum class Remediation { Remediate, ValidateOnly };

    struct ProviderTarget {
        std::filesystem::path path;
        ManagedFileProvider provider;
        FileMetadata metadata;
    };
    struct PathContract {
        FileMetadata metadata;
        ObjectType objectType = ObjectType::RegularFile;
        Remediation remediation = Remediation::Remediate;
        std::vector<std::filesystem::path> allowedFinalSymlinkTargets;
        std::vector<ProviderTarget> providerTargets;
    };
    struct StaticPathObject {
        std::filesystem::path path;
        std::map<Profile, PathContract> profiles;
    };
    struct CollectionMember {
        std::filesystem::path path;
        std::map<Profile, PathContract> profiles;
    };
    struct PathCollectionObject {
        std::vector<CollectionMember> members;
    };
    struct UserHomesObject {
        std::filesystem::path rootPath;
        std::filesystem::path passwdPath = "/etc/passwd";
        std::map<Profile, mode_t> directoryModes;
    };
    struct TcbCredentialTreeObject {
        std::map<Profile, TcbCredentialStorageConfig> profiles;
    };
    struct Object {
        std::string id;
        std::variant<StaticPathObject, PathCollectionObject, UserHomesObject,
                     TcbCredentialTreeObject> target;
        bool allowMissingVariant = false;
    };
    std::vector<Object> modeAndOwnerObjects;
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

// Constructs one logical object directly for the platform catalog. The ID is
// explicit and is never derived from the physical path.
DacPlatformConfig::Object makeModeAndOwnerPathObject(
    std::string id,
    const ModeAndOwnerPathProfiles& profiles);

DacPlatformConfig::Object makeModeAndOwnerTcbObject(
    std::string id,
    const TcbCredentialStorageConfig& profiles);

void appendModeAndOwnerObjects(
    DacPlatformConfig& config,
    const std::vector<ModeAndOwnerPathProfiles>& paths,
    const std::vector<std::string>& pathIds,
    const std::vector<ModeAndOwnerPathProfiles>& commands,
    const std::vector<std::string>& commandIds,
    const std::optional<TcbCredentialStorageConfig>& tcb = std::nullopt);

// Exactly one distribution-specific implementation is selected by CMake.
PlatformProfile makeBuildPlatformProfile();

} // namespace fic::platform

#endif // FIC_PLATFORM_PROFILE_H
