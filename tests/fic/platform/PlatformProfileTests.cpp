#include "platform/PlatformCompatibility.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

const fic::platform::PamScopeConfig& pamScope(
    const fic::platform::PamPlatformConfig& pam,
    fic::platform::PamScope scope) {
    const auto found = std::find_if(
        pam.scopes.begin(), pam.scopes.end(),
        [scope](const auto& candidate) { return candidate.scope == scope; });
    require(found != pam.scopes.end(), "required PAM scope is missing");
    return *found;
}

fic::platform::PamScopeConfig& pamScope(
    fic::platform::PamPlatformConfig& pam,
    fic::platform::PamScope scope) {
    return const_cast<fic::platform::PamScopeConfig&>(
        pamScope(std::as_const(pam), scope));
}

const fic::platform::PamCapabilityConfig* pamCapability(
    const fic::platform::PamPlatformConfig& pam,
    fic::platform::PamCapability capability) {
    const auto found = std::find_if(
        pam.capabilities.begin(), pam.capabilities.end(),
        [capability](const auto& candidate) {
            return candidate.capability == capability;
        });
    return found == pam.capabilities.end() ? nullptr : &*found;
}

fic::platform::PamCapabilityConfig* pamCapability(
    fic::platform::PamPlatformConfig& pam,
    fic::platform::PamCapability capability) {
    return const_cast<fic::platform::PamCapabilityConfig*>(
        pamCapability(std::as_const(pam), capability));
}

class TemporaryOsRelease {
public:
    TemporaryOsRelease() {
        char pattern[] = "/tmp/fic-platform-os-release-XXXXXX";
        const int descriptor = ::mkstemp(pattern);
        if (descriptor < 0) {
            throw std::runtime_error("cannot create temporary os-release");
        }
        ::close(descriptor);
        path = pattern;
    }

    ~TemporaryOsRelease() {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    std::filesystem::path path;
};

fic::platform::OsReleaseValues compatibleValues(
    const fic::platform::PlatformProfile& profile) {
    fic::platform::OsReleaseValues values;
    values["ID"] = profile.hostCompatibility.osIds.front();
    if (!profile.hostCompatibility.versionIds.empty()) {
        values["VERSION_ID"] = profile.hostCompatibility.versionIds.front();
    }
    if (!profile.hostCompatibility.altBranchIds.empty()) {
        values["ALT_BRANCH_ID"] = profile.hostCompatibility.altBranchIds.front();
    }
    return values;
}

std::vector<fic::platform::ModeAndOwnerPathProfiles> catalogRules(
    const fic::platform::DacPlatformConfig& dac, bool commands) {
    using Dac = fic::platform::DacPlatformConfig;
    std::vector<fic::platform::ModeAndOwnerPathProfiles> result;
    for (const auto& object : dac.modeAndOwnerObjects) {
        const auto* path = std::get_if<Dac::StaticPathObject>(&object.target);
        if (!path) continue;
        const auto system = path->profiles.find(Dac::Profile::System);
        if (system == path->profiles.end()) continue;
        const bool isCommand = object.id == "df" || object.id == "chattr" ||
            object.id == "arp" || object.id == "ip";
        if (isCommand != commands) continue;
        const auto strict = path->profiles.find(Dac::Profile::Strict);
        fic::platform::ModeAndOwnerPathProfiles rule;
        rule.path = path->path;
        rule.system = system->second.metadata;
        rule.strict = strict == path->profiles.end()
            ? rule.system : strict->second.metadata;
        rule.allowMissingVariant = object.allowMissingVariant;
        rule.allowedFinalSymlinkTargets =
            system->second.allowedFinalSymlinkTargets;
        for (const auto& provider : system->second.providerTargets) {
            fic::platform::ModeAndOwnerProviderProfileTarget converted{
                provider.path, provider.provider, provider.metadata,
                provider.metadata};
            if (strict != path->profiles.end()) {
                const auto strictProvider = std::find_if(
                    strict->second.providerTargets.begin(),
                    strict->second.providerTargets.end(),
                    [&](const auto& candidate) {
                        return candidate.path == provider.path;
                    });
                if (strictProvider != strict->second.providerTargets.end()) {
                    converted.strict = strictProvider->metadata;
                }
            }
            rule.providerManagedFinalSymlinkTargets.push_back(
                std::move(converted));
        }
        result.push_back(std::move(rule));
    }
    return result;
}

const fic::platform::DacPlatformConfig::TcbCredentialTreeObject* tcbObject(
    const fic::platform::DacPlatformConfig& dac) {
    for (const auto& object : dac.modeAndOwnerObjects) {
        if (object.id == "tcb_credentials") {
            return std::get_if<
                fic::platform::DacPlatformConfig::TcbCredentialTreeObject>(
                    &object.target);
        }
    }
    return nullptr;
}

fic::platform::DacPlatformConfig::PathContract& firstPathContract(
    fic::platform::PlatformProfile& profile) {
    auto& object = profile.dac.modeAndOwnerObjects.front();
    auto& path = std::get<fic::platform::DacPlatformConfig::StaticPathObject>(
        object.target);
    return path.profiles.at(
        fic::platform::DacPlatformConfig::Profile::System);
}

bool hasRule(const std::vector<fic::platform::ModeAndOwnerPathProfiles>& rules,
             std::filesystem::path path) {
    return std::any_of(
        rules.begin(), rules.end(),
        [&path](const fic::platform::ModeAndOwnerPathProfiles& rule) {
            return rule.path == path;
        });
}

fic::platform::ModeAndOwnerPathProfiles findRule(
    const std::vector<fic::platform::ModeAndOwnerPathProfiles>& rules,
    std::filesystem::path path) {
    const auto found = std::find_if(
        rules.begin(), rules.end(),
        [&path](const fic::platform::ModeAndOwnerPathProfiles& rule) {
            return rule.path == path;
        });
    if (found == rules.end()) {
        throw std::runtime_error("missing file access rule: " + path.string());
    }
    return *found;
}

const fic::platform::PlatformExecutableSpec& executableSpec(
    const fic::platform::PlatformProfile& profile,
    fic::platform::ExecutableId id) {
    const auto* spec =
        fic::platform::findExecutableSpec(profile.executables, id);
    if (spec == nullptr) {
        throw std::runtime_error(
            std::string("missing executable spec: ") +
            fic::platform::executableIdName(id));
    }
    return *spec;
}

fic::platform::PlatformExecutableSpec& executableSpec(
    fic::platform::PlatformProfile& profile,
    fic::platform::ExecutableId id) {
    for (auto& spec : profile.executables.entries) {
        if (spec.id == id) {
            return spec;
        }
    }
    throw std::runtime_error(
        std::string("missing executable spec: ") +
        fic::platform::executableIdName(id));
}

void testSelectedProfile() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    std::string error;
    require(fic::platform::validatePlatformProfile(profile, error), error);
    require(profile.sudo.mainConfigPath == "/etc/sudoers",
            "sudoers main configuration path is incorrect");
    require(profile.sudo.managedConfigPath == "/etc/sudoers.d/zzzz-fic",
            "managed sudoers path is incorrect");
    require(profile.sysctl.loader == fic::platform::SysctlLoaderKind::SystemdSysctl,
            "SYSCTL loader kind is incorrect");
    require(profile.sysctl.managedConfigPath == "/etc/sysctl.d/zzzz-fic.conf",
            "managed sysctl path is incorrect");
    const std::vector<std::filesystem::path> expectedVisudoCandidates =
        profile.id == "ubuntu-26.04"
        ? std::vector<std::filesystem::path>{
              "/usr/lib/cargo/bin/visudo", "/usr/sbin/visudo.ws"}
        : std::vector<std::filesystem::path>{"/usr/sbin/visudo"};
    const auto& visudoSpec = executableSpec(
        profile, fic::platform::ExecutableId::Visudo);
    require(visudoSpec.candidates ==
                expectedVisudoCandidates,
            "visudo candidates are incorrect");
    if (profile.id == "ubuntu-26.04") {
        require(visudoSpec.activeProviderSelector == "/usr/bin/sudo",
                "Ubuntu 26.04 sudo provider selector is incorrect");
        require(visudoSpec.providerExecutables.size() == 2,
                "Ubuntu 26.04 sudo provider mappings are incomplete");
    } else {
        require(visudoSpec.activeProviderSelector.empty() &&
                    visudoSpec.providerExecutables.empty(),
                "fixed-provider platform unexpectedly has provider mappings");
    }
    const auto* pamAuthUpdate = fic::platform::findExecutableSpec(
        profile.executables, fic::platform::ExecutableId::PamAuthUpdate);
    require((profile.id == "alt-p11") == (pamAuthUpdate == nullptr),
            "pam-auth-update support does not match the platform family");
    for (const auto id : {fic::platform::ExecutableId::Dconf,
                          fic::platform::ExecutableId::Gsettings}) {
        const auto& spec = executableSpec(profile, id);
        require(!spec.required && spec.candidates.size() == 1 &&
                    spec.candidates.front() ==
                        (id == fic::platform::ExecutableId::Dconf
                             ? "/usr/bin/dconf" : "/usr/bin/gsettings"),
                "GNOME command must be an optional canonical executable");
    }
    const auto supplementaryProvider =
        profile.userCreation.supplementaryGroupsProvider;
    if (profile.id == "debian-12" || profile.id == "ubuntu-24.04") {
        require(supplementaryProvider ==
                    fic::platform::UserSupplementaryGroupsProviderKind::DebianAdduser,
                "legacy Debian-family profile must use adduser extra groups");
        require(profile.userCreation.useraddDefaultsLookup ==
                    fic::platform::UseraddDefaultsLookupSemantics::ExactKey,
                "shadow 4.13 profile must use proven exact useradd keys");
    } else if (profile.id == "debian-13" || profile.id == "ubuntu-26.04") {
        require(supplementaryProvider ==
                    fic::platform::UserSupplementaryGroupsProviderKind::ShadowUseraddDefaults,
                "shadow 4.17 profile must use useradd GROUPS");
        require(profile.userCreation.useraddDefaultsLookup ==
                    fic::platform::UseraddDefaultsLookupSemantics::ExactKey,
                "shadow 4.17 profile must use exact useradd key lookup");
    } else if (profile.id == "alt-p11") {
        require(supplementaryProvider ==
                    fic::platform::UserSupplementaryGroupsProviderKind::Unsupported,
                "ALT p11 cannot express replacement or empty group-list semantics");
        require(profile.userCreation.adduserConfigPath.empty(),
                "ALT p11 must not claim a Debian adduser native path");
        require(profile.userCreation.useraddDefaultsLookup ==
                    fic::platform::UseraddDefaultsLookupSemantics::ExactKey,
                "ALT p11 must use the package-proven exact-key semantics");
    }
    require(executableSpec(
                profile,
                fic::platform::ExecutableId::Nft).candidates ==
                std::vector<std::filesystem::path>{"/usr/sbin/nft"},
            "nft candidate is incorrect");
    require(executableSpec(
                profile,
                fic::platform::ExecutableId::Chage).candidates ==
                std::vector<std::filesystem::path>{"/usr/bin/chage"},
            "chage candidate is incorrect");
    require(profile.passwordAging.loginDefsPath == "/etc/login.defs" &&
                profile.passwordAging.passwdPath == "/etc/passwd",
            "password-aging local database paths are incorrect");
    const auto& agingDefaults = profile.passwordAging.policyDefaults;
    require(agingDefaults.uidMin == (profile.id == "alt-p11" ? 500 : 1000) &&
                agingDefaults.uidMax == 60000,
            "password-aging UID policy defaults are incorrect");
    require(profile.passwordAging.missingKeySemantics.minDays == -1 &&
                profile.passwordAging.missingKeySemantics.maxDays == -1 &&
                profile.passwordAging.missingKeySemantics.warningDays == -1,
            "password-aging missing-key semantics are incorrect");
    if (profile.id == "alt-p11") {
        require(profile.passwordAging.shadowKind ==
                    fic::platform::LocalShadowKind::TcbDirectory &&
                    agingDefaults.minDays == 0 &&
                    agingDefaults.maxDays == 99999 &&
                    agingDefaults.warningDays == 7,
                "ALT p11 password-aging policy defaults/backend are incorrect");
    } else {
        require(profile.passwordAging.shadowKind ==
                    fic::platform::LocalShadowKind::ShadowFile &&
                    agingDefaults.minDays == 0 &&
                    agingDefaults.maxDays == 99999 &&
                    agingDefaults.warningDays == 7,
                "Debian/Ubuntu password-aging policy defaults are incorrect");
    }
    require(profile.userCreation.provider ==
                fic::platform::UserCreationProviderKind::ShadowUseradd &&
                profile.userCreation.useraddDefaultsPath ==
                    "/etc/default/useradd" &&
                profile.userCreation.loginDefsPath == "/etc/login.defs" &&
                profile.userCreation.passwdPath == "/etc/passwd" &&
                profile.userCreation.groupPath == "/etc/group" &&
                profile.userCreation.shellsPath == "/etc/shells" &&
                profile.userCreation.requireListedShellWhenShellsFileExists,
            "user-creation backend paths/capabilities are incorrect");
    const auto& creationDefaults = profile.userCreation.policyDefaults;
    require(creationDefaults.homeBaseDirectory == "/home" &&
                creationDefaults.skeletonDirectory == "/etc/skel" &&
                creationDefaults.createPrivateGroup == "yes" &&
                creationDefaults.defaultPrimaryGroup == "users",
            "common user-creation policy defaults are incorrect");
    require(
        creationDefaults.createHome ==
                (profile.id == "alt-p11" ? "yes" : "no") &&
            creationDefaults.defaultShell ==
                (profile.id == "alt-p11" ? "/bin/bash" : "/bin/sh"),
        "distribution-specific user-creation defaults are incorrect");
    require(!profile.packageManager.queryCandidates.empty(),
            "package manager query candidates are missing");
    require(profile.displayManager.sddmConfigPath == "/etc/sddm.conf",
            "SDDM configuration path is incorrect");
    require(profile.displayManager.lightDmConfigPath ==
                "/etc/lightdm/lightdm.conf",
            "LightDM configuration path is incorrect");
    require(!profile.pam.configDirectories.empty(),
            "PAM configuration directories are missing");
    require(!profile.pam.moduleDirectories.empty(),
            "PAM module directories are missing");
    if (profile.id == "alt-p11") {
        require(profile.pam.trustedServiceAliases.size() == 4 &&
                    profile.pam.trustedServiceAliases.front().aliasPath ==
                        "/etc/pam.d/system-auth" &&
                    profile.pam.trustedServiceAliases.front().allowedTargets ==
                        std::vector<std::filesystem::path>{
                            "/etc/pam.d/system-auth-local",
                            "/etc/pam.d/system-auth-sss",
                            "/etc/pam.d/system-auth-ldap",
                            "/etc/pam.d/system-auth-krb5",
                            "/etc/pam.d/system-auth-krb5_ccreds",
                            "/etc/pam.d/system-auth-winbind",
                            "/etc/pam.d/system-auth-multi",
                            "/etc/pam.d/system-auth-pkcs11"} &&
                    profile.pam.trustedServiceAliases[1].aliasPath ==
                        "/etc/pam.d/system-auth-use_first_pass" &&
                    profile.pam.trustedServiceAliases[1].allowedTargets ==
                        std::vector<std::filesystem::path>{
                            "/etc/pam.d/system-auth-use_first_pass-local",
                            "/etc/pam.d/system-auth-use_first_pass-sss",
                            "/etc/pam.d/system-auth-use_first_pass-ldap",
                            "/etc/pam.d/system-auth-use_first_pass-krb5",
                            "/etc/pam.d/system-auth-use_first_pass-krb5_ccreds",
                            "/etc/pam.d/system-auth-use_first_pass-winbind",
                            "/etc/pam.d/system-auth-use_first_pass-multi",
                            "/etc/pam.d/system-auth-use_first_pass-pkcs11"} &&
                    profile.pam.trustedServiceAliases[2].aliasPath ==
                        "/etc/pam.d/system-policy" &&
                    profile.pam.trustedServiceAliases[2].allowedTargets ==
                        std::vector<std::filesystem::path>{
                            "/etc/pam.d/system-policy-local",
                            "/etc/pam.d/system-policy-remote"} &&
                    profile.pam.trustedServiceAliases[3].aliasPath ==
                        "/etc/pam.d/system-check-localuser" &&
                    profile.pam.trustedServiceAliases[3].allowedTargets ==
                        std::vector<std::filesystem::path>{
                            "/etc/pam.d/system-check-localuser-legacy",
                            "/etc/pam.d/system-check-localuser-systemd"},
                "ALT trusted native PAM alias contract is incorrect");
    } else {
        require(profile.pam.trustedServiceAliases.empty(),
                "Debian-family profile unexpectedly permits PAM aliases");
    }
    const auto& authenticationServices = pamScope(
        profile.pam,
        fic::platform::PamScope::EffectiveAuthenticationStack).services;
    const auto& passwordServices = pamScope(
        profile.pam,
        profile.id == "alt-p11"
            ? fic::platform::PamScope::LocalPasswordChange
            : fic::platform::PamScope::EffectivePasswordStack).services;
    require(!authenticationServices.empty(),
            "PAM authentication services are missing");
    require(!passwordServices.empty(),
            "PAM password services are missing");
    require(!profile.pam.trustedAuthenticationBypasses.empty(),
            "trusted PAM authentication bypass rules are missing");
    const bool expectedSuLoginService = profile.id != "alt-p11";
    require((std::find(authenticationServices.begin(),
                       authenticationServices.end(),
                       "su-l") != authenticationServices.end()) ==
                expectedSuLoginService,
            "PAM su-l service selection is incorrect");
    const auto hasTrustedRootok = [&](const std::string& service) {
        return std::any_of(
            profile.pam.trustedAuthenticationBypasses.begin(),
            profile.pam.trustedAuthenticationBypasses.end(),
            [&](const auto& rule) {
                return rule.service == service &&
                    rule.module == "pam_rootok.so" &&
                    rule.reason == fic::platform::
                        PamTrustedAuthenticationBypassReason::
                            AlreadyPrivilegedCaller;
            });
    };
    require(hasTrustedRootok("su"),
            "trusted PAM root transition for su is missing");
    require(hasTrustedRootok("su-l") == expectedSuLoginService,
            "trusted PAM root transition for su-l is incorrect");
    const auto hasExactPasswordless = [&](const std::string& service) {
        return std::any_of(
            profile.pam.trustedAuthenticationBypasses.begin(),
            profile.pam.trustedAuthenticationBypasses.end(),
            [&](const auto& rule) {
                return rule.service == service &&
                    rule.module == "pam_succeed_if.so" &&
                    rule.reason == fic::platform::
                        PamTrustedAuthenticationBypassReason::
                            ExplicitPasswordlessLogin &&
                    rule.control == "sufficient" &&
                    rule.arguments == std::vector<std::string>{
                        "user", "ingroup", "nopasswdlogin"} &&
                    rule.source == std::optional<std::filesystem::path>{
                        "/etc/pam.d/" + service};
            });
    };
    if (profile.id == "alt-p11") {
        require(hasExactPasswordless("gdm-password") &&
                    hasExactPasswordless("lightdm") &&
                    profile.pam.passwordlessLoginControl.has_value() &&
                    profile.pam.passwordlessLoginControl->groupName ==
                        "nopasswdlogin" &&
                    profile.pam.passwordlessLoginControl->supportedNss.passwd ==
                        std::vector<std::vector<std::string>>{
                            {"files"}, {"files", "systemd"}} &&
                    profile.pam.passwordlessLoginControl->supportedNss.group ==
                        std::vector<std::vector<std::string>>{
                            {"files"}, {"files", "systemd"},
                            {"files", "role"},
                            {"files", "systemd", "role"}} &&
                    profile.pam.passwordlessLoginControl->
                            pamBypassNssServices ==
                        std::vector<std::string>{"sss"} &&
                    profile.pam.passwordlessLoginControl->supportedNss.
                            initgroups ==
                        std::vector<std::vector<std::string>>{
                            {"files"}, {"files", "systemd"},
                            {"files", "role"},
                            {"files", "systemd", "role"}},
                "ALT exact passwordless-login contract is incorrect");
    } else {
        require(!hasExactPasswordless("gdm-password") &&
                    !hasExactPasswordless("lightdm") &&
                    !profile.pam.passwordlessLoginControl.has_value(),
                "non-ALT profile declares ALT passwordless-login contract");
    }
    const auto* faillock = pamCapability(
        profile.pam, fic::platform::PamCapability::AuthenticationLockout);
    const auto* quality = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    const auto* history = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordHistory);
    require(faillock != nullptr &&
                faillock->configPath == "/etc/security/faillock.conf",
            "pam_faillock configuration path is incorrect");
    require(quality != nullptr &&
                quality->configPath ==
                    (profile.id == "alt-p11"
                         ? std::filesystem::path("/etc/passwdqc.conf")
                         : std::filesystem::path(
                               "/etc/security/pwquality.conf")),
            "password-quality provider configuration path is incorrect");
    require(
        quality->subjectScope ==
            (profile.id == "alt-p11"
                 ? fic::platform::PamIdentitySubjectScope::LocalUsersOnly
                 : fic::platform::PamIdentitySubjectScope::AllPamSubjects),
        "password-quality capability subject scope is incorrect");
    const bool legacyHistory = profile.id == "debian-12";
    const std::filesystem::path expectedHistoryConfig =
        profile.id == "alt-p11"
        ? "/etc/security/fic-pwhistory.conf"
        : "/etc/security/pwhistory.conf";
    require(history != nullptr &&
                (legacyHistory
                     ? history->configPath.empty() &&
                           history->configurationMode ==
                               fic::platform::PamCapabilityConfigurationMode::ModuleArguments
                     : history->configPath == expectedHistoryConfig &&
                           history->configurationMode ==
                               fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile),
            "password-history capability composition is incorrect");
    // Step 6 follow-up (P2, Variant A): module-argument evidence must
    // EXACTLY match the configuration mode — ModuleArguments platforms
    // carry the evidenced flags, provider-config-file platforms (Ubuntu
    // 24.04 included) carry none. The Ubuntu pwhistory options gate
    // results are a capability evidence probe, not production wiring.
    require(history != nullptr &&
                (legacyHistory
                     ? history->moduleArgumentSupport.pwhistoryRemember &&
                           history->moduleArgumentSupport
                               .pwhistoryEnforceForRoot
                     : !history->moduleArgumentSupport.pwhistoryRemember &&
                           !history->moduleArgumentSupport
                               .pwhistoryEnforceForRoot),
            "password-history module-argument evidence must match the "
            "configuration mode");
    const std::filesystem::path expectedLocalPamStack =
        profile.id == "alt-p11"
            ? std::filesystem::path("/etc/pam.d/system-auth-local-only")
            : std::filesystem::path{};
    std::vector<fic::platform::PamManagedTopologyTarget>
        expectedFaillockTargets;
    if (profile.id == "alt-p11") {
        expectedFaillockTargets = {
            {"/etc/pam.d/system-auth-local-only",
             fic::platform::PamManagedTopologyTargetRole::
                 AuthenticationAndAccount},
            {"/etc/pam.d/system-auth-use_first_pass-local-only",
             fic::platform::PamManagedTopologyTargetRole::Authentication}};
    }
    require(faillock->topologyTarget.empty() &&
                faillock->managedTopologyTargets.size() ==
                    expectedFaillockTargets.size() &&
                std::equal(
                    faillock->managedTopologyTargets.begin(),
                    faillock->managedTopologyTargets.end(),
                    expectedFaillockTargets.begin(),
                    [](const auto& actual, const auto& expected) {
                        return actual.path == expected.path &&
                            actual.role == expected.role;
                    }),
            "ALT PAM managed topology target metadata is incorrect");
    require(history->topologyTarget == expectedLocalPamStack,
            "ALT password-history topology target metadata is incorrect");
    if (profile.id == "alt-p11") {
        require(
            faillock->topology ==
                    fic::platform::PamTopologyStrategyKind::AltTcbManaged &&
                faillock->subjectScope ==
                    fic::platform::PamIdentitySubjectScope::LocalUsersOnly &&
                quality->scope ==
                    fic::platform::PamScope::LocalPasswordChange &&
                faillock->supportedFaillockStrategies ==
                    std::vector<fic::platform::PamFaillockStrategy>{
                        fic::platform::PamFaillockStrategy::PreauthRequired,
                        fic::platform::PamFaillockStrategy::PreauthRequisite} &&
                history->topology ==
                    fic::platform::PamTopologyStrategyKind::AltTcbManaged &&
                quality->topology ==
                    fic::platform::PamTopologyStrategyKind::StaticVerifyOnly &&
                faillock->activationIdentifiers.empty() &&
                history->activationIdentifiers.empty() &&
                quality->activationIdentifiers.empty(),
            "ALT PAM capabilities or supported faillock strategies are "
            "incorrect");
    } else {
        const auto hasStrategyActivation =
            [&](fic::platform::PamFaillockStrategy strategy,
                const std::vector<std::string>& identifiers) {
                return std::any_of(
                    faillock->strategyActivations.begin(),
                    faillock->strategyActivations.end(),
                    [&](const auto& activation) {
                        return activation.strategy == strategy &&
                            activation.activationIdentifiers == identifiers;
                    });
            };
        require(
            faillock->topology ==
                    fic::platform::PamTopologyStrategyKind::PamAuthUpdate &&
                history->topology ==
                    fic::platform::PamTopologyStrategyKind::PamAuthUpdate &&
                quality->topology ==
                    fic::platform::PamTopologyStrategyKind::PamAuthUpdate &&
                faillock->activationIdentifiers.empty() &&
                hasStrategyActivation(
                    fic::platform::PamFaillockStrategy::PreauthRequisite,
                    {"fic-faillock-hook-preauth",
                     "fic-faillock-hook-authfail",
                     "fic-faillock-hook-authsucc",
                     "fic-faillock-hook-account"}) &&
                hasStrategyActivation(
                    fic::platform::PamFaillockStrategy::PreauthRequired,
                    {"fic-faillock-hook-preauth",
                     "fic-faillock-hook-authfail",
                     "fic-faillock-hook-authsucc",
                     "fic-faillock-hook-account"}) &&
                hasStrategyActivation(
                    fic::platform::PamFaillockStrategy::Authsucc,
                    {"fic-faillock-hook-preauth",
                     "fic-faillock-hook-authfail",
                     "fic-faillock-hook-authsucc",
                     "fic-faillock-hook-account"}) &&
                history->activationIdentifiers ==
                    std::vector<std::string>{"fic-pwhistory"} &&
                quality->activationIdentifiers ==
                    std::vector<std::string>{"fic-pwquality"},
            "Debian-family PAM activation recipes are incorrect");
        require(pamAuthUpdate != nullptr &&
                    pamAuthUpdate->candidates ==
                        std::vector<std::filesystem::path>{
                            "/usr/sbin/pam-auth-update",
                            "/usr/bin/pam-auth-update"},
                "Debian-family pam-auth-update executable contract is incorrect");
    }
    if (profile.id == "alt-p11") {
        require(profile.grub.topology ==
                    fic::platform::GrubConfigTopology::SharedDefaultsFile &&
                    profile.grub.sharedDefaultsPath == "/etc/sysconfig/grub2" &&
                    profile.grub.managedConfigPath.empty() &&
                    profile.grub.baseDefaultsPath.empty(),
                "ALT GRUB shared-file topology is incorrect");
    } else {
        require(profile.grub.topology ==
                    fic::platform::GrubConfigTopology::OwnedDefaultsDropIn &&
                    profile.grub.sharedDefaultsPath.empty() &&
                    profile.grub.managedConfigPath ==
                        "/etc/default/grub.d/zzzz-fic.cfg" &&
                    profile.grub.baseDefaultsPath == "/etc/default/grub",
                "Debian-family GRUB owned-drop-in topology is incorrect");
    }
    require(hasRule(catalogRules(profile.dac, false),
                    profile.sudo.mainConfigPath),
            "the selected sudoers configuration must be protected by DAC policy");
    const std::string expectedSecurePath =
        profile.id == "alt-p11"
            ? "/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/bin"
            : (profile.id == "ubuntu-24.04" || profile.id == "ubuntu-26.04")
                ? "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
                : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    require(profile.sudo.securePathDefault == expectedSecurePath,
            "sudo secure_path platform default is incorrect");
    const auto hasLogicalObject = [&](const std::string& id) {
        return std::any_of(profile.dac.modeAndOwnerObjects.begin(),
                           profile.dac.modeAndOwnerObjects.end(),
                           [&](const auto& object) { return object.id == id; });
    };
    for (const std::string& command : {"df", "chattr", "arp", "ip"}) {
        require(hasLogicalObject(command),
                "protected executable must be an independent logical object: " +
                    command);
    }
    require(!hasLogicalObject("system_commands"),
            "aggregate system_commands logical object must not be exposed");
    const auto allowMissingVariant = [&](const std::string& id) {
        const auto found = std::find_if(
            profile.dac.modeAndOwnerObjects.begin(),
            profile.dac.modeAndOwnerObjects.end(),
            [&](const auto& object) { return object.id == id; });
        require(found != profile.dac.modeAndOwnerObjects.end(),
                "required DAC logical object is absent: " + id);
        return found->allowMissingVariant;
    };
    for (const std::string& id : {"fstab", "group", "passwd", "shadow",
                                  "df", "chattr", "ip"}) {
        require(!allowMissingVariant(id),
                "mandatory DAC object allows missing variant: " + id);
    }
    const bool debianSudoersOptional =
        profile.id == "debian-12" || profile.id == "debian-13";
    require(allowMissingVariant("sudoers") == debianSudoersOptional,
            "sudoers allow-missing capability does not match platform contract");
    for (const std::string& id : {"hosts_allow", "hosts_deny", "securetty",
                                  "arp"}) {
        require(allowMissingVariant(id),
                "optional DAC object lacks allow-missing variant: " + id);
    }
    const auto& resolvConfRule = findRule(
        catalogRules(profile.dac, false), "/etc/resolv.conf");
    using ManagedTarget = fic::platform::ModeAndOwnerProviderProfileTarget;
    using ManagedProvider = fic::platform::ManagedFileProvider;
    const ManagedTarget systemdResolvedRuntime = {
        "/run/systemd/resolve/stub-resolv.conf",
        ManagedProvider::SystemdResolved,
        {"systemd-resolve", "systemd-resolve", 0644},
        {"systemd-resolve", "systemd-resolve", 0644}};
    const ManagedTarget systemdResolvedUplink = {
        "/run/systemd/resolve/resolv.conf",
        ManagedProvider::SystemdResolved,
        {"systemd-resolve", "systemd-resolve", 0644},
        {"systemd-resolve", "systemd-resolve", 0644}};
    const ManagedTarget systemdResolvedStatic = {
        "/usr/lib/systemd/resolv.conf",
        ManagedProvider::SystemdResolved,
        {"root", "root", 0644}, {"root", "root", 0644}};
    const ManagedTarget networkManagerRuntime = {
        "/run/NetworkManager/resolv.conf",
        ManagedProvider::NetworkManager,
        {"root", "root", 0644}, {"root", "root", 0644}};
    std::vector<ManagedTarget> resolverTargets = {
        systemdResolvedRuntime,
        systemdResolvedUplink,
        systemdResolvedStatic,
        networkManagerRuntime
    };
    if (profile.id == "alt-p11") {
        resolverTargets.erase(resolverTargets.begin(),
                              resolverTargets.begin() + 3);
    } else if (profile.id == "debian-12" || profile.id == "debian-13") {
        resolverTargets.push_back({
            "/run/resolvconf/resolv.conf", ManagedProvider::Resolvconf,
            {"root", "root", 0644}, {"root", "root", 0644}});
    }
    require(resolvConfRule.allowedFinalSymlinkTargets.empty(),
            "provider-managed resolv.conf targets must not be remediate aliases");
    require(resolvConfRule.providerManagedFinalSymlinkTargets.size() ==
                resolverTargets.size() &&
            std::equal(
                resolvConfRule.providerManagedFinalSymlinkTargets.begin(),
                resolvConfRule.providerManagedFinalSymlinkTargets.end(),
                resolverTargets.begin(),
                [](const auto& actual, const auto& expected) {
                    return actual.path == expected.path &&
                        actual.provider == expected.provider &&
                        actual.strict.owner == expected.strict.owner &&
                        actual.strict.group == expected.strict.group &&
                        actual.strict.permissions ==
                            expected.strict.permissions &&
                        actual.system.owner == expected.system.owner &&
                        actual.system.group == expected.system.group &&
                        actual.system.permissions ==
                            expected.system.permissions;
                }),
            "resolv.conf provider target contracts are incorrect");
    require(std::none_of(
                resolverTargets.begin(), resolverTargets.end(),
                [](const auto& target) {
                    return target.path ==
                        "/run/NetworkManager/no-stub-resolv.conf";
                }),
            "NetworkManager no-stub internal file must not be allowlisted");
    for (const auto& rule : catalogRules(profile.dac, true)) {
        std::vector<std::filesystem::path> expectedTargets;
        if ((profile.id == "debian-13" || profile.id == "ubuntu-26.04") &&
            rule.path == "/usr/sbin/ip") {
            expectedTargets = {"/usr/bin/ip"};
        } else if (profile.id == "ubuntu-26.04" &&
                   rule.path == "/usr/bin/df") {
            expectedTargets = {"/usr/bin/gnudf"};
        }
        require(rule.allowedFinalSymlinkTargets == expectedTargets,
                "protected commands must not have unverified symlink exceptions");
    }

    if (profile.id == "alt-p11") {
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Rpm,
                "ALT p11 must use the RPM package database");
        require(profile.ssh.configPath == "/etc/openssh/sshd_config",
                "ALT p11 must use the OpenSSH configuration path");
        require(profile.ssh.serviceUnits ==
                    std::vector<std::string>({"sshd.service"}),
                "ALT p11 must use sshd.service");
        require(profile.displayManager.gdmConfigCandidates ==
                    std::vector<std::filesystem::path>({
                        "/etc/gdm/custom.conf"
                    }),
                "ALT p11 GDM configuration paths are incorrect");
        require(hasRule(catalogRules(profile.dac, false), "/etc/bashrc"),
                "ALT p11 must protect /etc/bashrc");
        require(hasRule(catalogRules(profile.dac, false), "/etc/securetty"),
                "ALT p11 must protect /etc/securetty");
        const auto& shadowRule = findRule(
            catalogRules(profile.dac, false), "/etc/shadow");
        require(shadowRule.strict.owner == "root" &&
                    shadowRule.strict.group == "root" &&
                    shadowRule.strict.permissions == 0400 &&
                    shadowRule.system.owner == "root" &&
                    shadowRule.system.group == "root" &&
                    shadowRule.system.permissions == 0400,
                "ALT p11 compatibility shadow metadata is incorrect");
        require(tcbObject(profile.dac) != nullptr,
                "ALT p11 must describe TCB credential storage");
        const auto& tcb = tcbObject(profile.dac)->profiles.at(fic::platform::DacPlatformConfig::Profile::System);
        require(tcb.rootPath == "/etc/tcb" && tcb.rootOwner == "root" &&
                    tcb.rootGroup == "shadow" && tcb.rootPermissions == 0710 &&
                    tcb.rootSystemPermissions == 0710 &&
                    tcb.entryGroup == "auth" &&
                    tcb.entryDirectoryPermissions == 02710 &&
                    tcb.entryDirectorySystemPermissions == 02710,
                "ALT p11 TCB directory metadata is incorrect");
        require(tcb.files.size() == 3 &&
                    tcb.files[0].name == "shadow" &&
                    tcb.files[0].permissions == 0640 &&
                    tcb.files[0].systemPermissions == 0640 &&
                    tcb.files[0].required &&
                    tcb.files[1].name == "shadow-" &&
                    tcb.files[1].permissions == 0640 &&
                    tcb.files[1].systemPermissions == 0640 &&
                    !tcb.files[1].required &&
                    tcb.files[2].name == "shadow.lock" &&
                    tcb.files[2].permissions == 0600 &&
                    tcb.files[2].systemPermissions == 0600 &&
                    !tcb.files[2].required,
                "ALT p11 TCB credential file metadata is incorrect");
        require(findRule(
                    catalogRules(profile.dac, false),
                    "/etc/sysctl.conf").allowedFinalSymlinkTargets ==
                    std::vector<std::filesystem::path>({
                        "/etc/sysctl.d/99-sysctl.conf"
                    }),
                "ALT p11 sysctl.conf symlink target is incorrect");
        require(findRule(
                    catalogRules(profile.dac, false),
                    "/etc/grub.cfg").allowedFinalSymlinkTargets ==
                    std::vector<std::filesystem::path>({
                        "/boot/grub/grub.cfg"
                    }),
                "ALT p11 grub.cfg symlink target is incorrect");
        require(!hasRule(catalogRules(profile.dac, false),
                         "/etc/sysconfig/securetty"),
                "ALT p11 must not use the obsolete securetty path");
        require(hasRule(catalogRules(profile.dac, true), "/sbin/ip"),
                "ALT p11 ip command path is incorrect");
        require(executableSpec(
                    profile,
                    fic::platform::ExecutableId::UpdateGrub).candidates ==
                    std::vector<std::filesystem::path>({
                        "/usr/sbin/grub-mkconfig",
                        "/usr/bin/grub-mkconfig"
                    }),
                "ALT p11 GRUB generator candidates are incorrect");
        require(profile.grub.rebuildArguments ==
                    std::vector<std::string>({"-o", "/etc/grub.cfg"}),
                "ALT p11 grub-mkconfig must write /etc/grub.cfg");
    } else if (profile.id == "debian-12") {
        require(tcbObject(profile.dac) == nullptr,
                "Debian must not enable ALT TCB handling");
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Debian 12 must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Debian 12 SSH configuration path is incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/daemon.conf",
                "Debian 12 primary GDM configuration path is incorrect");
        require(hasRule(catalogRules(profile.dac, false), "/etc/bash.bashrc"),
                "Debian 12 must protect /etc/bash.bashrc");
        require(hasRule(catalogRules(profile.dac, false),
                        "/boot/grub/grub.cfg"),
                "Debian 12 GRUB configuration path is incorrect");
        require(hasRule(catalogRules(profile.dac, true), "/usr/sbin/ip"),
                "Debian 12 ip command path is incorrect");
        require(executableSpec(
                    profile,
                    fic::platform::ExecutableId::UpdateGrub).candidates ==
                    std::vector<std::filesystem::path>({
                        "/usr/sbin/update-grub",
                        "/usr/bin/update-grub"
                    }),
                "Debian 12 update-grub candidates are incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Debian 12 update-grub must not receive arguments");
    } else if (profile.id == "debian-13") {
        require(tcbObject(profile.dac) == nullptr,
                "Debian must not enable ALT TCB handling");
        require(profile.hostCompatibility.versionIds ==
                    std::vector<std::string>({"13"}),
                "Debian 13 must accept only VERSION_ID=13");
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Debian 13 must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Debian 13 SSH configuration path is incorrect");
        require(profile.ssh.serviceUnits ==
                    std::vector<std::string>({"ssh.service", "sshd.service"}),
                "Debian 13 SSH service units are incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/daemon.conf",
                "Debian 13 primary GDM configuration path is incorrect");
        require(hasRule(catalogRules(profile.dac, false), "/etc/bash.bashrc"),
                "Debian 13 must protect /etc/bash.bashrc");
        require(hasRule(catalogRules(profile.dac, false),
                        "/boot/grub/grub.cfg"),
                "Debian 13 GRUB configuration path is incorrect");
        require(hasRule(catalogRules(profile.dac, true), "/usr/bin/df"),
                "Debian 13 df command path must use the merged-/usr location");
        require(hasRule(catalogRules(profile.dac, true), "/usr/sbin/ip"),
                "Debian 13 ip command path is incorrect");
        require(findRule(
                    catalogRules(profile.dac, true),
                    "/usr/sbin/ip").allowedFinalSymlinkTargets ==
                    std::vector<std::filesystem::path>({"/usr/bin/ip"}),
                "Debian 13 ip command symlink target is incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Debian 13 update-grub must not receive arguments");
        // Evidence-based lift (real Debian 13 gates: C2 G1-G11 PASS,
        // production wiring W1-W9 PASS, pwhistory options gate PASS with
        // the production ProviderConfigFile option path).
        require(profile.pam.passwordTopologyRuntimeMutable,
                "Debian 13 password topology must be lifted after the "
                "passed real Debian 13 gates");
        require(history != nullptr &&
                    history->configurationMode ==
                        fic::platform::PamCapabilityConfigurationMode::
                            ProviderConfigFile &&
                    !history->moduleArgumentSupport.pwhistoryRemember &&
                    !history->moduleArgumentSupport.pwhistoryEnforceForRoot,
                "Debian 13 keeps the provider-config option strategy with "
                "NO module-argument evidence");
    } else if (profile.id == "ubuntu-24.04" ||
               profile.id == "ubuntu-26.04") {
        require(tcbObject(profile.dac) == nullptr,
                "Ubuntu must not enable ALT TCB handling");
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Ubuntu must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Ubuntu SSH configuration path is incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/custom.conf",
                "Ubuntu primary GDM configuration path is incorrect");
        require(hasRule(catalogRules(profile.dac, false), "/etc/bash.bashrc"),
                "Ubuntu must protect /etc/bash.bashrc");
        require(hasRule(catalogRules(profile.dac, true), "/usr/bin/df"),
                "Ubuntu df command path is incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Ubuntu update-grub must not receive arguments");
        if (profile.id == "ubuntu-26.04") {
            // Evidence-based lift (real Ubuntu 26.04 gates: C2 G1-G11
            // PASS, production wiring W1-W9 PASS, pwhistory options gate
            // PASS with the production ProviderConfigFile option path).
            require(profile.pam.passwordTopologyRuntimeMutable,
                    "Ubuntu 26.04 password topology must be lifted after "
                    "the passed real Ubuntu 26.04 gates");
            require(history != nullptr &&
                        history->configurationMode ==
                            fic::platform::PamCapabilityConfigurationMode::
                                ProviderConfigFile &&
                        !history->moduleArgumentSupport.pwhistoryRemember &&
                        !history->moduleArgumentSupport
                             .pwhistoryEnforceForRoot,
                    "Ubuntu 26.04 keeps the provider-config option "
                    "strategy with NO module-argument evidence");
        }
        if (profile.id == "ubuntu-24.04") {
            require(profile.pam.passwordTopologyRuntimeMutable,
                    "Ubuntu 24.04 password topology must stay lifted");
        }
    } else {
        throw std::runtime_error("unexpected selected platform profile: " + profile.id);
    }
}

void testModeAndOwnerCapabilityPropagation() {
    using namespace fic::platform;
    ModeAndOwnerPathProfiles mandatory;
    mandatory.path = "/tmp/mandatory";
    mandatory.system = {"root", "root", 0644};
    mandatory.strict = mandatory.system;
    require(!makeModeAndOwnerPathObject("mandatory", mandatory)
                 .allowMissingVariant,
            "default source capability became allow-missing");

    ModeAndOwnerPathProfiles optional = mandatory;
    optional.path = "/tmp/optional";
    optional.allowMissingVariant = true;
    require(makeModeAndOwnerPathObject("optional", optional)
                .allowMissingVariant,
            "positive source capability was inverted by the factory");
}

void testCompatibilityIsFailClosed() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    fic::platform::OsReleaseValues values = compatibleValues(profile);
    std::string error;
    require(fic::platform::isHostCompatible(profile, values, error), error);

    values["ID"] = "another-distribution";
    require(!fic::platform::isHostCompatible(profile, values, error),
            "an incompatible os-release ID must be rejected");

    values = compatibleValues(profile);
    if (!profile.hostCompatibility.versionIds.empty()) {
        values["VERSION_ID"] = "unsupported-version";
        require(!fic::platform::isHostCompatible(profile, values, error),
                "an incompatible VERSION_ID must be rejected");
    }
    if (!profile.hostCompatibility.altBranchIds.empty()) {
        values["ALT_BRANCH_ID"] = "unsupported-branch";
        require(!fic::platform::isHostCompatible(profile, values, error),
                "an incompatible ALT_BRANCH_ID must be rejected");
    }
}

void testPamCompositionIsMechanismDriven() {
    fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    profile.id = "synthetic-passwdqc-with-history";
    auto* quality = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    require(quality != nullptr, "selected profile has no quality capability");
    quality->provider = fic::platform::PamProviderKind::PamPasswdqc;
    quality->configPath = "/etc/passwdqc.conf";
    if (pamCapability(
            profile.pam,
            fic::platform::PamCapability::PasswordHistory) == nullptr) {
        profile.pam.capabilities.push_back({
            fic::platform::PamCapability::PasswordHistory,
            fic::platform::PamProviderKind::PamPwhistory,
            quality->scope,
            "/etc/security/pwhistory.conf",
            fic::platform::PamTopologyStrategyKind::StaticVerifyOnly,
            {}});
    }

    std::string error;
    require(
        fic::platform::validatePlatformProfile(profile, error),
        "synthetic non-ALT passwdqc composition was rejected: " + error);
    require(
        pamCapability(
            profile.pam,
            fic::platform::PamCapability::PasswordHistory) != nullptr,
        "synthetic passwdqc composition lost an independent history capability");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.id = "synthetic-pwquality-without-history";
    quality = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    require(quality != nullptr, "selected profile has no quality capability");
    quality->provider = fic::platform::PamProviderKind::PamPwquality;
    quality->configPath = "/etc/security/pwquality.conf";
    profile.pam.capabilities.erase(
        std::remove_if(
            profile.pam.capabilities.begin(),
            profile.pam.capabilities.end(),
            [](const auto& capability) {
                return capability.capability ==
                    fic::platform::PamCapability::PasswordHistory;
            }),
        profile.pam.capabilities.end());
    require(
        fic::platform::validatePlatformProfile(profile, error),
        "synthetic pwquality composition without history was rejected: " +
            error);
}

void testCmakePamProviderSelectionMatchesProfile() {
    const auto profile = fic::platform::makeBuildPlatformProfile();
    const auto* quality = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    require(quality != nullptr,
            "selected platform has no password-quality capability");
    const std::string qualityProvider =
        quality->provider == fic::platform::PamProviderKind::PamPasswdqc
        ? "passwdqc"
        : quality->provider == fic::platform::PamProviderKind::PamPwquality
            ? "pwquality"
            : "unsupported";
    require(
        qualityProvider == FIC_CMAKE_PAM_PASSWORD_QUALITY_PROVIDER,
        "CMake password-quality provider diverges from PlatformProfile");

    const auto* history = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordHistory);
    const std::string historyProvider = history == nullptr
        ? "none"
        : history->provider == fic::platform::PamProviderKind::PamPwhistory
            ? "pwhistory"
            : "unsupported";
    require(
        historyProvider == FIC_CMAKE_PAM_PASSWORD_HISTORY_PROVIDER,
        "CMake password-history provider diverges from PlatformProfile");
}

void testInvalidProfileIsRejected() {
    fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    const auto configurePwqualityTopology = [](auto& candidate) -> auto& {
        auto* quality = pamCapability(
            candidate.pam, fic::platform::PamCapability::PasswordQuality);
        require(quality != nullptr, "selected profile has no quality capability");
        quality->provider = fic::platform::PamProviderKind::PamPwquality;
        quality->configPath = "/etc/security/pwquality.conf";
        quality->configTopology.emplace();
        quality->configTopology->primaryPath = quality->configPath;
        quality->configTopology->dropInDirectories = {
            "/etc/security/pwquality.conf.d"};
        return *quality->configTopology;
    };
    profile.ssh.configPath = "etc/ssh/sshd_config";
    std::string error;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative SSH configuration path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    auto* activation = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    activation->topology =
        fic::platform::PamTopologyStrategyKind::PamAuthUpdate;
    activation->activationIdentifiers.clear();
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an empty pam-auth-update activation recipe must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    activation = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    activation->topology =
        fic::platform::PamTopologyStrategyKind::PamAuthUpdate;
    activation->activationIdentifiers = {"pwquality", "pwquality"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "duplicate pam-auth-update profile identifiers must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    activation = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    activation->topology =
        fic::platform::PamTopologyStrategyKind::PamAuthUpdate;
    activation->activationIdentifiers = {"../pwquality"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "unsafe pam-auth-update profile identifiers must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    activation = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    activation->topology =
        fic::platform::PamTopologyStrategyKind::StaticVerifyOnly;
    activation->activationIdentifiers = {"pwquality"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a static PAM strategy must reject activation identifiers");

    profile = fic::platform::makeBuildPlatformProfile();
    if (fic::platform::findExecutableSpec(
            profile.executables,
            fic::platform::ExecutableId::PamAuthUpdate) != nullptr) {
        profile.executables.entries.erase(
            std::remove_if(
                profile.executables.entries.begin(),
                profile.executables.entries.end(),
                [](const auto& candidate) {
                    return candidate.id ==
                        fic::platform::ExecutableId::PamAuthUpdate;
                }),
            profile.executables.entries.end());
        require(!fic::platform::validatePlatformProfile(profile, error),
                "pam-auth-update strategy without a trusted executable must "
                "be rejected");
    }

    profile = fic::platform::makeBuildPlatformProfile();
    executableSpec(profile, fic::platform::ExecutableId::Sshd).candidates = {
        "usr/sbin/sshd"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative executable path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    auto& providerSpec = executableSpec(
        profile, fic::platform::ExecutableId::Sshd);
    providerSpec.activeProviderSelector = "/usr/bin/ssh";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a provider selector without mappings must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    auto& unmappedCandidateSpec = executableSpec(
        profile, fic::platform::ExecutableId::Sshd);
    unmappedCandidateSpec.activeProviderSelector = "/usr/bin/ssh";
    unmappedCandidateSpec.providerExecutables = {
        {"/usr/bin/ssh", "/usr/bin/not-a-candidate"}
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a provider executable outside candidates must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.executables.entries.push_back(profile.executables.entries.front());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate executable identifier must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.executables.entries.erase(
        std::remove_if(profile.executables.entries.begin(),
                       profile.executables.entries.end(), [](const auto& entry) {
            return entry.id == fic::platform::ExecutableId::Sshd;
        }),
        profile.executables.entries.end());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a missing required executable must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sudo.managedConfigPath = "etc/sudoers.d/zzzz-fic";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative sudoers path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sysctl.managedConfigPath = "etc/sysctl.d/zzzz-fic.conf";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative sysctl managed path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sysctl.managedConfigPath = "/etc/sysctl.d/zzzz-fic";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a sysctl managed path without .conf suffix must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.displayManager.gdmConfigCandidates.clear();
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an empty GDM configuration path list must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.configDirectories.front() = "etc/pam.d";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative PAM configuration directory must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.trustedServiceAliases = {
        {profile.pam.configDirectories.front() / "system-auth", {}}
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an empty trusted PAM alias allowlist must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.trustedServiceAliases = {
        {profile.pam.configDirectories.front() / "system-auth",
         {"/tmp/system-auth-local"}}
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a trusted PAM alias target outside its directory must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.trustedServiceAliases = {
        {profile.pam.configDirectories.front() / "system-auth",
         {profile.pam.configDirectories.front() / "system-auth-local"}},
        {profile.pam.configDirectories.front() / "system-auth",
         {profile.pam.configDirectories.front() / "system-auth-local"}}
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate trusted PAM alias must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    auto& authenticationServices = pamScope(
        profile.pam,
        fic::platform::PamScope::EffectiveAuthenticationStack).services;
    authenticationServices.push_back(authenticationServices.front());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate PAM service must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.trustedAuthenticationBypasses.push_back(
        profile.pam.trustedAuthenticationBypasses.front());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate trusted PAM bypass must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.pam.trustedAuthenticationBypasses.front().service =
        "unverified-service";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a trusted PAM bypass for an unverified service must be rejected");

    const auto withResolvConfTargets = [](std::function<void(
        fic::platform::DacPlatformConfig::PathContract&)> mutate) {
            fic::platform::PlatformProfile profile =
                fic::platform::makeBuildPlatformProfile();
            bool mutated = false;
            for (auto& object : profile.dac.modeAndOwnerObjects) {
                if (object.id != "resolv") continue;
                auto* path = std::get_if<fic::platform::DacPlatformConfig::
                    StaticPathObject>(&object.target);
                auto& contract = path->profiles.at(
                    fic::platform::DacPlatformConfig::Profile::System);
                if (!contract.providerTargets.empty()) {
                    mutate(contract);
                    mutated = true;
                }
            }
            if (!mutated) {
                return;
            }
            std::string validationError;
            require(!fic::platform::validatePlatformProfile(
                        profile, validationError),
                    "invalid provider target metadata must be rejected");
        };

    withResolvConfTargets([](auto& contract) {
        contract.providerTargets.front().metadata.owner.clear();
    });
    withResolvConfTargets([](auto& contract) {
        contract.providerTargets.front().metadata.group.clear();
    });
    withResolvConfTargets([](auto& contract) {
        contract.providerTargets.front().metadata.permissions = 0;
    });
    withResolvConfTargets([](auto& contract) {
        contract.providerTargets.push_back(contract.providerTargets.front());
    });
    withResolvConfTargets([](auto& contract) {
        contract.providerTargets.front().path = "run/relative";
    });
    withResolvConfTargets([](auto& contract) {
        contract.providerTargets.front().path =
            "/run/NetworkManager/../resolv.conf";
    });

    profile = fic::platform::makeBuildPlatformProfile();
    if (profile.pam.passwordlessLoginControl.has_value()) {
        auto exact = std::find_if(
            profile.pam.trustedAuthenticationBypasses.begin(),
            profile.pam.trustedAuthenticationBypasses.end(),
            [](const auto& rule) {
                return rule.reason == fic::platform::
                    PamTrustedAuthenticationBypassReason::
                        ExplicitPasswordlessLogin;
            });
        exact->arguments.back() = "wheel";
        require(!fic::platform::validatePlatformProfile(profile, error),
                "mismatched passwordless group metadata must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        exact = std::find_if(
            profile.pam.trustedAuthenticationBypasses.begin(),
            profile.pam.trustedAuthenticationBypasses.end(),
            [](const auto& rule) {
                return rule.reason == fic::platform::
                    PamTrustedAuthenticationBypassReason::
                        ExplicitPasswordlessLogin;
            });
        exact->source = "/etc/pam.d/common-login";
        require(!fic::platform::validatePlatformProfile(profile, error),
                "passwordless bypass from another source must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        profile.pam.passwordlessLoginControl->supportedNss.group.clear();
        require(!fic::platform::validatePlatformProfile(profile, error),
                "empty passwordless NSS contract must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        profile.pam.passwordlessLoginControl->supportedNss.group.push_back(
            {"files", "systemd", "role"});
        require(!fic::platform::validatePlatformProfile(profile, error),
                "duplicate passwordless NSS contract must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        profile.pam.passwordlessLoginControl->pamBypassNssServices = {
            "sss", "sss"};
        require(!fic::platform::validatePlatformProfile(profile, error),
                "duplicate PAM-bypass NSS service must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        profile.pam.passwordlessLoginControl->pamBypassNssServices = {
            "sss [SUCCESS=return]"};
        require(!fic::platform::validatePlatformProfile(profile, error),
                "unsafe PAM-bypass NSS service name must be rejected");
    }

    profile = fic::platform::makeBuildPlatformProfile();
    pamScope(profile.pam,
             fic::platform::PamScope::EffectivePasswordStack).services =
        {"../passwd"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an unsafe PAM service name must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    pamCapability(profile.pam,
                  fic::platform::PamCapability::PasswordQuality)->configPath =
        "etc/security/pwquality.conf";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative PAM option file path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    configurePwqualityTopology(profile).primaryPath =
        "etc/security/pwquality.conf";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative PAM topology primary path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    configurePwqualityTopology(profile).dropInDirectories = {
        "etc/security/pwquality.conf.d"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative PAM topology drop-in path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    configurePwqualityTopology(profile).fallbackPaths = {
        "/usr/lib/security/pwquality.conf",
        "/usr/lib/security/pwquality.conf"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "duplicate PAM topology fallback paths must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    configurePwqualityTopology(profile).fallbackPaths = {
        "/etc/security/pwquality.conf"};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "PAM topology primary path duplicated as fallback must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    configurePwqualityTopology(profile).primaryPath =
        "/etc/security/other-pwquality.conf";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "pwquality topology primary diverging from managed path must fail");

    profile = fic::platform::makeBuildPlatformProfile();
    configurePwqualityTopology(profile).explicitConfig =
        fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "pwquality topology accepted unsupported explicit config semantics");

    profile = fic::platform::makeBuildPlatformProfile();
    auto& validTopology = configurePwqualityTopology(profile);
    validTopology.fallbackPaths = {"/usr/lib/security/pwquality.conf"};
    validTopology.dropInDirectories = {
        "/etc/security/pwquality.conf.d",
        "/usr/lib/security/pwquality.conf.d"};
    require(fic::platform::validatePlatformProfile(profile, error),
            "valid synthetic PAM topology was rejected: " + error);

    profile = fic::platform::makeBuildPlatformProfile();
    pamCapability(
        profile.pam,
        fic::platform::PamCapability::AuthenticationLockout)->subjectScope =
            fic::platform::PamIdentitySubjectScope::LocalUsersOnly;
    auto* localLockout = pamCapability(
        profile.pam, fic::platform::PamCapability::AuthenticationLockout);
    if (localLockout->topology ==
        fic::platform::PamTopologyStrategyKind::AltTcbManaged) {
        localLockout->topology =
            fic::platform::PamTopologyStrategyKind::StaticVerifyOnly;
        localLockout->managedTopologyTargets.clear();
    }
    require(!fic::platform::validatePlatformProfile(profile, error),
            "non-ALT lockout capability accepted local-only subject scope");

    profile = fic::platform::makeBuildPlatformProfile();
    pamCapability(profile.pam,
                  fic::platform::PamCapability::PasswordQuality)->scope =
        fic::platform::PamScope::EffectiveAuthenticationStack;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a password capability in an authentication scope must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    auto* qualityCapability = pamCapability(
        profile.pam, fic::platform::PamCapability::PasswordQuality);
    auto* lockoutCapability = pamCapability(
        profile.pam, fic::platform::PamCapability::AuthenticationLockout);
    qualityCapability->configPath = lockoutCapability->configPath;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a PAM config path shared by capabilities must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    auto* lockout = pamCapability(
        profile.pam, fic::platform::PamCapability::AuthenticationLockout);
    lockout->topology =
        fic::platform::PamTopologyStrategyKind::AltTcbManaged;
    lockout->topologyTarget = "etc/pam.d/system-auth-local-only";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative PAM topology target must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    lockout = pamCapability(
        profile.pam, fic::platform::PamCapability::AuthenticationLockout);
    if (lockout->topology ==
        fic::platform::PamTopologyStrategyKind::AltTcbManaged) {
        lockout->managedTopologyTargets.clear();
        require(!fic::platform::validatePlatformProfile(profile, error),
                "an empty ALT managed topology target list must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        lockout = pamCapability(
            profile.pam, fic::platform::PamCapability::AuthenticationLockout);
        lockout->managedTopologyTargets.push_back(
            lockout->managedTopologyTargets.front());
        require(!fic::platform::validatePlatformProfile(profile, error),
                "a duplicate ALT managed topology target must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        lockout = pamCapability(
            profile.pam, fic::platform::PamCapability::AuthenticationLockout);
        lockout->managedTopologyTargets.front().role =
            fic::platform::PamManagedTopologyTargetRole::Authentication;
        require(!fic::platform::validatePlatformProfile(profile, error),
                "ALT managed topology without an account target must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        lockout = pamCapability(
            profile.pam, fic::platform::PamCapability::AuthenticationLockout);
        lockout->managedTopologyTargets.back().path =
            "etc/pam.d/system-auth-use_first_pass-local-only";
        require(!fic::platform::validatePlatformProfile(profile, error),
                "a relative ALT managed topology target must be rejected");
    }

    profile = fic::platform::makeBuildPlatformProfile();
    profile.userCreation.useraddDefaultsPath = "etc/default/useradd";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative useradd defaults path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.userCreation.policyDefaults.homeBaseDirectory = "/";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an unsafe user home base default must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.userCreation.policyDefaults.defaultPrimaryGroup = "100";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a numeric user primary group default must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    if (profile.grub.topology ==
        fic::platform::GrubConfigTopology::OwnedDefaultsDropIn) {
        profile.grub.managedConfigPath = "etc/default/grub.d/zzzz-fic.cfg";
    } else {
        profile.grub.sharedDefaultsPath = "etc/sysconfig/grub2";
    }
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative GRUB defaults path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    if (profile.grub.topology ==
        fic::platform::GrubConfigTopology::OwnedDefaultsDropIn) {
        profile.grub.sharedDefaultsPath = "/etc/default/grub";
    } else {
        profile.grub.managedConfigPath =
            "/etc/default/grub.d/zzzz-fic.cfg";
    }
    require(!fic::platform::validatePlatformProfile(profile, error),
            "GRUB topology with both path kinds must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    if (profile.grub.topology ==
        fic::platform::GrubConfigTopology::OwnedDefaultsDropIn) {
        profile.grub.baseDefaultsPath.clear();
        require(!fic::platform::validatePlatformProfile(profile, error),
                "an owned GRUB topology without a base defaults path "
                "must be rejected");

        profile = fic::platform::makeBuildPlatformProfile();
        profile.grub.baseDefaultsPath = "etc/default/grub";
        require(!fic::platform::validatePlatformProfile(profile, error),
                "a relative GRUB base defaults path must be rejected");
    } else {
        profile.grub.baseDefaultsPath = "/etc/default/grub";
        require(!fic::platform::validatePlatformProfile(profile, error),
                "a shared GRUB topology with a base defaults path "
                "must be rejected");
    }

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sudo.securePathDefault = "/usr/bin::/bin";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an empty sudo secure_path default component must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.sudo.securePathDefault = "/usr/bin:relative/bin";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative sudo secure_path default must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.grub.rebuildArguments.push_back("unsafe\nargument");
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a GRUB generator argument containing a newline must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    firstPathContract(profile).metadata.permissions = 0;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "invalid DAC enforced permissions must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    firstPathContract(profile).metadata.owner.clear();
    require(!fic::platform::validatePlatformProfile(profile, error),
            "empty DAC baseline owner must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.modeAndOwnerObjects.push_back(
        fic::platform::makeModeAndOwnerTcbObject(
        "invalid_tcb", fic::platform::TcbCredentialStorageConfig{
            "etc/tcb", "root", "shadow", 0710, 0710, "auth", 02710, 02710,
            {{"shadow", 0640, 0640, true}}}));
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative TCB credential root must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.modeAndOwnerObjects.push_back(
        fic::platform::makeModeAndOwnerTcbObject(
        "invalid_tcb", fic::platform::TcbCredentialStorageConfig{
            "/etc/tcb", "root", "shadow", 0710, 0710, "auth", 02710, 02710,
            {{"shadow", 0640, 0640, true}, {"shadow", 0600, 0600, false}}}));
    require(!fic::platform::validatePlatformProfile(profile, error),
            "duplicate TCB credential file metadata must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    firstPathContract(profile).allowedFinalSymlinkTargets = {
        "run/unsafe-target"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative DAC symlink target must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    firstPathContract(profile).allowedFinalSymlinkTargets = {
        "/run/safe/../unnormalized"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an unnormalized DAC symlink target must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    firstPathContract(profile).allowedFinalSymlinkTargets = {
        "/run/target", "/run/target"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate DAC symlink target must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    firstPathContract(profile).providerTargets = {{
            "run/provider-target",
            fic::platform::ManagedFileProvider::NetworkManager,
            {"root", "root", 0644}
        }};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative provider-managed target must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    auto& duplicateProviderTarget = firstPathContract(profile);
    duplicateProviderTarget.allowedFinalSymlinkTargets = {"/run/target"};
    duplicateProviderTarget.providerTargets = {{
        "/run/target",
        fic::platform::ManagedFileProvider::NetworkManager,
        {"root", "root", 0644}
    }};
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a target shared by remediate and validate-only lists must be rejected");
}

void testExecutableResolver() {
    std::string pattern = "/tmp/fic-platform-executables-XXXXXX";
    char* created = ::mkdtemp(pattern.data());
    require(created != nullptr, "cannot create temporary executable directory");
    const std::filesystem::path directory = created;

    try {
        const std::filesystem::path executable = directory / "sshd";
        std::ofstream stream(executable);
        stream << "#!/bin/sh\nexit 0\n";
        stream.close();
        require(::chmod(executable.c_str(), 0755) == 0,
                "cannot mark temporary command executable");

        fic::platform::PlatformExecutables registry;
        registry.entries = {{
            fic::platform::ExecutableId::Sshd,
            {directory / "missing", executable}
        }};
        fic::platform::PlatformExecutableResolverOptions resolverOptions;
        resolverOptions.enforceTrustedOwnership = false;
        fic::platform::PlatformExecutableResolver resolver(
            std::move(registry),
            resolverOptions);

        std::filesystem::path resolved;
        std::string error;
        require(resolver.resolve(
                    fic::platform::ExecutableId::Sshd, resolved, error),
                error);
        require(resolved == executable,
                "resolver did not select the first usable candidate");

        const std::filesystem::path replacement = directory / "missing";
        std::ofstream replacementStream(replacement);
        replacementStream << "#!/bin/sh\nexit 0\n";
        replacementStream.close();
        require(::chmod(replacement.c_str(), 0755) == 0,
                "cannot mark replacement command executable");
        std::filesystem::remove(executable);
        require(resolver.resolve(
                    fic::platform::ExecutableId::Sshd, resolved, error),
                error);
        require(resolved == replacement,
                "resolver must revalidate an invalidated cached candidate");

        std::ofstream restoredStream(executable);
        restoredStream << "#!/bin/sh\nexit 0\n";
        restoredStream.close();
        require(::chmod(executable.c_str(), 0755) == 0,
                "cannot restore temporary command");
        const std::filesystem::path symlink = directory / "sshd-link";
        std::filesystem::create_symlink(executable, symlink);
        fic::platform::PlatformExecutables symlinkRegistry;
        symlinkRegistry.entries = {{
            fic::platform::ExecutableId::Sshd,
            {symlink}
        }};
        fic::platform::PlatformExecutableResolver symlinkResolver(
            std::move(symlinkRegistry),
            resolverOptions);
        require(!symlinkResolver.resolve(
                    fic::platform::ExecutableId::Sshd, resolved, error),
                "resolver must reject a symbolic-link executable candidate");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
        throw;
    }

    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

void testProviderLinkedExecutableResolver() {
    std::string pattern = "/tmp/fic-provider-executables-XXXXXX";
    char* created = ::mkdtemp(pattern.data());
    require(created != nullptr,
            "cannot create provider executable directory");
    const std::filesystem::path directory = created;

    try {
        const auto makeExecutable = [&](const std::filesystem::path& path) {
            std::ofstream stream(path);
            stream << "#!/bin/sh\nexit 0\n";
            stream.close();
            require(::chmod(path.c_str(), 0755) == 0,
                    "cannot mark provider command executable");
        };
        const std::filesystem::path sudoRs = directory / "sudo-rs";
        const std::filesystem::path visudoRs = directory / "visudo-rs";
        const std::filesystem::path sudoClassic = directory / "sudo.ws";
        const std::filesystem::path visudoClassic = directory / "visudo.ws";
        const std::filesystem::path unknownSudo = directory / "sudo-unknown";
        const std::filesystem::path activeSudo = directory / "sudo";
        makeExecutable(sudoRs);
        makeExecutable(visudoRs);
        makeExecutable(sudoClassic);
        makeExecutable(visudoClassic);
        makeExecutable(unknownSudo);
        std::filesystem::create_symlink(sudoRs.filename(), activeSudo);

        fic::platform::PlatformExecutableResolverOptions options;
        options.enforceTrustedOwnership = false;
        fic::platform::PlatformExecutables fixedRegistry;
        fixedRegistry.entries = {{
            fic::platform::ExecutableId::Visudo,
            {visudoClassic}
        }};
        fic::platform::PlatformExecutableResolver fixedResolver(
            std::move(fixedRegistry), options);
        std::filesystem::path resolved;
        std::string error;
        require(fixedResolver.resolve(
                    fic::platform::ExecutableId::Visudo, resolved, error),
                error);
        require(resolved == visudoClassic,
                "fixed classic sudo platform did not select visudo");

        fic::platform::PlatformExecutableSpec visudoSpec{
            fic::platform::ExecutableId::Visudo,
            {visudoRs, visudoClassic}
        };
        visudoSpec.activeProviderSelector = activeSudo;
        visudoSpec.providerExecutables = {
            {sudoRs, visudoRs},
            {sudoClassic, visudoClassic}
        };
        fic::platform::PlatformExecutables registry;
        registry.entries = {visudoSpec};
        fic::platform::PlatformExecutableResolver resolver(
            std::move(registry), options);

        require(resolver.resolve(
                    fic::platform::ExecutableId::Visudo, resolved, error),
                error);
        require(resolved == visudoRs,
                "active sudo-rs provider did not select visudo-rs");

        std::filesystem::remove(activeSudo);
        std::filesystem::create_symlink(sudoClassic.filename(), activeSudo);
        require(resolver.resolve(
                    fic::platform::ExecutableId::Visudo, resolved, error),
                error);
        require(resolved == visudoClassic,
                "classic provider switch did not select visudo.ws");

        std::filesystem::remove(visudoClassic);
        require(!resolver.resolve(
                    fic::platform::ExecutableId::Visudo, resolved, error),
                "missing authoritative validator fell back to another provider");
        require(error.find("authoritative visudo") != std::string::npos,
                "missing authoritative validator diagnostic is unclear");

        makeExecutable(visudoClassic);
        std::filesystem::remove(activeSudo);
        std::filesystem::create_symlink(unknownSudo.filename(), activeSudo);
        require(!resolver.resolve(
                    fic::platform::ExecutableId::Visudo, resolved, error),
                "unknown active sudo provider was accepted");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
        throw;
    }

    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

void testOsReleaseParsing() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    const fic::platform::OsReleaseValues expected = compatibleValues(profile);
    TemporaryOsRelease file;
    std::ofstream stream(file.path);
    stream << "NAME=\"Test Distribution\"\n";
    for (const auto& [key, value] : expected) {
        stream << key << "=\"" << value << "\"\n";
    }
    stream.close();

    fic::platform::OsReleaseValues parsed;
    std::string error;
    require(fic::platform::readOsRelease(file.path, parsed, error), error);
    require(parsed.at("NAME") == "Test Distribution",
            "quoted os-release value was not decoded");
    require(fic::platform::isHostCompatible(profile, parsed, error), error);
}

void testModeAndOwnerCatalogValidation() {
    using Dac = fic::platform::DacPlatformConfig;
    std::string error;
    auto profile = fic::platform::makeBuildPlatformProfile();
    require(!profile.dac.modeAndOwnerObjects.empty(),
            "mode-and-owner logical catalog is empty");
    for (const Dac::Object& object : profile.dac.modeAndOwnerObjects) {
        const bool hasSystem = std::visit([](const auto& target) {
            using Target = std::decay_t<decltype(target)>;
            if constexpr (std::is_same_v<Target, Dac::PathCollectionObject>) {
                return !target.members.empty() &&
                    std::all_of(target.members.begin(), target.members.end(),
                        [](const Dac::CollectionMember& member) {
                            return member.profiles.count(Dac::Profile::System) != 0;
                        });
            } else if constexpr (std::is_same_v<Target, Dac::UserHomesObject>) {
                return target.directoryModes.count(Dac::Profile::System) != 0;
            } else {
                return target.profiles.count(Dac::Profile::System) != 0;
            }
        }, object.target);
        require(hasSystem, "logical object lacks system profile: " + object.id);
    }

    profile.dac.modeAndOwnerObjects.push_back(
        profile.dac.modeAndOwnerObjects.front());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "duplicate mode-and-owner object id was accepted");

    profile = fic::platform::makeBuildPlatformProfile();
    auto* path = std::get_if<Dac::StaticPathObject>(
        &profile.dac.modeAndOwnerObjects.front().target);
    require(path != nullptr, "first catalog object is not StaticPath");
    path->profiles.erase(Dac::Profile::System);
    require(!fic::platform::validatePlatformProfile(profile, error),
            "logical object without system profile was accepted");
}

} // namespace

int main() {
    try {
        testSelectedProfile();
        testCompatibilityIsFailClosed();
        testPamCompositionIsMechanismDriven();
        testCmakePamProviderSelectionMatchesProfile();
        testInvalidProfileIsRejected();
        testExecutableResolver();
        testProviderLinkedExecutableResolver();
        testOsReleaseParsing();
        testModeAndOwnerCatalogValidation();
        testModeAndOwnerCapabilityPropagation();
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
