#include "platform/PlatformCompatibility.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"
#include "platform/RequiredPamEnforcementDefaultsGenerated.h"

#include <cstdlib>
#include <algorithm>
#include <fstream>
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

bool hasRule(const std::vector<fic::platform::FileAccessRule>& rules,
             const std::filesystem::path& path) {
    return std::any_of(
        rules.begin(), rules.end(),
        [&path](const fic::platform::FileAccessRule& rule) {
            return rule.path == path;
        });
}

const fic::platform::FileAccessRule& findRule(
    const std::vector<fic::platform::FileAccessRule>& rules,
    const std::filesystem::path& path) {
    const auto found = std::find_if(
        rules.begin(), rules.end(),
        [&path](const fic::platform::FileAccessRule& rule) {
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
              "/usr/sbin/visudo.ws", "/usr/sbin/visudo"}
        : std::vector<std::filesystem::path>{"/usr/sbin/visudo"};
    require(executableSpec(
                profile,
                fic::platform::ExecutableId::Visudo).candidates ==
                expectedVisudoCandidates,
            "visudo candidates are incorrect");
    require(profile.executables.entries.size() ==
                fic::platform::allExecutableIds().size(),
            "the executable registry must contain every supported logical command");
    const auto supplementaryProvider =
        profile.userCreation.supplementaryGroupsProvider;
    if (profile.id == "debian-12" || profile.id == "ubuntu-24.04") {
        require(supplementaryProvider ==
                    fic::platform::UserSupplementaryGroupsProviderKind::DebianAdduser,
                "legacy Debian-family profile must use adduser extra groups");
    } else if (profile.id == "debian-13" || profile.id == "ubuntu-26.04") {
        require(supplementaryProvider ==
                    fic::platform::UserSupplementaryGroupsProviderKind::ShadowUseraddDefaults,
                "shadow 4.17 profile must use useradd GROUPS");
    } else if (profile.id == "alt-p11") {
        require(supplementaryProvider ==
                    fic::platform::UserSupplementaryGroupsProviderKind::Unsupported,
                "ALT p11 cannot express replacement or empty group-list semantics");
        require(profile.userCreation.adduserConfigPath.empty(),
                "ALT p11 must not claim a Debian adduser native path");
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
    require(
        std::string(FIC_REQUIRED_PAM_ENFORCEMENT_DEFAULT) ==
            (profile.id == "alt-p11"
                 ? "pam_faillock,pam_passwdqc,pam_pwhistory"
                 : "pam_faillock,pam_pwquality,pam_pwhistory"),
        "required-PAM platform default is incorrect");
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
        require(profile.pam.trustedServiceAliases.size() == 3 &&
                    profile.pam.trustedServiceAliases.front().aliasPath ==
                        "/etc/pam.d/system-auth" &&
                    profile.pam.trustedServiceAliases.front().allowedTargets ==
                        std::vector<std::filesystem::path>{
                            "/etc/pam.d/system-auth-local",
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
                            "/etc/pam.d/system-policy-remote"},
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
            fic::platform::PamIdentitySubjectScope::AllPamSubjects,
        "password-quality capability subject scope is not explicit/all-subject");
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
    const std::filesystem::path expectedLocalPamStack =
        profile.id == "alt-p11"
            ? std::filesystem::path("/etc/pam.d/system-auth-local-only")
            : std::filesystem::path{};
    const std::vector<fic::platform::PamManagedTopologyTarget>
        expectedFaillockTargets = profile.id == "alt-p11"
        ? std::vector<fic::platform::PamManagedTopologyTarget>{
              {"/etc/pam.d/system-auth-local-only",
               fic::platform::PamManagedTopologyTargetRole::
                   AuthenticationAndAccount},
              {"/etc/pam.d/system-auth-use_first_pass-local-only",
               fic::platform::PamManagedTopologyTargetRole::Authentication}}
        : std::vector<fic::platform::PamManagedTopologyTarget>{};
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
    const std::filesystem::path expectedGrubDefaults =
        profile.id == "alt-p11"
            ? "/etc/sysconfig/grub2"
            : "/etc/default/grub";
    require(profile.grub.defaultsPath == expectedGrubDefaults,
            "GRUB defaults path is incorrect");
    require(hasRule(profile.dac.protectedSystemFiles,
                    profile.sudo.mainConfigPath),
            "the selected sudoers configuration must be protected by DAC policy");
    const auto& resolvConfRule = findRule(
        profile.dac.protectedSystemFiles, "/etc/resolv.conf");
    const std::vector<std::filesystem::path> resolvedTargets = {
        "/run/systemd/resolve/stub-resolv.conf",
        "/run/systemd/resolve/resolv.conf",
        "/usr/lib/systemd/resolv.conf"
    };
    if (profile.id == "alt-p11") {
        require(resolvConfRule.allowedFinalSymlinkTargets.empty(),
                "ALT p11 must not inherit systemd-resolved exceptions");
    } else {
        require(resolvConfRule.allowedFinalSymlinkTargets == resolvedTargets,
                "Debian/Ubuntu resolv.conf symlink targets are incorrect");
    }
    for (const auto& rule : profile.dac.protectedSystemCommands) {
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
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bashrc"),
                "ALT p11 must protect /etc/bashrc");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/securetty"),
                "ALT p11 must protect /etc/securetty");
        require(findRule(
                    profile.dac.protectedSystemFiles,
                    "/etc/sysctl.conf").allowedFinalSymlinkTargets ==
                    std::vector<std::filesystem::path>({
                        "/etc/sysctl.d/99-sysctl.conf"
                    }),
                "ALT p11 sysctl.conf symlink target is incorrect");
        require(findRule(
                    profile.dac.protectedSystemFiles,
                    "/etc/grub.cfg").allowedFinalSymlinkTargets ==
                    std::vector<std::filesystem::path>({
                        "/boot/grub/grub.cfg"
                    }),
                "ALT p11 grub.cfg symlink target is incorrect");
        require(!hasRule(profile.dac.protectedSystemFiles,
                         "/etc/sysconfig/securetty"),
                "ALT p11 must not use the obsolete securetty path");
        require(hasRule(profile.dac.protectedSystemCommands, "/sbin/ip"),
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
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Debian 12 must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Debian 12 SSH configuration path is incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/daemon.conf",
                "Debian 12 primary GDM configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bash.bashrc"),
                "Debian 12 must protect /etc/bash.bashrc");
        require(hasRule(profile.dac.protectedSystemFiles,
                        "/boot/grub/grub.cfg"),
                "Debian 12 GRUB configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/sbin/ip"),
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
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bash.bashrc"),
                "Debian 13 must protect /etc/bash.bashrc");
        require(hasRule(profile.dac.protectedSystemFiles,
                        "/boot/grub/grub.cfg"),
                "Debian 13 GRUB configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/bin/df"),
                "Debian 13 df command path must use the merged-/usr location");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/sbin/ip"),
                "Debian 13 ip command path is incorrect");
        require(findRule(
                    profile.dac.protectedSystemCommands,
                    "/usr/sbin/ip").allowedFinalSymlinkTargets ==
                    std::vector<std::filesystem::path>({"/usr/bin/ip"}),
                "Debian 13 ip command symlink target is incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Debian 13 update-grub must not receive arguments");
    } else if (profile.id == "ubuntu-24.04" ||
               profile.id == "ubuntu-26.04") {
        require(profile.packageManager.kind ==
                    fic::platform::PackageManagerKind::Dpkg,
                "Ubuntu must use the dpkg package database");
        require(profile.ssh.configPath == "/etc/ssh/sshd_config",
                "Ubuntu SSH configuration path is incorrect");
        require(profile.displayManager.gdmConfigCandidates.front() ==
                    "/etc/gdm3/custom.conf",
                "Ubuntu primary GDM configuration path is incorrect");
        require(hasRule(profile.dac.protectedSystemFiles, "/etc/bash.bashrc"),
                "Ubuntu must protect /etc/bash.bashrc");
        require(hasRule(profile.dac.protectedSystemCommands, "/usr/bin/df"),
                "Ubuntu df command path is incorrect");
        require(profile.grub.rebuildArguments.empty(),
                "Ubuntu update-grub must not receive arguments");
    } else {
        throw std::runtime_error("unexpected selected platform profile: " + profile.id);
    }
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
            fic::platform::PamTopologyStrategyKind::StaticReadOnly,
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
    executableSpec(profile, fic::platform::ExecutableId::Sshd).candidates = {
        "usr/sbin/sshd"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative executable path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.executables.entries.push_back(profile.executables.entries.front());
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate executable identifier must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.executables.entries.pop_back();
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
    require(!fic::platform::validatePlatformProfile(profile, error),
            "non-quality PAM capability accepted local-only subject scope");

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
    profile.grub.defaultsPath = "etc/default/grub";
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative GRUB defaults path must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.grub.rebuildArguments.push_back("unsafe\nargument");
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a GRUB generator argument containing a newline must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.protectedSystemFiles.front().permissions = 0;
    require(!fic::platform::validatePlatformProfile(profile, error),
            "invalid DAC permissions must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.protectedSystemFiles.front().allowedFinalSymlinkTargets = {
        "run/unsafe-target"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a relative DAC symlink target must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.protectedSystemFiles.front().allowedFinalSymlinkTargets = {
        "/run/safe/../unnormalized"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "an unnormalized DAC symlink target must be rejected");

    profile = fic::platform::makeBuildPlatformProfile();
    profile.dac.protectedSystemFiles.front().allowedFinalSymlinkTargets = {
        "/run/target", "/run/target"
    };
    require(!fic::platform::validatePlatformProfile(profile, error),
            "a duplicate DAC symlink target must be rejected");
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

} // namespace

int main() {
    try {
        testSelectedProfile();
        testCompatibilityIsFailClosed();
        testPamCompositionIsMechanismDriven();
        testCmakePamProviderSelectionMatchesProfile();
        testInvalidProfileIsRejected();
        testExecutableResolver();
        testOsReleaseParsing();
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
