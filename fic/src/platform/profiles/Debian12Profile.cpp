#include "platform/PlatformProfile.h"

namespace fic::platform {

PlatformProfile makeBuildPlatformProfile() {
    PlatformProfile profile;
    profile.id = "debian-12";
    profile.displayName = "Debian 12";
    profile.hostCompatibility.osIds = {"debian"};
    profile.hostCompatibility.versionIds = {"12"};
    profile.userCreation.supplementaryGroupsProvider =
        UserSupplementaryGroupsProviderKind::DebianAdduser;
    profile.executables.entries = {
        {
            ExecutableId::Sshd,
            {"/usr/sbin/sshd", "/usr/bin/sshd"}
        },
        {
            ExecutableId::Systemctl,
            {"/usr/bin/systemctl", "/bin/systemctl"}
        },
        {
            ExecutableId::Loginctl,
            {"/usr/bin/loginctl", "/bin/loginctl"}
        },
        {
            ExecutableId::Visudo,
            {"/usr/sbin/visudo"}
        },
        {
            ExecutableId::Lscpu,
            {"/usr/bin/lscpu", "/bin/lscpu"}
        },
        {
            ExecutableId::Dmidecode,
            {"/usr/sbin/dmidecode", "/sbin/dmidecode"}
        },
        {
            ExecutableId::Udevadm,
            {"/usr/bin/udevadm", "/usr/sbin/udevadm", "/bin/udevadm", "/sbin/udevadm"}
        },
        {
            ExecutableId::UpdateGrub,
            {"/usr/sbin/update-grub", "/usr/bin/update-grub"}
        },
        {
            ExecutableId::Nft,
            {"/usr/sbin/nft"}
        },
        {
            ExecutableId::Chage,
            {"/usr/bin/chage"}
        },
        {
            ExecutableId::Gpasswd,
            {"/usr/bin/gpasswd", "/usr/sbin/gpasswd"}
        },
        {
            ExecutableId::PamAuthUpdate,
            {"/usr/sbin/pam-auth-update", "/usr/bin/pam-auth-update"}
        },
        {
            ExecutableId::Dconf,
            {"/usr/bin/dconf"},
            false
        },
        {
            ExecutableId::Gsettings,
            {"/usr/bin/gsettings"},
            false
        }
    };
    profile.packageManager.kind = PackageManagerKind::Dpkg;
    profile.packageManager.queryCandidates = {"/usr/bin/dpkg-query", "/bin/dpkg-query"};
    profile.ssh.configPath = "/etc/ssh/sshd_config";
    profile.ssh.includeBasePath = "/etc/ssh";
    profile.ssh.serviceUnits = {"ssh.service", "sshd.service"};
    profile.sudo.mainConfigPath = "/etc/sudoers";
    profile.sudo.managedConfigPath = "/etc/sudoers.d/zzzz-fic";
    profile.sysctl.loader = SysctlLoaderKind::SystemdSysctl;
    profile.sysctl.managedConfigPath = "/etc/sysctl.d/zzzz-fic.conf";
    profile.pam.configDirectories = {
        "/etc/pam.d",
        "/usr/lib/pam.d",
        "/usr/share/pam/pam.d"
    };
    profile.pam.moduleDirectories = {
        "/lib/security", "/lib64/security",
        "/usr/lib/security", "/usr/lib64/security"
    };
#ifdef FIC_LIBRARY_ARCHITECTURE
    profile.pam.moduleDirectories.push_back(
        std::filesystem::path("/lib") / FIC_LIBRARY_ARCHITECTURE / "security");
    profile.pam.moduleDirectories.push_back(
        std::filesystem::path("/usr/lib") / FIC_LIBRARY_ARCHITECTURE / "security");
#endif
    profile.pam.scopes = {
        {PamScope::EffectiveAuthenticationStack,
         {"login", "sshd", "sudo", "su", "su-l", "sddm",
          "gdm-password", "lightdm"}},
        {PamScope::EffectivePasswordStack, {"passwd", "common-password"}}
    };
    profile.pam.trustedAuthenticationBypasses = {
        {"su", "pam_rootok.so",
         PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller},
        {"su-l", "pam_rootok.so",
         PamTrustedAuthenticationBypassReason::AlreadyPrivilegedCaller}
    };
    profile.pam.trustedAuthenticationExclusions = {
        {"sddm", "pam_succeed_if.so",
         PamTrustedAuthenticationExclusionReason::ExplicitSubjectExclusion,
         "root", "required", {"user", "!=", "root", "quiet_success"},
         "/etc/pam.d/sddm", "common-auth", "requisite"}
    };
    profile.pam.capabilities = {
        {PamCapability::AuthenticationLockout, PamProviderKind::PamFaillock,
         PamScope::EffectiveAuthenticationStack,
         "/etc/security/faillock.conf",
         PamTopologyStrategyKind::PamAuthUpdate, {}},
        {PamCapability::PasswordQuality, PamProviderKind::PamPwquality,
         PamScope::EffectivePasswordStack,
         "/etc/security/pwquality.conf",
         PamTopologyStrategyKind::PamAuthUpdate, {}, std::nullopt,
         PamIdentitySubjectScope::AllPamSubjects},
        {PamCapability::PasswordHistory, PamProviderKind::PamPwhistory,
         PamScope::EffectivePasswordStack, {},
         PamTopologyStrategyKind::PamAuthUpdate, {}, std::nullopt,
         PamIdentitySubjectScope::AllPamSubjects,
         PamCapabilityConfigurationMode::ModuleArguments}
    };
    profile.pam.capabilities[0].supportedFaillockStrategies = {
        PamFaillockStrategy::PreauthRequired,
        PamFaillockStrategy::PreauthRequisite,
        PamFaillockStrategy::Authsucc};
    profile.pam.capabilities[0].defaultFaillockStrategy =
        PamFaillockStrategy::PreauthRequired;
    // Permanent pam-auth-update hooks are infrastructure, not policy
    // ownership. Every strategy uses the same four hooks; the actual policy
    // state lives in /etc/pam.d/fic-faillock-* slots and is tagged with the
    // journal mutation id.
    const std::vector<std::string> faillockHooks = {
        "fic-faillock-hook-preauth",
        "fic-faillock-hook-authfail",
        "fic-faillock-hook-authsucc",
        "fic-faillock-hook-account"};
    profile.pam.capabilities[0].strategyActivations = {
        {PamFaillockStrategy::PreauthRequisite, faillockHooks},
        {PamFaillockStrategy::PreauthRequired, faillockHooks},
        {PamFaillockStrategy::Authsucc, faillockHooks}
    };
    profile.pam.capabilities[1].activationIdentifiers = {"fic-pwquality"};
    profile.pam.capabilities[2].activationIdentifiers = {"fic-pwhistory"};
    profile.displayManager.sddmConfigPath = "/etc/sddm.conf";
    profile.displayManager.lightDmConfigPath = "/etc/lightdm/lightdm.conf";
    profile.displayManager.gdmConfigCandidates = {
        "/etc/gdm3/daemon.conf",
        "/etc/gdm3/custom.conf"
    };
    profile.grub.topology = GrubConfigTopology::OwnedDefaultsDropIn;
    profile.grub.managedConfigPath = "/etc/default/grub.d/zzzz-fic.cfg";
    profile.grub.baseDefaultsPath = "/etc/default/grub";
    profile.grub.rebuildArguments = {};
    profile.dac.protectedSystemFiles = {
        {"/etc/bash.bashrc", {"root", "root", 0644}, {"root", "root", 0644}},
        // Debian 12/13 ship /etc/crontab as 0644 root:root
        // (cron-daemon-common package archive). FIC hardens it to 0600 and
        // restores the packaged 0644 on disable.
        {"/etc/crontab", {"root", "root", 0600}, {"root", "root", 0644}},
        {"/etc/fstab", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/hostname", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/hosts", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/hosts.allow", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/hosts.deny", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/group", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/resolv.conf", {"root", "root", 0644}, {"root", "root", 0644}, {}, {
            // Provider metadata is the штатное provider state: baseline ==
            // enforced for every provider-managed final target.
            {"/run/systemd/resolve/stub-resolv.conf",
             ManagedFileProvider::SystemdResolved,
             {"systemd-resolve", "systemd-resolve", 0644},
             {"systemd-resolve", "systemd-resolve", 0644}},
            {"/run/systemd/resolve/resolv.conf",
             ManagedFileProvider::SystemdResolved,
             {"systemd-resolve", "systemd-resolve", 0644},
             {"systemd-resolve", "systemd-resolve", 0644}},
            {"/usr/lib/systemd/resolv.conf",
             ManagedFileProvider::SystemdResolved,
             {"root", "root", 0644}, {"root", "root", 0644}},
            {"/run/NetworkManager/resolv.conf",
             ManagedFileProvider::NetworkManager,
             {"root", "root", 0644}, {"root", "root", 0644}},
            {"/run/resolvconf/resolv.conf",
             ManagedFileProvider::Resolvconf,
             {"root", "root", 0644}, {"root", "root", 0644}}
        }},
        {"/etc/sysctl.conf", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/logrotate.conf", {"root", "root", 0644}, {"root", "root", 0644}},
        {"/etc/passwd", {"root", "root", 0644}, {"root", "root", 0644}},
        // shadowconfig on (passwd package postinst) provisions
        // /etc/shadow as root:shadow 0640 on Debian.
        {"/etc/shadow", {"root", "shadow", 0640}, {"root", "shadow", 0640}},
        {"/boot/grub/grub.cfg", {"root", "root", 0600}, {"root", "root", 0600}},
        // util-linux no longer ships /etc/securetty on Debian 12+; the rule
        // stays Ignore-on-missing and the baseline matches the legacy
        // securetty file mode.
        {"/etc/securetty", {"root", "root", 0600}, {"root", "root", 0600}}
    };
    profile.dac.protectedSystemFiles.push_back(
        {profile.sudo.mainConfigPath, {"root", "root", 0440}, {"root", "root", 0440}});
    // Packaged executable metadata is root:root 0755 (coreutils, e2fsprogs,
    // net-tools, iproute2 archives); FIC hardens to 0750 and restores the
    // packaged 0755 on disable.
    profile.dac.protectedSystemCommands = {
        {"/bin/df", {"root", "root", 0750}, {"root", "root", 0755}},
        {"/usr/bin/chattr", {"root", "root", 0750}, {"root", "root", 0755}},
        {"/usr/sbin/arp", {"root", "root", 0750}, {"root", "root", 0755}},
        {"/usr/sbin/ip", {"root", "root", 0750}, {"root", "root", 0755}}
    };
    return profile;
}

} // namespace fic::platform
