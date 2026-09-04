#include "platform/PlatformProfile.h"

namespace fic::platform {

PlatformProfile makeBuildPlatformProfile() {
    PlatformProfile profile;
    profile.id = "ubuntu-26.04";
    profile.displayName = "Ubuntu 26.04";
    profile.hostCompatibility.osIds = {"ubuntu"};
    profile.hostCompatibility.versionIds = {"26.04"};
    profile.userCreation.supplementaryGroupsProvider =
        UserSupplementaryGroupsProviderKind::ShadowUseraddDefaults;
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
            {"/usr/lib/cargo/bin/visudo", "/usr/sbin/visudo.ws"},
            true,
            "/usr/bin/sudo",
            {
                {"/usr/lib/cargo/bin/sudo", "/usr/lib/cargo/bin/visudo"},
                {"/usr/bin/sudo.ws", "/usr/sbin/visudo.ws"}
            }
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
    profile.pam.capabilities = {
        {PamCapability::AuthenticationLockout, PamProviderKind::PamFaillock,
         PamScope::EffectiveAuthenticationStack,
         "/etc/security/faillock.conf",
         PamTopologyStrategyKind::ExternalOptIn, {}},
        {PamCapability::PasswordQuality, PamProviderKind::PamPwquality,
         PamScope::EffectivePasswordStack,
         "/etc/security/pwquality.conf",
         PamTopologyStrategyKind::ExternalOptIn, {}, std::nullopt,
         PamIdentitySubjectScope::AllPamSubjects},
        {PamCapability::PasswordHistory, PamProviderKind::PamPwhistory,
         PamScope::EffectivePasswordStack,
         "/etc/security/pwhistory.conf",
         PamTopologyStrategyKind::ExternalOptIn, {}}
    };
    profile.displayManager.sddmConfigPath = "/etc/sddm.conf";
    profile.displayManager.lightDmConfigPath = "/etc/lightdm/lightdm.conf";
    profile.displayManager.gdmConfigCandidates = {
        "/etc/gdm3/custom.conf",
        "/etc/gdm3/daemon.conf"
    };
    profile.grub.defaultsPath = "/etc/default/grub";
    profile.grub.rebuildArguments = {};
    profile.dac.protectedSystemFiles = {
        {"/etc/bash.bashrc", "root", "root", 0644},
        {"/etc/crontab", "root", "root", 0600},
        {"/etc/fstab", "root", "root", 0644},
        {"/etc/hostname", "root", "root", 0644},
        {"/etc/hosts", "root", "root", 0644},
        {"/etc/hosts.allow", "root", "root", 0644},
        {"/etc/hosts.deny", "root", "root", 0644},
        {"/etc/group", "root", "root", 0644},
        {"/etc/resolv.conf", "root", "root", 0644, {
            "/run/systemd/resolve/stub-resolv.conf",
            "/run/systemd/resolve/resolv.conf",
            "/usr/lib/systemd/resolv.conf"
        }},
        {"/etc/sysctl.conf", "root", "root", 0644},
        {"/etc/logrotate.conf", "root", "root", 0644},
        {"/etc/passwd", "root", "root", 0644},
        {"/etc/shadow", "root", "shadow", 0640},
        {"/boot/grub/grub.cfg", "root", "root", 0600},
        {"/etc/securetty", "root", "root", 0600}
    };
    profile.dac.protectedSystemFiles.push_back(
        {profile.sudo.mainConfigPath, "root", "root", 0440});
    profile.dac.protectedSystemCommands = {
        {
            "/usr/bin/df",
            "root",
            "root",
            0750,
            {"/usr/bin/gnudf"}
        },
        {"/usr/bin/chattr", "root", "root", 0750},
        {"/usr/sbin/arp", "root", "root", 0750},
        {
            "/usr/sbin/ip",
            "root",
            "root",
            0750,
            {"/usr/bin/ip"}
        }
    };
    return profile;
}

} // namespace fic::platform
