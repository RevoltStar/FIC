#include "platform/PlatformProfile.h"

namespace fic::platform {

PlatformProfile makeBuildPlatformProfile() {
    PlatformProfile profile;
    profile.id = "alt-p11";
    profile.displayName = "ALT Linux p11";
    profile.hostCompatibility.osIds = {"altlinux"};
    profile.hostCompatibility.altBranchIds = {"p11"};
    profile.executables.entries = {
        {
            ExecutableId::Sshd,
            {"/usr/sbin/sshd"}
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
            {"/usr/sbin/grub-mkconfig", "/usr/bin/grub-mkconfig",
             "/usr/sbin/update-grub", "/usr/bin/update-grub"}
        }
    };
    profile.packageManager.kind = PackageManagerKind::Rpm;
    profile.packageManager.queryCandidates = {"/bin/rpm", "/usr/bin/rpm"};
    profile.ssh.configPath = "/etc/openssh/sshd_config";
    profile.ssh.includeBasePath = "/etc/openssh";
    profile.ssh.serviceUnits = {"sshd.service"};
    profile.sudo.mainConfigPath = "/etc/sudoers";
    profile.sudo.managedConfigPath = "/etc/sudoers.d/zzzz-fic";
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
    profile.pam.authenticationServices = {
        "login", "sshd", "sudo", "su", "sddm", "gdm-password", "lightdm",
        "system-auth"
    };
    profile.pam.passwordServices = {"passwd", "system-auth"};
    profile.pam.faillockConfigPath = "/etc/security/faillock.conf";
    profile.pam.passwordQualityConfigPath = "/etc/security/pwquality.conf";
    profile.pam.passwordHistoryConfigPath = "/etc/security/pwhistory.conf";
    profile.displayManager.sddmConfigPath = "/etc/sddm.conf";
    profile.displayManager.lightDmConfigPath = "/etc/lightdm/lightdm.conf";
    profile.displayManager.gdmConfigCandidates = {"/etc/gdm/custom.conf"};
    profile.grub.defaultsPath = "/etc/default/grub";
    profile.grub.rebuildCandidates = {
        "/usr/sbin/grub-mkconfig",
        "/usr/bin/grub-mkconfig",
        "/usr/sbin/update-grub",
        "/usr/bin/update-grub"
    };
    profile.dac.protectedSystemFiles = {
        {"/etc/bashrc", "root", "root", 0644},
        {"/etc/crontab", "root", "root", 0600},
        {"/etc/fstab", "root", "root", 0640},
        {"/etc/hostname", "root", "root", 0644},
        {"/etc/hosts", "root", "root", 0644},
        {"/etc/hosts.allow", "root", "root", 0644},
        {"/etc/hosts.deny", "root", "root", 0644},
        {"/etc/group", "root", "root", 0644},
        {"/etc/resolv.conf", "root", "root", 0644},
        {"/etc/sysctl.conf", "root", "root", 0644},
        {"/etc/logrotate.conf", "root", "root", 0644},
        {"/etc/inittab", "root", "root", 0644},
        {"/etc/passwd", "root", "root", 0644},
        {"/etc/shadow", "root", "shadow", 0640},
        {"/etc/grub.cfg", "root", "root", 0600},
        {"/etc/securetty", "root", "root", 0600}
    };
    profile.dac.protectedSystemFiles.push_back(
        {profile.sudo.mainConfigPath, "root", "root", 0440});
    profile.dac.protectedSystemCommands = {
        {"/bin/df", "root", "root", 0750},
        {"/usr/bin/chattr", "root", "root", 0750},
        {"/usr/sbin/arp", "root", "root", 0750},
        {"/sbin/ip", "root", "root", 0750}
    };
    return profile;
}

} // namespace fic::platform
