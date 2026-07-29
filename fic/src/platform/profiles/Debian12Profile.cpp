#include "platform/PlatformProfile.h"

namespace fic::platform {

PlatformProfile makeBuildPlatformProfile() {
    PlatformProfile profile;
    profile.id = "debian-12";
    profile.displayName = "Debian 12";
    profile.hostCompatibility.osIds = {"debian"};
    profile.hostCompatibility.versionIds = {"12"};
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
        }
    };
    profile.ssh.configPath = "/etc/ssh/sshd_config";
    profile.ssh.includeBasePath = "/etc/ssh";
    profile.ssh.serviceUnits = {"ssh.service", "sshd.service"};
    profile.sudo.mainConfigPath = "/etc/sudoers";
    profile.sudo.managedConfigPath = "/etc/sudoers.d/zzzz-fic";
    profile.displayManager.sddmConfigPath = "/etc/sddm.conf";
    profile.displayManager.lightDmConfigPath = "/etc/lightdm/lightdm.conf";
    profile.displayManager.gdmConfigCandidates = {
        "/etc/gdm3/daemon.conf",
        "/etc/gdm3/custom.conf"
    };
    profile.dac.protectedSystemFiles = {
        {"/etc/bash.bashrc", "root", "root", 0644},
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
        {"/etc/passwd", "root", "root", 0644},
        {"/etc/shadow", "root", "shadow", 0640},
        {"/boot/grub/grub.cfg", "root", "root", 0600},
        {"/etc/securetty", "root", "root", 0600}
    };
    profile.dac.protectedSystemFiles.push_back(
        {profile.sudo.mainConfigPath, "root", "root", 0440});
    profile.dac.protectedSystemCommands = {
        {"/bin/df", "root", "root", 0750},
        {"/usr/bin/chattr", "root", "root", 0750},
        {"/usr/sbin/arp", "root", "root", 0750},
        {"/usr/sbin/ip", "root", "root", 0750}
    };
    return profile;
}

} // namespace fic::platform
