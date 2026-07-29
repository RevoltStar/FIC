#include "platform/PlatformProfile.h"

namespace fic::platform {

PlatformProfile makeBuildPlatformProfile() {
    PlatformProfile profile;
    profile.id = "alt-p11";
    profile.displayName = "ALT Linux p11";
    profile.hostCompatibility.osIds = {"altlinux"};
    profile.hostCompatibility.altBranchIds = {"p11"};
    profile.systemTools.systemctlCandidates = {
        "/usr/bin/systemctl",
        "/bin/systemctl"
    };
    profile.systemTools.loginctlCandidates = {
        "/usr/bin/loginctl",
        "/bin/loginctl"
    };
    profile.ssh.configPath = "/etc/openssh/sshd_config";
    profile.ssh.includeBasePath = "/etc/openssh";
    profile.ssh.sshdCandidates = {"/usr/sbin/sshd"};
    profile.ssh.serviceUnits = {"sshd.service"};
    profile.sudo.mainConfigPath = "/etc/sudoers";
    profile.sudo.managedConfigPath = "/etc/sudoers.d/zzzz-fic";
    profile.sudo.visudoCandidates = {"/usr/sbin/visudo"};
    profile.displayManager.sddmConfigPath = "/etc/sddm.conf";
    profile.displayManager.lightDmConfigPath = "/etc/lightdm/lightdm.conf";
    profile.displayManager.gdmConfigCandidates = {"/etc/gdm/custom.conf"};
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
