#include "modules/dac/submodules/modeandowner/DAC_blocking_user_access_to_system_files.h"

DAC_blocking_user_access_to_system_files::DAC_blocking_user_access_to_system_files ()
    : ModeAndOwner ()
{
    this->ModeAndOwner::expected = {
    {"/etc/bashrc", {"root", "root", 0644}},
    {"/etc/crontab", {"root", "root", 0600}},
    {"/etc/fstab", {"root", "root", 0640}},
    {"/etc/hostname", {"root", "root", 0644}},
    {"/etc/hosts", {"root", "root", 0644}},
    {"/etc/hosts.allow", {"root", "root", 0644}},
    {"/etc/hosts.deny", {"root", "root", 0644}},
    {"/etc/group", {"root", "root", 0644}},
    {"/etc/ntpd.conf", {"root", "ntp", 0640}},
    {"/etc/resolv.conf", {"root", "root", 0644}},
    {"/etc/sysctl.conf", {"root", "root", 0644}},
    {"/etc/logrotate.conf", {"root", "root", 0644}},
    {"/etc/inittab", {"root", "root", 0644}},
    {"/etc/passwd", {"root", "root", 0644}},
    {"/etc/shadow", {"root", "shadow", 0640}},
    {"/etc/sudoers", {"root", "root", 0440}},
    {"/etc/grub.cfg", {"root", "root", 0600}},
    {"/etc/sysconfig/securetty", {"root", "root", 0600}}
    };
    this->policyName = "blocking_user_access_to_system_files";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool DAC_blocking_user_access_to_system_files::apply(){
        return this->ModeAndOwner::apply();
}
