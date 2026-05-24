#ifndef DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#define DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
#include <iostream>
#include <fstream>
#include <map>
#include <vector>

#include "modules/dac/submodules/ModeAndOwner.h"

class DAC_blocking_user_access_to_system_files : public ModeAndOwner
{

    //Файлы и права, которые у них ожидаются
    std::map<std::string, FileStats> expected = {
        {"/etc/bashrc", {"root", "root", 0644}},
        {"/etc/bash.bashrc", {"root", "root", 0644}},

        {"/etc/gshadow", {"root", "shadow", 0640}},
        {"/etc/passwd-", {"root", "root", 0644}},
        {"/etc/shadow-", {"root", "shadow", 0640}},
        {"/etc/group-", {"root", "root", 0644}},
        {"/etc/gshadow-", {"root", "shadow", 0640}},

        {"/etc/crontab", {"root", "root", 0600}},
        {"/etc/cron.d", {"root", "root", 0700}},
        {"/etc/cron.hourly", {"root", "root", 0700}},
        {"/etc/cron.daily", {"root", "root", 0700}},
        {"/etc/cron.weekly", {"root", "root", 0700}},
        {"/etc/cron.monthly", {"root", "root", 0700}},

        {"/etc/fstab", {"root", "root", 0640}},
        {"/etc/hostname", {"root", "root", 0644}},
        {"/etc/hosts", {"root", "root", 0644}},
        {"/etc/hosts.allow", {"root", "root", 0644}},
        {"/etc/hosts.deny", {"root", "root", 0644}},

        {"/etc/sudoers.d", {"root", "root", 0750}},
        {"/etc/ssh/sshd_config", {"root", "root", 0600}},


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
        {"/boot/grub/grub.cfg", {"root", "root", 0600}},
        {"/boot/grub2/grub.cfg", {"root", "root", 0600}},
        {"/boot/efi/EFI/redhat/grub.cfg", {"root", "root", 0600}},
        {"/boot/efi/EFI/ubuntu/grub.cfg", {"root", "root", 0600}},
        {"/boot/efi/EFI/debian/grub.cfg", {"root", "root", 0600}},

        {"/etc/securetty", {"root", "root", 0600}},
        {"/etc/sysconfig/securetty", {"root", "root", 0600}}
    };
public:
     DAC_blocking_user_access_to_system_files ();
     bool check_and_fix () override;

};

#endif // DAC_BLOCKING_USER_ACCESS_TO_SYSTEM_FILES_H
