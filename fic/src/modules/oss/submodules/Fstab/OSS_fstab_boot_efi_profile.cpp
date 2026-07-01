#include "modules/oss/submodules/Fstab/OSS_fstab_boot_efi_profile.h"

OSS_fstab_boot_efi_profile::OSS_fstab_boot_efi_profile()
    : Fstab()
{
    this->policyName = "fstab_boot_efi_profile";
    this->mountPoints = {"/boot/efi"};
    this->configureProfiles({
        {"minimal", {"nodev", "nosuid", "noexec", "umask=0077"}},
        {"optimal", {"ro", "nodev", "nosuid", "noexec", "umask=0077"}}
    });
}
