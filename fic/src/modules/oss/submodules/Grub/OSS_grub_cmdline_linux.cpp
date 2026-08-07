#include "modules/oss/submodules/Grub/OSS_grub_cmdline_linux.h"
#include "modules/oss/submodules/GrubConfiguration.h"

#include <utility>

OSS_grub_cmdline_linux::OSS_grub_cmdline_linux(
    fic::platform::GrubPlatformConfig platformConfig)
    : Grub(std::move(platformConfig)) {
    this->policyName = "grub_cmdline_linux";
    this->policyTypeValue = std::make_unique<MultiLineTextPolicyTypeValue>(
        ",", " ", "");
}

bool OSS_grub_cmdline_linux::applyGrub(const std::string& expectedValue) {
    return this->applyGrubValue("GRUB_CMDLINE_LINUX", expectedValue);
}