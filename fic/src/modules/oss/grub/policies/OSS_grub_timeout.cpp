#include "modules/oss/grub/policies/OSS_grub_timeout.h"
#include "modules/oss/grub/GrubConfiguration.h"

#include <utility>

OSS_grub_timeout::OSS_grub_timeout(
    fic::platform::GrubPlatformConfig platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Grub(std::move(platformConfig), executables) {
    this->policyName = "grub_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(0, 60, 5);
}

bool OSS_grub_timeout::applyGrub(const std::string& expectedValue) {
    return this->applyGrubValue("GRUB_TIMEOUT", expectedValue);
}
