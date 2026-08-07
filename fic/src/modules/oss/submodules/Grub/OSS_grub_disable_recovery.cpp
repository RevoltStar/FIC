#include "modules/oss/submodules/Grub/OSS_grub_disable_recovery.h"
#include "modules/oss/submodules/GrubConfiguration.h"

#include <utility>

OSS_grub_disable_recovery::OSS_grub_disable_recovery(
    fic::platform::GrubPlatformConfig platformConfig)
    : Grub(std::move(platformConfig)) {
    this->policyName = "grub_disable_recovery";
    this->policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        std::vector<std::string>{"ENABLE", "DISABLE"});
}

bool OSS_grub_disable_recovery::applyGrub(const std::string& expectedValue) {
    return this->applyGrubValue(
        "GRUB_DISABLE_RECOVERY",
        expectedValue,
        [](const std::string& value) {
            return value == "ENABLE" ? "true" : "false";
        }
    );
}