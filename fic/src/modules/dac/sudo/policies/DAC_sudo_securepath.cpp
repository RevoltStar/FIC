#include "modules/dac/sudo/policies/DAC_sudo_securepath.h"
#include "modules/dac/sudo/SudoSecurePathPolicyTypeValue.h"

DAC_sudo_securepath::DAC_sudo_securepath(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Sudo(platformConfig, executables) {
    //Какой параметр рассматриваем?
    this->Sudo::sudoParameter = std::make_unique<KeyValueDefaultsSudoersParam>(
        "Defaults", "", "", "secure_path", "=", "", 0);
    this->policyName = "sudo_securepath";
    this->policyTypeValue = std::make_unique<SudoSecurePathPolicyTypeValue>(
        platformConfig.securePathDefault);
    addRequiredDependency({"DAC", "SudoEdit", "sudo_disable_scoped_defaults"});
    // Upstream sudoers: "Users in the group specified by the exempt_group
    // option are not affected by secure_path".
    addRequiredDependency({"DAC", "SudoEdit", "sudo_exempt_group_disable"});
}

DAC_sudo_securepath::~DAC_sudo_securepath() {

}

bool DAC_sudo_securepath::apply() {
    return this->Sudo::apply();
}
