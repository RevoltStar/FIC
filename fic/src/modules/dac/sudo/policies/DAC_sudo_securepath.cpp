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
}

DAC_sudo_securepath::~DAC_sudo_securepath() {

}

bool DAC_sudo_securepath::apply() {
    return this->Sudo::apply();
}
