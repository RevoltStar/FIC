#include "modules/dac/sudo/policies/DAC_sudo_env_reset.h"

DAC_sudo_env_reset::DAC_sudo_env_reset(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Sudo(platformConfig, executables) {
    this->Sudo::sudoParameter = std::make_unique<SingleDefaultsSudoersParam>(
        "Defaults", "", "", "env_reset", 0);
    this->policyName = "sudo_env_reset";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

DAC_sudo_env_reset::~DAC_sudo_env_reset() {

}

bool DAC_sudo_env_reset::apply() {
    this->log("Начинаем проверку сброса переменных окружения sudo", logLevel::INFO);
    return this->Sudo::apply();
}
