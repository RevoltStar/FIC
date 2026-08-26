#include "modules/dac/sudo/policies/DAC_sudo_passwd_tries.h"

DAC_sudo_passwd_tries::DAC_sudo_passwd_tries(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Sudo(platformConfig, executables) {
    //Какой параметр рассматриваем?
    /*this->Sudo::sudoParameter = "Defaults passwd_tries";*/
    this->Sudo::sudoParameter = std::make_unique<KeyValueDefaultsSudoersParam>(
        "Defaults", "", "", "passwd_tries", "=", "0", 0);
    this->policyName = "sudo_passwd_tries";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1,5,2);
}

DAC_sudo_passwd_tries::~DAC_sudo_passwd_tries() {

}

bool DAC_sudo_passwd_tries::apply() {
    this->log("Начинаем проверку максимального количества попыток ввода пароля sudo", logLevel::INFO);
    return this->Sudo::apply();
}
