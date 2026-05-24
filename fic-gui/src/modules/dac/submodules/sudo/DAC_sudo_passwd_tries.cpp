#include "modules/dac/submodules/sudo/DAC_sudo_passwd_tries.h"

DAC_sudo_passwd_tries::DAC_sudo_passwd_tries()
    : Sudo(){
    //Какой параметр рассматриваем?
    /*this->Sudo::sudoParameter = "Defaults passwd_tries";*/
    this->Sudo::sudoParameter = std::make_unique<KeyValueDefaultsSudoersParam>(
        "Defaults", "", "", "passwd_tries", "=", "0", 0);
    this->policyName = "sudo_passwd_tries";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1,5,2);
}

DAC_sudo_passwd_tries::~DAC_sudo_passwd_tries() {

}

bool DAC_sudo_passwd_tries::check_and_fix() {
    this->log("Начинаем проверку максимального количества попыток ввода пароля sudo", logLevel::INFO);
    return this->Sudo::check_and_fix();
}
