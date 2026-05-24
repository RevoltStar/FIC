#include "modules/dac/submodules/sudo/DAC_sudo_timeout.h"
DAC_sudo_timeout::DAC_sudo_timeout()
    : Sudo(){
    //Какой параметр рассматриваем?
    this->Sudo::sudoParameter = std::make_unique<KeyValueDefaultsSudoersParam>(
        "Defaults", "", "", "timestamp_timeout", "=", "0", 0);
    this->policyName = "sudo_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(0,10,1);
}

DAC_sudo_timeout::~DAC_sudo_timeout() {

}

bool DAC_sudo_timeout::check_and_fix() {
    this->log("Начинаем проверку времени действия sudo", logLevel::INFO);
    return this->Sudo::check_and_fix();
}
