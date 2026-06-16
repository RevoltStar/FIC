#include "modules/dac/submodules/modeandowner/DAC_systemcommandlock.h"
#include <sstream>
#include <vector>



DAC_systemcommandlock::DAC_systemcommandlock(){
    //Системные утилиты
    this->ModeAndOwner::expected = {
        {"/bin/df", {"root", "root", 0750}},
        {"/usr/bin/chattr", {"root", "root", 0750}},
        {"/usr/sbin/arp", {"root", "root", 0750}},
        {"/sbin/ip", {"root", "root", 0750}}
    };
    this->policyName = "systemcommandlock";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool DAC_systemcommandlock::apply(){
    return this->ModeAndOwner::apply();
}

