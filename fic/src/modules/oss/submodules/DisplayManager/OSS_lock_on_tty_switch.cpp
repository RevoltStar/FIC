#include "modules/oss/submodules/DisplayManager/OSS_lock_on_tty_switch.h"

OSS_lock_on_tty_switch::OSS_lock_on_tty_switch()
    :DisplayManager()
{
    this->policyName = "lock_on_tty_switch";
    this->policyTypeValue = std::make_unique<EnableDisablePolicyTypeValue>();
}

bool OSS_lock_on_tty_switch::check_and_fix (){
    SectionConfigFileHandler scfh("/etc/systemd/logind.conf");
    if(!scfh.loadConfig()){
        std::cerr << "РќРµ СѓРґР°Р»РѕСЃСЊ РїСЂРѕС‡РµСЃС‚СЊ С„Р°Р№Р» /etc/systemd/logind.conf" <<std::endl;
        return false;
    }
    if(
            !scfh.setValue("Login", "HandleLidSwitch", "suspend") ||
            !scfh.setValue("Login", "HandleLidSwitchExternalPower", "suspend") ||
            !scfh.setValue("Login", "HandleLidSwitchDocked", "ignore") ||
            !scfh.setValue("Login", "IdleAction", "lock") ||
            !scfh.setValue("Login", "IdleActionSec", "0")){
        std::cerr << "РќРµ СѓРґР°Р»РѕСЃСЊ СѓСЃС‚Р°РЅРѕРІРёС‚СЊ РїР°СЂР°РјРµС‚СЂС‹ РґР»СЏ /etc/systemd/logind.conf" <<std::endl;
        return false;
    }
    if(!scfh.saveConfig()){
        std::cerr << "РќРµ СѓРґР°Р»РѕСЃСЊ СЃРѕС…СЂР°РЅРёС‚СЊ РїР°СЂР°РјРµС‚СЂС‹ РґР»СЏ /etc/systemd/logind.conf" <<std::endl;
        return false;
    }
    return true;
}
