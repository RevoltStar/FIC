#include "modules/oss/submodules/DisplayManager/OSS_disable_videodisplay_when_locked.h"

OSS_disable_videodisplay_when_locked::OSS_disable_videodisplay_when_locked()
    :DisplayManager()
{
    this->policyName = "disable_videodisplay_when_locked";
    this->policyTypeValue = std::make_unique<EnableDisablePolicyTypeValue>();
}

bool OSS_disable_videodisplay_when_locked::check_and_fix (){
    const std::string displayManager = this->detectDisplayManager();
    if (displayManager != "SDDM") {
        this->log("disable_videodisplay_when_locked is currently supported only for SDDM. Active display manager: " + displayManager, logLevel::ERROR);
        return false;
    }

    SectionConfigFileHandler scfh(this->sddmConf);
    if(!scfh.loadConfig()){
        this->log("Failed to load SDDM configuration: " + this->sddmConf, logLevel::ERROR);
        return false;
    }
    if(!scfh.setValue("General", "ShowVideoWhenLocked", "false")){
        this->log("Failed to set ShowVideoWhenLocked for SDDM", logLevel::ERROR);
        return false;
    }
    if(!scfh.saveConfig()){
        this->log("Failed to save SDDM configuration", logLevel::ERROR);
        return false;
    }
    return true;
}
