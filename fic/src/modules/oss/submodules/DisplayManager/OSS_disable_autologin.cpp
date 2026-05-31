#include "modules/oss/submodules/DisplayManager/OSS_disable_autologin.h"

OSS_disable_autologin::OSS_disable_autologin()
    :DisplayManager()
{
    this->policyName = "disable_autologin";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_disable_autologin::check_and_fix (){
    const std::string displayManager = this->detectDisplayManager();
    std::string configPath;

    if (displayManager == "SDDM") {
        configPath = this->sddmConf;
        SectionConfigFileHandler scfh(configPath);
        if (!scfh.loadConfig()) {
            this->log("Failed to load SDDM configuration: " + configPath, logLevel::ERROR);
            return false;
        }

        if (!scfh.setValue("Autologin", "User", "") ||
            !scfh.setValue("Autologin", "Session", "") ||
            !scfh.saveConfig()) {
            this->log("Failed to disable autologin for SDDM", logLevel::ERROR);
            return false;
        }

        return true;
    }

    if (displayManager == "LIGHTDM") {
        configPath = this->lightdmConf;
        SectionConfigFileHandler scfh(configPath);
        if (!scfh.loadConfig()) {
            this->log("Failed to load LightDM configuration: " + configPath, logLevel::ERROR);
            return false;
        }

        if (!scfh.setValue("Seat:*", "autologin-user", "") ||
            !scfh.setValue("Seat:*", "autologin-session", "") ||
            !scfh.saveConfig()) {
            this->log("Failed to disable autologin for LightDM", logLevel::ERROR);
            return false;
        }

        return true;
    }

    if (displayManager == "GDM" || displayManager == "GDM3") {
        configPath = displayManager == "GDM3" ? this->gdm3Conf : this->gdmConf;
        SectionConfigFileHandler scfh(configPath);
        if (!scfh.loadConfig()) {
            this->log("Failed to load GDM configuration: " + configPath, logLevel::ERROR);
            return false;
        }

        if (!scfh.setValue("daemon", "AutomaticLoginEnable", "false") ||
            !scfh.setValue("daemon", "AutomaticLogin", "") ||
            !scfh.saveConfig()) {
            this->log("Failed to disable autologin for GDM", logLevel::ERROR);
            return false;
        }

        return true;
    }

    this->log("Failed to detect active display manager for disable_autologin policy", logLevel::ERROR);
    return false;
}
