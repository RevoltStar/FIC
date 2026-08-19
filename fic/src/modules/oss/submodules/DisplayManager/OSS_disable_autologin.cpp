#include "modules/oss/submodules/DisplayManager/OSS_disable_autologin.h"

#include "modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.h"

OSS_disable_autologin::OSS_disable_autologin(
    const fic::platform::PlatformExecutableResolver& executables,
    const fic::platform::DisplayManagerPlatformConfig& displayManager)
    : DisplayManager(executables, displayManager)
{
    this->policyName = "disable_autologin";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_disable_autologin::apply()
{
    const std::string displayManager = this->detectDisplayManager();
    std::unique_ptr<DisplayManagerBackend> backend =
        DisplayManagerBackendFactory::create(
            displayManager, this->displayManagerConfig());
    if (!backend) {
        this->log(
            "Failed to detect configured display manager for disable_autologin policy",
            logLevel::ERROR
        );
        return false;
    }

    std::vector<DisplayManagerConfigValue> values;
    switch (backend->kind()) {
    case DisplayManagerKind::Sddm:
        values = {
            {"Autologin", "User", ""},
            {"Autologin", "Session", ""}
        };
        break;
    case DisplayManagerKind::LightDm:
        values = {
            {"Seat:*", "autologin-user", ""},
            {"Seat:*", "autologin-session", ""}
        };
        break;
    case DisplayManagerKind::Gdm:
        values = {
            {"daemon", "AutomaticLoginEnable", "false"},
            {"daemon", "AutomaticLogin", ""}
        };
        break;
    case DisplayManagerKind::Unknown:
        this->log("Unsupported display manager: " + displayManager, logLevel::ERROR);
        return false;
    }

    std::string error;
    if (!backend->updateConfig(values, error)) {
        this->log("Failed to disable autologin for " + std::string(backend->name()) + ": " + error,
                  logLevel::ERROR);
        return false;
    }
    return true;
}
