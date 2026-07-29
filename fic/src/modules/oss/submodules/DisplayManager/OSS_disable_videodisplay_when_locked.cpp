#include "modules/oss/submodules/DisplayManager/OSS_disable_videodisplay_when_locked.h"

#include "modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.h"

OSS_disable_videodisplay_when_locked::OSS_disable_videodisplay_when_locked(
    const fic::platform::SystemToolsPlatformConfig& systemTools,
    const fic::platform::DisplayManagerPlatformConfig& displayManager)
    : DisplayManager(systemTools, displayManager)
{
    this->policyName = "disable_videodisplay_when_locked";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_disable_videodisplay_when_locked::apply()
{
    const std::string displayManager = this->detectDisplayManager();
    std::unique_ptr<DisplayManagerBackend> backend =
        DisplayManagerBackendFactory::create(
            displayManager, this->displayManagerConfig());
    if (!backend || backend->kind() != DisplayManagerKind::Sddm) {
        this->log(
            "disable_videodisplay_when_locked is currently supported only for SDDM. Active display manager: " +
            displayManager,
            logLevel::ERROR
        );
        return false;
    }

    std::string error;
    if (!backend->updateConfig({{"General", "ShowVideoWhenLocked", "false"}}, error)) {
        this->log("Failed to disable video display when locked for SDDM: " + error, logLevel::ERROR);
        return false;
    }
    return true;
}
