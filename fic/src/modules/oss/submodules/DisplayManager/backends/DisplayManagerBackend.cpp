#include "modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.h"

#include "modules/oss/submodules/DisplayManager/backends/GdmBackend.h"
#include "modules/oss/submodules/DisplayManager/backends/LightDmBackend.h"
#include "modules/oss/submodules/DisplayManager/backends/SddmBackend.h"
#include "utils/SectionConfigFileHandler.h"

#include <algorithm>
#include <cctype>

bool DisplayManagerBackend::updateConfig(
    const std::vector<DisplayManagerConfigValue>& values,
    std::string& error
) const
{
    if (values.empty()) {
        error = "display manager configuration update is empty";
        return false;
    }

    SectionConfigFileHandler config(configPath());
    if (!config.loadConfig()) {
        error = "failed to load " + std::string(name()) + " configuration: " + configPath();
        return false;
    }

    for (const DisplayManagerConfigValue& value : values) {
        if (!config.setValue(value.section, value.key, value.value)) {
            error = "failed to set " + value.section + "/" + value.key +
                    " in " + std::string(name()) + " configuration";
            return false;
        }
    }
    if (!config.saveConfig()) {
        error = "failed to save " + std::string(name()) + " configuration: " + configPath();
        return false;
    }
    error.clear();
    return true;
}

bool DisplayManagerBackend::readConfig(
    const std::string& section,
    const std::string& key,
    std::string& value,
    std::string& error
) const
{
    SectionConfigFileHandler config(configPath());
    if (!config.loadConfig()) {
        error = "failed to load " + std::string(name()) + " configuration: " + configPath();
        return false;
    }
    if (!config.hasParameter(section, key)) {
        error = "parameter " + section + "/" + key + " is absent in " +
                std::string(name()) + " configuration";
        return false;
    }
    value = config.getValue(section, key);
    error.clear();
    return true;
}

std::unique_ptr<DisplayManagerBackend> DisplayManagerBackendFactory::create(
    const std::string& displayManager
)
{
    std::string normalized = displayManager;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });

    if (normalized == "SDDM") {
        return std::make_unique<SddmBackend>();
    }
    if (normalized == "LIGHTDM") {
        return std::make_unique<LightDmBackend>();
    }
    if (normalized == "GDM" || normalized == "GDM3") {
        return std::make_unique<GdmBackend>(normalized == "GDM3");
    }
    return nullptr;
}
