#include <fic/core/config/PolicyConfig.h>

#include <fic/core/config/ModuleConfigFileHandler.h>

namespace {
constexpr const char* ENABLED_FLAG = "ENABLE";
}

std::optional<std::string> PolicyConfig::getEnabledValue(
    const std::string& module,
    const std::string& policy)
{
    ModuleConfigFileHandler config(module);
    if (!config.loadConfig() || !config.hasConfiguredValue(policy)) {
        return std::nullopt;
    }
    if (config.getPolicyStatus(policy) != ENABLED_FLAG) {
        return std::nullopt;
    }
    return config.getPolicyValue(policy);
}
