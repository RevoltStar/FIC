#include <fic/core/GlobalConfig.h>

#include <fic/core/ModuleConfigFileHandler.h>

namespace {
constexpr const char* GLOBAL_MODULE_NAME = "GLOBAL";
constexpr const char* ENABLED_FLAG = "ENABLE";
} // namespace

std::optional<std::string> GlobalConfig::getEnabledValue(const std::string& parameter)
{
    ModuleConfigFileHandler globalConfig(GLOBAL_MODULE_NAME);
    if (!globalConfig.loadConfig()) {
        return std::nullopt;
    }

    if (!globalConfig.hasConfiguredValue(parameter)) {
        return std::nullopt;
    }

    if (globalConfig.getPolicyStatus(parameter) != ENABLED_FLAG) {
        return std::nullopt;
    }

    return globalConfig.getPolicyValue(parameter);
}
