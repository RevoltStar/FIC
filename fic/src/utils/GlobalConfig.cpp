#include "utils/GlobalConfig.h"

#include "utils/ModuleConfigFileHandler.h"

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

    if (!globalConfig.isParameterExists(parameter)) {
        return std::nullopt;
    }

    if (globalConfig.getIsEnable(parameter) != ENABLED_FLAG) {
        return std::nullopt;
    }

    return globalConfig.getValue(parameter);
}
