#include "utils/ModuleConfigFileHandler.h"

const std::string ModuleConfigFileHandler::moduleFolderPath = "/opt/fic/config";

ModuleConfigFileHandler::ModuleConfigFileHandler(const std::string& module)
    : ConfigFileHandler(moduleFolderPath + "/" + module + ".conf", "=") {
}

std::string ModuleConfigFileHandler::statusKey(const std::string& policy) {
    return policy + ".status";
}

std::string ModuleConfigFileHandler::valueKey(const std::string& policy) {
    return policy + ".value";
}

bool ModuleConfigFileHandler::hasPolicyStatus(const std::string& policy) const {
    return ConfigFileHandler::isParameterExists(statusKey(policy));
}

bool ModuleConfigFileHandler::hasConfiguredValue(const std::string& policy) const {
    return ConfigFileHandler::isParameterExists(valueKey(policy));
}

std::string ModuleConfigFileHandler::getPolicyStatus(const std::string& policy) {
    const std::string key = statusKey(policy);
    if (!ConfigFileHandler::isParameterExists(key)) {
        return DISABLED_STATUS;
    }

    const std::string status = ConfigFileHandler::getValue(key);
    return status == ENABLED_STATUS ? ENABLED_STATUS : DISABLED_STATUS;
}

std::string ModuleConfigFileHandler::getPolicyValue(const std::string& policy) const {
    return ConfigFileHandler::getValue(valueKey(policy));
}

bool ModuleConfigFileHandler::setPolicyStatus(const std::string& policy, const std::string& status) {
    if (policy.empty()) {
        return false;
    }
    if (status != ENABLED_STATUS && status != DISABLED_STATUS) {
        return false;
    }
    return ConfigFileHandler::setValue(statusKey(policy), status);
}

bool ModuleConfigFileHandler::setPolicyValue(const std::string& policy, const std::string& value) {
    if (policy.empty()) {
        return false;
    }
    if (!ConfigFileHandler::isParameterExists(statusKey(policy))) {
        ConfigFileHandler::setValue(statusKey(policy), DISABLED_STATUS);
    }
    return ConfigFileHandler::setValue(valueKey(policy), value);
}

bool ModuleConfigFileHandler::enablePolicy(const std::string& policy) {
    return setPolicyStatus(policy, ENABLED_STATUS);
}

bool ModuleConfigFileHandler::disablePolicy(const std::string& policy) {
    return setPolicyStatus(policy, DISABLED_STATUS);
}

std::string ModuleConfigFileHandler::getValue(const std::string& parameter) const {
    return getPolicyValue(parameter);
}

bool ModuleConfigFileHandler::setValue(const std::string& parameter, const std::string& value) {
    return setPolicyValue(parameter, value);
}

bool ModuleConfigFileHandler::saveConfig() {
    return ConfigFileHandler::saveFile();
}

bool ModuleConfigFileHandler::isParameterExists(const std::string& parameter) {
    return hasConfiguredValue(parameter);
}

void ModuleConfigFileHandler::printConfig() const {
    ConfigFileHandler::printConfig();
}
