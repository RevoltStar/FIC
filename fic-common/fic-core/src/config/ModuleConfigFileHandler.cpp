#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/core/runtime/FicRuntimePaths.h>

ModuleConfigFileHandler::ModuleConfigFileHandler(const std::string& module)
    : ModuleConfigFileHandler(fic::core::FicRuntimePaths::get().configDir, module) {
}

ModuleConfigFileHandler::ModuleConfigFileHandler(
    const std::filesystem::path& configDirectory,
    const std::string& module)
    : ConfigFileHandler((configDirectory / (module + ".conf")).string(), "=") {
}

std::string ModuleConfigFileHandler::statusKey(const std::string& policy) {
    return policy + ".status";
}

std::string ModuleConfigFileHandler::valueKey(const std::string& policy) {
    return policy + ".value";
}

std::string ModuleConfigFileHandler::violationSeverityKey(
    const std::string& policy) {
    return policy + ".violation_severity";
}

bool ModuleConfigFileHandler::hasPolicyViolationSeverity(
    const std::string& policy) const {
    return ConfigFileHandler::isParameterExists(violationSeverityKey(policy));
}

::fic::core::ViolationSeverity ModuleConfigFileHandler::getPolicyViolationSeverity(
    const std::string& policy) const {
    const std::string key = violationSeverityKey(policy);
    if (!ConfigFileHandler::isParameterExists(key)) {
        // No entry: the caller falls back to the compiled-in default.
        return ::fic::core::ViolationSeverity::None;
    }
    const std::optional<::fic::core::ViolationSeverity> parsed = ::fic::core::parseViolationSeverityToken(
        ConfigFileHandler::getValue(key));
    if (!parsed.has_value()) {
        // An unparsable severity must not degrade the reaction: a policy whose
        // configured severity cannot be understood is treated as ISOLATE.
        return ::fic::core::ViolationSeverity::Isolate;
    }
    return *parsed;
}

bool ModuleConfigFileHandler::setPolicyViolationSeverity(
    const std::string& policy,
    ::fic::core::ViolationSeverity severity) {
    if (policy.empty()) {
        return false;
    }
    return ConfigFileHandler::setValue(
        violationSeverityKey(policy),
        ::fic::core::violationSeverityToken(severity));
}

bool ModuleConfigFileHandler::hasPolicyStatus(const std::string& policy) const {
    return ConfigFileHandler::isParameterExists(statusKey(policy));
}

bool ModuleConfigFileHandler::hasConfiguredValue(const std::string& policy) const {
    return ConfigFileHandler::isParameterExists(valueKey(policy));
}

std::string ModuleConfigFileHandler::getPolicyStatus(const std::string& policy) const {
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

void ModuleConfigFileHandler::printConfig() const {
    ConfigFileHandler::printConfig();
}
