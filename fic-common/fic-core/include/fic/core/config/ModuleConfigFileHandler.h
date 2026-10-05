#ifndef MODULECONFIGFILEHANDLER_H
#define MODULECONFIGFILEHANDLER_H
#include <fic/core/config/ConfigFileHandler.h>
#include <fic/core/incident/IncidentSeverity.h>
#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>
#include <filesystem>

class ModuleConfigFileHandler : public ConfigFileHandler {
public:
    ModuleConfigFileHandler(const std::string& module);
    ModuleConfigFileHandler(const std::filesystem::path& configDirectory,
                            const std::string& module);

    bool hasPolicyStatus(const std::string& policy) const;
    bool hasConfiguredValue(const std::string& policy) const;
    bool hasPolicyViolationSeverity(const std::string& policy) const;

    std::string getPolicyStatus(const std::string& policy) const;
    std::string getPolicyValue(const std::string& policy) const;

    bool setPolicyStatus(const std::string& policy, const std::string& status);
    bool setPolicyValue(const std::string& policy, const std::string& value);

    // <policy>.violation_severity
    //
    // Stored as an opaque, strictly validated token: NONE | SOFT | STANDARD |
    // HARD | ISOLATE. An absent entry means "use the policy's compiled-in
    // default"; an INVALID entry fails closed to ViolationSeverity::Isolate
    // rather than silently degrading to a lower severity.
    fic::core::ViolationSeverity getPolicyViolationSeverity(const std::string& policy) const;
    bool setPolicyViolationSeverity(const std::string& policy,
                                    fic::core::ViolationSeverity severity);

    bool enablePolicy(const std::string& policy);
    bool disablePolicy(const std::string& policy);

    std::string getValue(const std::string& parameter) const override;
    bool setValue(const std::string& parameter, const std::string& value) override;

    //Вывести весь конфиг
    void printConfig() const override;

    //Сохранить конфиг
    bool saveConfig();

private:
    static constexpr const char* ENABLED_STATUS = "ENABLE";
    static constexpr const char* DISABLED_STATUS = "DISABLE";

    static std::string statusKey(const std::string& policy);
    static std::string valueKey(const std::string& policy);
    static std::string violationSeverityKey(const std::string& policy);
};

#endif // MODULECONFIGFILEHANDLER_H
