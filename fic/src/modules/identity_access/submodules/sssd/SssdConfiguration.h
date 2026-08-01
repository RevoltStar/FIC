#ifndef FIC_IDENTITY_ACCESS_SSSD_CONFIGURATION_H
#define FIC_IDENTITY_ACCESS_SSSD_CONFIGURATION_H

#include "modules/identity_access/configuration/PreparedFileChange.h"
#include "modules/identity_access/submodules/composite/ConfigurationParticipant.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fic::identity::sssd {

struct SssdConfigurationOptions {
    SecureConfigurationFileOptions mainFile;
    std::vector<std::filesystem::path> snippetDirectories;

    static SssdConfigurationOptions production();
};

struct SssdSetting {
    std::string section;
    std::string option;
    std::string value;
};

class SssdConfiguration {
public:
    explicit SssdConfiguration(SssdConfigurationOptions options);

    bool tryGetEffectiveValue(
        const std::string& section,
        const std::string& option,
        std::optional<std::string>& value,
        std::string& error) const;

    ConfigurationPreparationResult prepareSetValue(
        const std::string& section,
        const std::string& option,
        const std::string& value) const;

    ConfigurationPreparationResult prepareSetValues(
        const std::vector<SssdSetting>& settings) const;

    bool setValue(const std::string& section,
                  const std::string& option,
                  const std::string& value,
                  std::string& error) const;

    bool setValues(const std::vector<SssdSetting>& settings,
                   std::string& error) const;

private:
    SssdConfigurationOptions options_;
};

} // namespace fic::identity::sssd

#endif // FIC_IDENTITY_ACCESS_SSSD_CONFIGURATION_H
