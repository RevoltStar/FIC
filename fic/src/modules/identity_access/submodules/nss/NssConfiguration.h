#ifndef FIC_IDENTITY_ACCESS_NSS_CONFIGURATION_H
#define FIC_IDENTITY_ACCESS_NSS_CONFIGURATION_H

#include "modules/identity_access/configuration/PreparedFileChange.h"
#include "modules/identity_access/submodules/composite/ConfigurationParticipant.h"

#include <optional>
#include <string>
#include <vector>

namespace fic::identity::nss {

struct NssAction {
    bool negated = false;
    std::string status;
    std::string result;
};

struct NssService {
    std::string name;
    std::vector<NssAction> actions;
};

struct NssDatabaseSetting {
    std::string database;
    std::vector<NssService> services;
};

struct NssConfigurationOptions {
    SecureConfigurationFileOptions mainFile;

    static NssConfigurationOptions production();
};

class NssConfiguration {
public:
    explicit NssConfiguration(NssConfigurationOptions options);

    bool tryGetServices(
        const std::string& database,
        std::optional<std::vector<NssService>>& services,
        std::string& error) const;

    ConfigurationPreparationResult prepareSetServices(
        const std::string& database,
        const std::vector<NssService>& services) const;

    ConfigurationPreparationResult prepareSetDatabases(
        const std::vector<NssDatabaseSetting>& settings) const;

    bool setServices(const std::string& database,
                     const std::vector<NssService>& services,
                     std::string& error) const;

    bool setDatabases(const std::vector<NssDatabaseSetting>& settings,
                      std::string& error) const;

private:
    NssConfigurationOptions options_;
};

} // namespace fic::identity::nss

#endif // FIC_IDENTITY_ACCESS_NSS_CONFIGURATION_H
