#ifndef FIC_IDENTITY_ACCESS_KERBEROS_CONFIGURATION_H
#define FIC_IDENTITY_ACCESS_KERBEROS_CONFIGURATION_H

#include "modules/identity_access/configuration/PreparedFileChange.h"
#include "modules/identity_access/submodules/composite/ConfigurationParticipant.h"

#include <optional>
#include <string>
#include <vector>

namespace fic::identity::kerberos {

struct KerberosConfigurationOptions {
    SecureConfigurationFileOptions mainFile;
    std::size_t maximumIncludeDepth = 16;
    std::size_t maximumFiles = 256;

    static KerberosConfigurationOptions production();
};

struct KerberosScalarSetting {
    std::string section;
    std::string relation;
    std::string value;
};

class KerberosConfiguration {
public:
    explicit KerberosConfiguration(KerberosConfigurationOptions options);

    bool tryGetScalarValue(
        const std::string& section,
        const std::string& relation,
        std::optional<std::string>& value,
        std::string& error) const;

    ConfigurationPreparationResult prepareSetScalar(
        const std::string& section,
        const std::string& relation,
        const std::string& value) const;

    ConfigurationPreparationResult prepareSetScalars(
        const std::vector<KerberosScalarSetting>& settings) const;

    bool setScalar(const std::string& section,
                   const std::string& relation,
                   const std::string& value,
                   std::string& error) const;

    bool setScalars(const std::vector<KerberosScalarSetting>& settings,
                    std::string& error) const;

private:
    KerberosConfigurationOptions options_;
};

} // namespace fic::identity::kerberos

#endif // FIC_IDENTITY_ACCESS_KERBEROS_CONFIGURATION_H
