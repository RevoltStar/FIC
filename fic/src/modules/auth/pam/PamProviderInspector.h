#ifndef FIC_AUTH_PAM_PROVIDER_INSPECTOR_H
#define FIC_AUTH_PAM_PROVIDER_INSPECTOR_H

#include "modules/auth/pam/PamConfiguration.h"

#include <optional>
#include <string>
#include <vector>

namespace fic::auth {

enum class PamCapability {
    AuthenticationLockout,
    PasswordQuality,
    PasswordHistory
};

enum class PamProviderKind {
    PamFaillock,
    PamTally2,
    PamTally,
    PamPwquality,
    PamPasswdqc,
    PamCracklib,
    PamPwhistory,
    PamUnixHistory
};

struct PamProviderInspection {
    PamProviderKind provider = PamProviderKind::PamFaillock;
    std::vector<std::string> services;
    std::vector<PamRule> providerRules;
    std::vector<std::filesystem::path> configurationFiles;
};

class PamProviderInspector {
public:
    static bool inspect(PamConfiguration& configuration,
                        const std::vector<std::string>& candidateServices,
                        PamCapability capability,
                        PamProviderKind expectedProvider,
                        PamProviderInspection& inspection,
                        std::string& error);

    static bool verifyOptionOverrides(
        const PamProviderInspection& inspection,
        const std::string& expectedConfigPath,
        const std::string& option,
        const std::string& expectedValue,
        std::string& error);

    static bool verifyProviderFiles(
        const PamProviderInspection& inspection,
        const std::vector<std::filesystem::path>& moduleDirectories,
        std::string& error);

    static bool verifyConfigurationFiles(
        const PamProviderInspection& inspection,
        std::string& error);

    static std::optional<std::string> argumentValue(
        const PamRule& rule,
        const std::string& option);
};

std::string pamProviderName(PamProviderKind provider);

} // namespace fic::auth

#endif // FIC_AUTH_PAM_PROVIDER_INSPECTOR_H
