#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_INSPECTOR_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_INSPECTOR_H

#include "modules/identity_access/pam/PamConfiguration.h"

#include <optional>
#include <string>
#include <vector>

namespace fic::identity::pam {

using PamCapability = fic::platform::PamCapability;
using PamProviderKind = fic::platform::PamProviderKind;

struct PamProviderInspection {
    PamProviderKind provider = PamProviderKind::PamFaillock;
    std::vector<std::string> services;
    std::vector<PamRule> providerRules;
    std::vector<std::filesystem::path> configurationFiles;
};

enum class PamProviderInspectionFailure {
    None,
    Inactive,
    Conflicting,
    Broken
};

enum class PamProviderFileState {
    Missing,
    Untrusted,
    Trusted
};

class PamProviderInspector {
public:
    static bool inspect(PamConfiguration& configuration,
                        const std::vector<std::string>& candidateServices,
                        PamCapability capability,
                        PamProviderKind expectedProvider,
                        PamProviderInspection& inspection,
                        std::string& error,
                        PamProviderInspectionFailure* failure = nullptr);

    static PamProviderFileState inspectExpectedProviderFile(
        PamProviderKind provider,
        const std::vector<std::filesystem::path>& moduleDirectories,
        std::string& error);

    static bool verifyExternalConfigContract(
        const PamProviderInspection& inspection,
        const std::string& expectedConfigPath,
        std::string& error);

    static bool verifyOptionOverrides(
        const PamProviderInspection& inspection,
        const std::string& expectedConfigPath,
        const std::string& option,
        const std::string& expectedValue,
        std::string& error);

    static bool verifyFlagOverrides(
        const PamProviderInspection& inspection,
        const std::string& expectedConfigPath,
        const std::string& flag,
        bool expectedEnabled,
        std::string& error,
        const std::vector<std::string>&
            conflictingOptionsWhenDisabled = {});

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

    static bool hasArgument(const PamRule& rule,
                            const std::string& argument);
};

std::string pamProviderName(PamProviderKind provider);
std::string pamProviderModuleName(PamProviderKind provider);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_INSPECTOR_H
