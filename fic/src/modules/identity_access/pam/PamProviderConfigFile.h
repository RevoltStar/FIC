#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_CONFIG_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_CONFIG_FILE_H

#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"

#include <filesystem>
#include <string>

namespace fic::identity::pam {

class PamProviderConfigFile {
public:
    static bool hasExpectedState(
        const PamProviderDescriptor& provider,
        const PamProviderPolicyBinding& binding,
        const std::filesystem::path& path,
        const std::string& expectedValue,
        bool expectedFlagEnabled,
        std::string& error);

    static bool setExpectedState(
        const PamProviderDescriptor& provider,
        const PamProviderPolicyBinding& binding,
        const std::filesystem::path& path,
        const std::string& expectedValue,
        bool expectedFlagEnabled,
        std::string& error,
        PamOptionFile::Writer writer = {});

    static bool verifyNoActiveDirectives(
        const PamProviderDescriptor& provider,
        const std::filesystem::path& path,
        const std::vector<std::string>& directives,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_CONFIG_FILE_H
