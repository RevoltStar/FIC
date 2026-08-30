#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_MODULE_ARGUMENTS_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_MODULE_ARGUMENTS_H

#include "modules/identity_access/pam/PamConfigFileTransaction.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderInspector.h"

namespace fic::identity::pam {

// Dispatch boundary for capabilities whose managed state lives in an existing
// parsed PAM module invocation instead of a provider configuration file.
class PamProviderModuleArguments {
public:
    static bool uniqueRule(const PamProviderInspection& inspection,
                           PamRule& rule,
                           std::string& error);

    static bool hasExpectedState(
        const PamProviderInspection& inspection,
        const PamProviderPolicyBinding& binding,
        const std::string& expectedValue,
        bool expectedFlagEnabled,
        std::string& error);

    static bool setExpectedState(
        PamProviderKind provider,
        const PamRule& rule,
        const PamProviderPolicyBinding& binding,
        const std::string& expectedValue,
        bool expectedFlagEnabled,
        PamConfigFileSnapshot& snapshot,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_MODULE_ARGUMENTS_H
