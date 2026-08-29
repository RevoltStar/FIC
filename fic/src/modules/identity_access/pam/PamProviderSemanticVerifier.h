#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_SEMANTIC_VERIFIER_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_SEMANTIC_VERIFIER_H

#include "modules/identity_access/pam/PamProviderInspector.h"

namespace fic::identity::pam {

enum class PamProviderSemanticFailure {
    None,
    Broken,
    Ineffective
};

class PamProviderSemanticVerifier {
public:
    static bool verifyCapability(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        bool requireSecurityEnforcement,
        PamProviderSemanticFailure& failure,
        std::string& error);

    static bool verifyOption(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        const std::string& option,
        const std::string& expectedValue,
        std::string& error);

    static bool verifyFlag(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        const std::string& flag,
        bool expectedEnabled,
        const std::vector<std::string>& conflictingOptionsWhenDisabled,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_SEMANTIC_VERIFIER_H
