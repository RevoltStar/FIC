#include "modules/identity_access/pam/PamProviderModuleArguments.h"

#include "modules/identity_access/pam/PamPwhistoryArguments.h"

namespace fic::identity::pam {
namespace {

bool supported(PamProviderKind provider, std::string& error) {
    if (provider == PamProviderKind::PamPwhistory) {
        return true;
    }
    error = "provider does not support PAM module-argument configuration: " +
        pamProviderName(provider);
    return false;
}

} // namespace

bool PamProviderModuleArguments::uniqueRule(
    const PamProviderInspection& inspection,
    PamRule& rule,
    std::string& error) {
    return supported(inspection.provider, error) &&
        PamPwhistoryArguments::uniqueRule(inspection, rule, error);
}

bool PamProviderModuleArguments::hasExpectedState(
    const PamProviderInspection& inspection,
    const PamProviderPolicyBinding& binding,
    const std::string& expectedValue,
    bool expectedFlagEnabled,
    std::string& error) {
    return supported(inspection.provider, error) &&
        PamPwhistoryArguments::hasExpectedState(
            inspection, binding, expectedValue, expectedFlagEnabled, error);
}

bool PamProviderModuleArguments::setExpectedState(
    PamProviderKind provider,
    const PamRule& rule,
    const PamProviderPolicyBinding& binding,
    const std::string& expectedValue,
    bool expectedFlagEnabled,
    PamConfigFileSnapshot& snapshot,
    std::string& error) {
    return supported(provider, error) &&
        PamPwhistoryArguments::setExpectedState(
            rule, binding, expectedValue, expectedFlagEnabled, snapshot,
            error);
}

} // namespace fic::identity::pam
