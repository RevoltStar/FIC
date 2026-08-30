#ifndef FIC_IDENTITY_ACCESS_PAM_PWHISTORY_ARGUMENTS_H
#define FIC_IDENTITY_ACCESS_PAM_PWHISTORY_ARGUMENTS_H

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamConfigFileTransaction.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderInspector.h"

#include <optional>

namespace fic::identity::pam {

inline constexpr unsigned kLegacyPamPwhistoryDefaultRemember = 10;

struct PamPwhistoryArgumentState {
    std::optional<unsigned> rememberOverride;
    bool enforceForRoot = false;

    unsigned effectiveRemember() const {
        return rememberOverride.value_or(
            kLegacyPamPwhistoryDefaultRemember);
    }
};

class PamPwhistoryArguments {
public:
    static bool evaluate(const PamRule& rule,
                         PamPwhistoryArgumentState& state,
                         std::string& error);

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
        const PamRule& rule,
        const PamProviderPolicyBinding& binding,
        const std::string& expectedValue,
        bool expectedFlagEnabled,
        PamConfigFileSnapshot& snapshot,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PWHISTORY_ARGUMENTS_H
