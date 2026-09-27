#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_ENFORCE_FOR_ROOT_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_ENFORCE_FOR_ROOT_POLICY_H

#include "modules/identity_access/pam/policies/PamPasswordHistoryOptionPolicy.h"

// Step 6 platform-support contract: the bare `enforce_for_root` module
// argument is only rendered on platforms whose pwhistory provider is
// evidence-proven to accept it (platform capability metadata; see the
// platform profiles). On platforms without that evidence the policy stays
// ReadOnly and is never production-mutable there — the token support is
// never assumed from the writer's rendering ability alone.
class PamPasswordHistoryEnforceForRootPolicy final
    : public PamPasswordHistoryOptionPolicy {
public:
    explicit PamPasswordHistoryEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig,
        PasswordCoordinatorFactory passwordCoordinatorFactory = {});
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_ENFORCE_FOR_ROOT_POLICY_H
