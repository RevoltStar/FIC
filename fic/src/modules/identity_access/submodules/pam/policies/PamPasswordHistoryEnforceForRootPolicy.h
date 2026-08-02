#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_ENFORCE_FOR_ROOT_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_ENFORCE_FOR_ROOT_POLICY_H

#include "modules/identity_access/submodules/pam/PamOptionPolicy.h"

class PamPasswordHistoryEnforceForRootPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordHistoryEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_ENFORCE_FOR_ROOT_POLICY_H
