#ifndef FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_ENFORCE_FOR_ROOT_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_ENFORCE_FOR_ROOT_POLICY_H

#include "modules/identity_access/submodules/pam/PamOptionPolicy.h"

class PamFailedAuthenticationEnforceForRootPolicy final
    : public PamOptionPolicy {
public:
    explicit PamFailedAuthenticationEnforceForRootPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_ENFORCE_FOR_ROOT_POLICY_H
