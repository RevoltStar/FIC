#ifndef FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_UNLOCK_TIME_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_UNLOCK_TIME_POLICY_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamFailedAuthenticationUnlockTimePolicy final : public PamOptionPolicy {
public:
    explicit PamFailedAuthenticationUnlockTimePolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_UNLOCK_TIME_POLICY_H
