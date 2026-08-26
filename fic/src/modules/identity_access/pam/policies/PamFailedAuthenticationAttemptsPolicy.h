#ifndef FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_ATTEMPTS_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_ATTEMPTS_POLICY_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamFailedAuthenticationAttemptsPolicy final : public PamOptionPolicy {
public:
    explicit PamFailedAuthenticationAttemptsPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_ATTEMPTS_POLICY_H
