#ifndef FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_COUNTING_PERIOD_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_COUNTING_PERIOD_POLICY_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamFailedAuthenticationCountingPeriodPolicy final : public PamOptionPolicy {
public:
    explicit PamFailedAuthenticationCountingPeriodPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_FAILED_AUTHENTICATION_COUNTING_PERIOD_POLICY_H
