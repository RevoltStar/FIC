#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_MIN_LENGTH_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_MIN_LENGTH_POLICY_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamPasswordMinLengthPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordMinLengthPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_MIN_LENGTH_POLICY_H
