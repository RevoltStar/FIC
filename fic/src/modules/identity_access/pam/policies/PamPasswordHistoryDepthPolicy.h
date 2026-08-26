#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_DEPTH_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_DEPTH_POLICY_H

#include "modules/identity_access/pam/PamOptionPolicy.h"

class PamPasswordHistoryDepthPolicy final : public PamOptionPolicy {
public:
    explicit PamPasswordHistoryDepthPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_DEPTH_POLICY_H
