#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_DEPTH_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_DEPTH_POLICY_H

#include "modules/identity_access/pam/policies/PamPasswordHistoryOptionPolicy.h"

// Authoritative policy contract of password_history_depth: the single
// source of truth for the policy type value AND the joint desired-state
// reader (Step 6). The default is the POLICY default, never a hardcoded
// topology value.
inline constexpr unsigned kPasswordHistoryDepthMin = 1;
inline constexpr unsigned kPasswordHistoryDepthMax = 50;
inline constexpr unsigned kPasswordHistoryDepthDefault = 5;

class PamPasswordHistoryDepthPolicy final
    : public PamPasswordHistoryOptionPolicy {
public:
    explicit PamPasswordHistoryDepthPolicy(
        const fic::platform::PamPlatformConfig& platformConfig,
        PasswordCoordinatorFactory passwordCoordinatorFactory = {});
};

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_HISTORY_DEPTH_POLICY_H
