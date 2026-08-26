#ifndef FIC_REQUIRED_PAM_ENFORCEMENT_POLICY_H
#define FIC_REQUIRED_PAM_ENFORCEMENT_POLICY_H

#include "modules/identity_access/pam/PamPolicy.h"
#include "platform/PlatformProfile.h"

class RequiredPamEnforcementPolicy final : public PamPolicy {
public:
    explicit RequiredPamEnforcementPolicy(
        const fic::platform::PamPlatformConfig& platformConfig);

private:
    bool applyPam(const std::string& expectedValue) override;

    fic::platform::PamPlatformConfig platformConfig_;
};

#endif // FIC_REQUIRED_PAM_ENFORCEMENT_POLICY_H
