#ifndef FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H

#include "modules/identity_access/pam/PamPolicy.h"
#include "platform/PlatformProfile.h"

#include <string>

class PamOptionPolicy : public PamPolicy {
public:
    ~PamOptionPolicy() override = default;

protected:
    PamOptionPolicy(
        fic::platform::PamPlatformConfig platformConfig,
        fic::platform::PamPolicyFeature feature);

    bool applyPam(const std::string& expectedValue) override;

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::platform::PamPolicyFeature feature_;
};

#endif // FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H
