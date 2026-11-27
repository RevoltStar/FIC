#ifndef FIC_PAM_DISABLE_NOPASSWDLOGIN_POLICY_H
#define FIC_PAM_DISABLE_NOPASSWDLOGIN_POLICY_H

#include "modules/identity_access/pam/PamPolicy.h"
#include "platform/PlatformProfile.h"

class PamDisableNopasswdloginPolicy final : public PamPolicy {
public:
    explicit PamDisableNopasswdloginPolicy(fic::platform::PamPlatformConfig platform);

protected:
    bool applyPam(const std::string& expectedValue) override;

private:
    fic::platform::PamPlatformConfig platform_;
};
#endif
