#ifndef FIC_PAM_DENY_EMPTY_PASSWORD_LOGIN_POLICY_H
#define FIC_PAM_DENY_EMPTY_PASSWORD_LOGIN_POLICY_H

#include "modules/identity_access/pam/PamPolicy.h"
#include "platform/PlatformProfile.h"

class PamDenyEmptyPasswordLoginPolicy final : public PamPolicy {
public:
    explicit PamDenyEmptyPasswordLoginPolicy(fic::platform::PamPlatformConfig platform);

private:
    bool applyPam(const std::string& expectedValue) override;

    fic::platform::PamPlatformConfig platform_;
};
#endif
