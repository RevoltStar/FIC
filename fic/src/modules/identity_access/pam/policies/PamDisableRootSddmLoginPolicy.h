#ifndef FIC_PAM_DISABLE_ROOT_SDDM_LOGIN_POLICY_H
#define FIC_PAM_DISABLE_ROOT_SDDM_LOGIN_POLICY_H

#include "modules/identity_access/pam/PamPolicy.h"
#include "platform/PlatformProfile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <functional>

class PamDisableRootSddmLoginPolicy final : public PamPolicy {
public:
    using Writer = std::function<bool(
        const std::string&,
        const std::string&,
        const AtomicWriteOptions&,
        std::string*)>;

    explicit PamDisableRootSddmLoginPolicy(
        fic::platform::PamPlatformConfig platform,
        Writer writer = {});

protected:
    bool applyPam(const std::string& expectedValue) override;

private:
    fic::platform::PamPlatformConfig platform_;
    Writer writer_;
};

#endif // FIC_PAM_DISABLE_ROOT_SDDM_LOGIN_POLICY_H
