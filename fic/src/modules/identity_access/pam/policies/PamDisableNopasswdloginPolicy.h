#ifndef FIC_PAM_DISABLE_NOPASSWDLOGIN_POLICY_H
#define FIC_PAM_DISABLE_NOPASSWDLOGIN_POLICY_H

#include "modules/identity_access/pam/PamPolicy.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"

#include <fic/core/process/ProcessExecutor.h>

#include <functional>

class PamDisableNopasswdloginPolicy final : public PamPolicy {
public:
    using Runner = std::function<ProcessResult(
        const std::string&, const std::vector<std::string>&)>;

    PamDisableNopasswdloginPolicy(
        fic::platform::PamPlatformConfig platform,
        const fic::platform::PlatformExecutableResolver& executables,
        Runner runner = {});

protected:
    bool applyPam(const std::string& expectedValue) override;

private:
    fic::platform::PamPlatformConfig platform_;
    const fic::platform::PlatformExecutableResolver& executables_;
    Runner runner_;
};

#endif
