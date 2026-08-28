#ifndef FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H

#include "modules/identity_access/pam/PamPolicy.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "platform/PlatformProfile.h"

#include <cstddef>
#include <string>
#include <vector>

class PamOptionPolicy : public PamPolicy {
public:
    ~PamOptionPolicy() override = default;

protected:
    PamOptionPolicy(
        fic::platform::PamPlatformConfig platformConfig,
        fic::platform::PamPolicyFeature feature);

    bool applyPam(const std::string& expectedValue) override;

    virtual bool verifyPostMutationPamState(
        const fic::platform::PamCapabilityConfig& capability,
        const std::vector<std::string>& services,
        const fic::identity::pam::PamProviderPolicyBinding& binding,
        const std::string& nativeExpectedValue,
        bool expectedFlagEnabled,
        std::size_t& verifiedServiceCount,
        std::string& error) const;

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::platform::PamPolicyFeature feature_;
};

#endif // FIC_IDENTITY_ACCESS_PAM_OPTION_POLICY_H
