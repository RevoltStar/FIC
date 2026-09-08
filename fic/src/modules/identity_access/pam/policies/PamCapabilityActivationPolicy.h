#ifndef FIC_PAM_CAPABILITY_ACTIVATION_POLICY_H
#define FIC_PAM_CAPABILITY_ACTIVATION_POLICY_H

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamPolicy.h"
#include "modules/identity_access/pam/PamTopologyManager.h"

#include <functional>
#include <memory>
#include <stdexcept>

inline const char* pamCapabilityActivationPolicyName(
    fic::platform::PamCapability capability) {
    switch (capability) {
    case fic::platform::PamCapability::AuthenticationLockout:
        return "enable_authentication_lockout";
    case fic::platform::PamCapability::PasswordHistory:
        return "enable_password_history";
    case fic::platform::PamCapability::PasswordQuality:
        return "enable_password_quality";
    }
    throw std::logic_error("unsupported PAM capability activation policy");
}

struct PamCapabilityActivationPolicyOptions {
    using ManagerFactory = std::function<std::unique_ptr<
        fic::identity::pam::PamTopologyManager>(
            const fic::platform::PamCapabilityConfig&,
            const std::vector<std::string>&,
            std::string&)>;
    using Verifier = std::function<bool(
        const fic::platform::PamCapabilityConfig&,
        const std::vector<std::string>&,
        fic::identity::pam::PamCapabilityVerification&)>;

    ManagerFactory managerFactory;
    Verifier verifier;
};

class PamCapabilityActivationPolicy final : public PamPolicy {
public:
    PamCapabilityActivationPolicy(
        fic::platform::PamPlatformConfig platformConfig,
        fic::platform::PamCapability capability,
        PamCapabilityActivationPolicyOptions options = {});

    fic::platform::PamCapability capability() const { return capability_; }

protected:
    bool applyPam(const std::string& expectedValue) override;

private:
    fic::platform::PamPlatformConfig platformConfig_;
    fic::platform::PamCapability capability_;
    PamCapabilityActivationPolicyOptions options_;

    bool verifyFresh(
        const fic::platform::PamCapabilityConfig& capability,
        const std::vector<std::string>& services,
        fic::identity::pam::PamCapabilityVerification& verification) const;
};

#endif
