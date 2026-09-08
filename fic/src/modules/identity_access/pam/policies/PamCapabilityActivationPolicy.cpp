#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <fic/policy/PolicyTypeValue.h>

#include <utility>

PamCapabilityActivationPolicy::PamCapabilityActivationPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::platform::PamCapability capability,
    PamCapabilityActivationPolicyOptions options)
    : PamPolicy(),
      platformConfig_(std::move(platformConfig)),
      capability_(capability),
      options_(std::move(options)) {
    policyName = pamCapabilityActivationPolicyName(capability_);
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
}

bool PamCapabilityActivationPolicy::verifyFresh(
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    fic::identity::pam::PamCapabilityVerification& verification) const {
    if (options_.verifier) {
        return options_.verifier(capability, services, verification);
    }
    fic::identity::pam::PamConfiguration configuration(platformConfig_);
    return fic::identity::pam::PamCapabilityVerifier::verify(
        configuration, platformConfig_, services, capability.capability,
        capability.provider, verification,
        fic::identity::pam::PamCapabilityVerificationMode::Structural);
}

bool PamCapabilityActivationPolicy::applyPam(
    const std::string& expectedValue) {
    if (expectedValue != "ENABLE") {
        log("PAM capability activation value must be ENABLE", logLevel::ERROR);
        return false;
    }

    const fic::platform::PamCapabilityConfig* capability = nullptr;
    const std::vector<std::string>* services = nullptr;
    std::string error;
    if (!fic::identity::pam::resolveCapability(
            platformConfig_, capability_, capability, services, error)) {
        log("PAM activation platform composition failed: " + error,
            logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamCapabilityVerification verification;
    if (verifyFresh(*capability, *services, verification)) {
        log("PAM capability topology is already structurally active",
            logLevel::INFO);
        return true;
    }

    if (!options_.managerFactory) {
        log("PAM topology activation manager factory is unavailable",
            logLevel::ERROR);
        return false;
    }
    std::unique_ptr<fic::identity::pam::PamTopologyManager> manager =
        options_.managerFactory(*capability, *services, error);
    if (!manager) {
        log("Could not create PAM topology activation manager: " + error,
            logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamTopologyStatus status;
    if (!manager->inspect(status, error)) {
        log("PAM topology inspection failed: " + error, logLevel::ERROR);
        return false;
    }
    if (status.state != fic::identity::pam::PamTopologyState::Disabled) {
        log("PAM topology is not safely activatable: " + status.detail,
            logLevel::ERROR);
        return false;
    }
    if (!manager->canEnable(error)) {
        log("PAM topology cannot be activated: " + error, logLevel::ERROR);
        return false;
    }
    if (!manager->enable(error)) {
        log("PAM topology activation failed: " + error, logLevel::ERROR);
        return false;
    }

    verification = {};
    if (!verifyFresh(*capability, *services, verification)) {
        log("PAM topology activation command succeeded but resulting PAM "
            "topology verification failed; manual/native recovery may be "
            "required: " +
                fic::identity::pam::formatPamCapabilityVerification(
                    verification),
            logLevel::ERROR);
        return false;
    }
    log("PAM capability topology was activated and structurally verified",
        logLevel::INFO);
    return true;
}
