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
        if (status.state == fic::identity::pam::PamTopologyState::Broken) {
            log("PAM topology is broken: " +
                    (status.detail.empty() ? error : status.detail),
                logLevel::ERROR);
        } else if (status.state ==
                   fic::identity::pam::PamTopologyState::Unavailable) {
            log("PAM topology is unavailable: " +
                    (status.detail.empty() ? error : status.detail),
                logLevel::ERROR);
        } else {
            log("PAM topology inspection failed: " + error,
                logLevel::ERROR);
        }
        return false;
    }

    bool activated = false;
    switch (status.state) {
    case fic::identity::pam::PamTopologyState::Enabled:
        break;
    case fic::identity::pam::PamTopologyState::Disabled:
        if (!manager->canEnable(error)) {
            log("PAM topology cannot be activated: " + error,
                logLevel::ERROR);
            return false;
        }
        if (!manager->enable(error)) {
            log("PAM topology activation failed: " + error,
                logLevel::ERROR);
            return false;
        }
        activated = true;
        status = {};
        if (!manager->inspect(status, error)) {
            log("PAM topology activation succeeded but ownership/state "
                "verification failed: " +
                    (status.detail.empty() ? error : status.detail),
                logLevel::ERROR);
            return false;
        }
        if (status.state != fic::identity::pam::PamTopologyState::Enabled) {
            log("PAM topology activation succeeded but ownership/state "
                "verification did not report enabled topology: " +
                    status.detail,
                logLevel::ERROR);
            return false;
        }
        break;
    case fic::identity::pam::PamTopologyState::Broken:
        log("PAM topology is broken: " + status.detail,
            logLevel::ERROR);
        return false;
    case fic::identity::pam::PamTopologyState::Unavailable:
        log("PAM topology is unavailable: " + status.detail,
            logLevel::ERROR);
        return false;
    }

    fic::identity::pam::PamCapabilityVerification verification;
    if (!verifyFresh(*capability, *services, verification)) {
        log(std::string(activated
                ? "PAM topology activation succeeded but capability "
                  "structural verification failed; manual/native recovery "
                  "may be required: "
                : "PAM topology is enabled but capability structural "
                  "verification failed: ") +
                fic::identity::pam::formatPamCapabilityVerification(
                    verification),
            logLevel::ERROR);
        return false;
    }
    log(activated
            ? "PAM capability topology was activated and structurally verified"
            : "PAM capability topology is enabled and structurally verified",
        logLevel::INFO);
    return true;
}
