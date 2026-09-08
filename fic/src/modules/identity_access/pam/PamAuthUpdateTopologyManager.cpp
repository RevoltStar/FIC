#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <chrono>
#include <utility>

namespace fic::identity::pam {
namespace {

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "pam-auth-update timed out";
    }
    return "pam-auth-update exited with code " +
        std::to_string(result.exitCode) +
        (result.standardError.empty() ? "" : ": " + result.standardError);
}

} // namespace

PamAuthUpdateTopologyManager::PamAuthUpdateTopologyManager(
    fic::platform::PamPlatformConfig platformConfig,
    fic::platform::PamCapabilityConfig capability,
    std::vector<std::string> services,
    const fic::platform::PlatformExecutableResolver& executables,
    PamAuthUpdateTopologyManagerOptions options)
    : platformConfig_(std::move(platformConfig)),
      capability_(std::move(capability)),
      services_(std::move(services)),
      executables_(executables),
      options_(std::move(options)) {
    if (!options_.runner) {
        options_.runner = VerifiedProcessExecutor::execute;
    }
}

bool PamAuthUpdateTopologyManager::inspect(PamTopologyStatus& status,
                                            std::string& error) {
    PamConfiguration configuration(platformConfig_);
    PamCapabilityVerification verification;
    if (PamCapabilityVerifier::verify(
            configuration, platformConfig_, services_, capability_.capability,
            capability_.provider, verification,
            PamCapabilityVerificationMode::Structural)) {
        status = {PamTopologyState::Enabled, true, {}};
        error.clear();
        return true;
    }
    status.manageable = true;
    status.detail = formatPamCapabilityVerification(verification);
    if (verification.state == PamEnforcementState::Missing ||
        verification.state == PamEnforcementState::Inactive) {
        status.state = PamTopologyState::Disabled;
        error.clear();
        return true;
    }
    status.state = PamTopologyState::Broken;
    error = status.detail;
    return false;
}

bool PamAuthUpdateTopologyManager::canEnable(std::string& error) const {
    if (capability_.topology !=
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate ||
        capability_.activationIdentifiers.empty()) {
        error = "PAM capability has no pam-auth-update activation recipe";
        return false;
    }
    std::filesystem::path executable;
    return executables_.resolve(
        fic::platform::ExecutableId::PamAuthUpdate, executable, error);
}

bool PamAuthUpdateTopologyManager::enable(std::string& error) {
    std::filesystem::path executable;
    if (!canEnable(error) || !executables_.resolve(
            fic::platform::ExecutableId::PamAuthUpdate, executable, error)) {
        return false;
    }
    std::vector<std::string> arguments = {"--enable"};
    arguments.insert(arguments.end(), capability_.activationIdentifiers.begin(),
                     capability_.activationIdentifiers.end());
    ProcessOptions processOptions;
    processOptions.timeout = std::chrono::seconds(30);
    processOptions.clearEnvironment = true;
    const ProcessResult result = options_.runner(
        executable.string(), arguments, processOptions);
    if (!result.success()) {
        error = processFailure(result);
        return false;
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::disable(std::string& error) {
    error = "automatic PAM topology deactivation is not supported";
    return false;
}

} // namespace fic::identity::pam
