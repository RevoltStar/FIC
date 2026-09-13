#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <chrono>
#include <set>
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

bool PamAuthUpdateTopologyManager::resolveExecutable(
    std::filesystem::path& executable,
    std::string& error) const {
    return executables_.resolve(
        fic::platform::ExecutableId::PamAuthUpdate, executable, error);
}

bool PamAuthUpdateTopologyManager::inspect(PamTopologyStatus& status,
                                            std::string& error) {
    PamConfiguration configuration(platformConfig_);
    PamCapabilityVerification verification;
    if (PamCapabilityVerifier::verify(
            configuration, platformConfig_, services_, capability_.capability,
            capability_.provider, verification,
            PamCapabilityVerificationMode::Structural)) {
        status = {PamTopologyState::Enabled, true, {}, {}};
        if (capability_.capability ==
            fic::platform::PamCapability::AuthenticationLockout) {
            PamEffectiveStack authStack;
            std::string strategyError;
            std::optional<fic::platform::PamFaillockStrategy> strategy;
            if (!configuration.buildEffectiveStack(
                    services_.front(), PamManagementGroup::Auth, authStack,
                    strategyError)) {
                status = {PamTopologyState::Broken, true, {}, strategyError};
                error = strategyError;
                return false;
            }
            strategy = detectPamFaillockStrategy(authStack, strategyError);
            if (!strategy.has_value()) {
                status = {PamTopologyState::Broken, true, {},
                    "cannot prove the active pam_faillock strategy: " +
                        strategyError};
                error = status.detail;
                return false;
            }
            status.activeStrategy = strategy;
        }
        error.clear();
        return true;
    }
    status.manageable = true;
    status.detail = formatPamCapabilityVerification(verification);
    if (verification.state == PamEnforcementState::Missing ||
        verification.state == PamEnforcementState::Inactive) {
        status.state = PamTopologyState::Disabled;
        status.activeStrategy.reset();
        error.clear();
        return true;
    }
    status.state = PamTopologyState::Broken;
    status.activeStrategy.reset();
    error = status.detail;
    return false;
}

std::vector<std::string>
PamAuthUpdateTopologyManager::knownActivationIdentifiers() const {
    std::vector<std::string> identifiers;
    for (const auto& activation : capability_.strategyActivations) {
        for (const std::string& identifier :
             activation.activationIdentifiers) {
            if (std::find(identifiers.begin(), identifiers.end(),
                    identifier) == identifiers.end()) {
                identifiers.push_back(identifier);
            }
        }
    }
    for (const std::string& identifier : capability_.activationIdentifiers) {
        if (std::find(identifiers.begin(), identifiers.end(), identifier) ==
            identifiers.end()) {
            identifiers.push_back(identifier);
        }
    }
    return identifiers;
}

const std::vector<std::string>*
PamAuthUpdateTopologyManager::strategyActivationIdentifiers(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) const {
    for (const auto& activation : capability_.strategyActivations) {
        if (activation.strategy == strategy) {
            return &activation.activationIdentifiers;
        }
    }
    error = "platform profile declares no pam-auth-update activation "
        "recipe for pam_faillock strategy " +
        fic::platform::pamFaillockStrategyName(strategy);
    return nullptr;
}

bool PamAuthUpdateTopologyManager::runPamAuthUpdate(
    const std::string& mode,
    const std::vector<std::string>& identifiers,
    std::string& error) {
    std::filesystem::path executable;
    if (!resolveExecutable(executable, error)) {
        return false;
    }
    std::vector<std::string> arguments = {mode};
    arguments.insert(arguments.end(), identifiers.begin(), identifiers.end());
    ProcessOptions processOptions;
    processOptions.timeout = std::chrono::seconds(30);
    processOptions.clearEnvironment = true;
    const ProcessResult result = options_.runner(
        executable.string(), arguments, processOptions);
    if (!result.success()) {
        error = "pam-auth-update " + mode + " failed: " +
            processFailure(result);
        return false;
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::canEnable(std::string& error) const {
    if (capability_.topology !=
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate ||
        (capability_.activationIdentifiers.empty() &&
            capability_.strategyActivations.empty())) {
        error = "PAM capability has no pam-auth-update activation recipe";
        return false;
    }
    std::filesystem::path executable;
    return resolveExecutable(executable, error);
}

bool PamAuthUpdateTopologyManager::enable(std::string& error) {
    if (!capability_.supportedFaillockStrategies.empty()) {
        return enableStrategy(capability_.defaultFaillockStrategy, error);
    }
    const std::vector<std::string>& identifiers =
        capability_.activationIdentifiers;
    if (identifiers.empty()) {
        error = "PAM capability has no pam-auth-update activation recipe";
        return false;
    }
    return runPamAuthUpdate("--enable", identifiers, error);
}

bool PamAuthUpdateTopologyManager::disable(std::string& error) {
    error = "automatic PAM topology deactivation is not supported";
    return false;
}

bool PamAuthUpdateTopologyManager::canEnableStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) const {
    if (capability_.capability !=
        fic::platform::PamCapability::AuthenticationLockout) {
        error = "pam_faillock strategies apply only to the authentication "
            "lockout capability";
        return false;
    }
    if (!fic::platform::supportsPamFaillockStrategy(capability_, strategy)) {
        error = "pam_faillock strategy " +
            fic::platform::pamFaillockStrategyName(strategy) +
            " is not supported by this platform profile";
        return false;
    }
    if (strategyActivationIdentifiers(strategy, error) == nullptr) {
        return false;
    }
    std::filesystem::path executable;
    return resolveExecutable(executable, error);
}

bool PamAuthUpdateTopologyManager::enableStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) {
    if (!canEnableStrategy(strategy, error)) {
        return false;
    }
    const std::vector<std::string>* desiredIdentifiers =
        strategyActivationIdentifiers(strategy, error);
    if (desiredIdentifiers == nullptr) {
        return false;
    }

    // Idempotency: the requested strategy is already active.
    PamTopologyStatus current;
    if (!inspect(current, error)) {
        return false;
    }
    if (current.state == PamTopologyState::Enabled &&
        current.activeStrategy == strategy) {
        error.clear();
        return true;
    }

    const std::optional<fic::platform::PamFaillockStrategy> priorStrategy =
        current.state == PamTopologyState::Enabled
            ? current.activeStrategy
            : std::nullopt;

    // Reset the faillock profile selection so the regenerated stacks
    // contain exactly the requested strategy's recipes.
    std::vector<std::string> toDisable;
    for (const std::string& identifier : knownActivationIdentifiers()) {
        if (std::find(desiredIdentifiers->begin(), desiredIdentifiers->end(),
                identifier) == desiredIdentifiers->end()) {
            toDisable.push_back(identifier);
        }
    }
    if (!toDisable.empty() &&
        !runPamAuthUpdate("--disable", toDisable, error)) {
        return false;
    }

    if (!runPamAuthUpdate("--enable", *desiredIdentifiers, error)) {
        // Rollback: restore the previously active strategy when the
        // activation of the requested one failed after the reset.
        if (priorStrategy.has_value()) {
            const std::vector<std::string>* rollbackIdentifiers =
                strategyActivationIdentifiers(*priorStrategy, error);
            if (rollbackIdentifiers != nullptr) {
                std::string rollbackError;
                if (!runPamAuthUpdate("--enable", *rollbackIdentifiers,
                        rollbackError)) {
                    error += "; rollback to strategy " +
                        fic::platform::pamFaillockStrategyName(
                            *priorStrategy) + " failed: " + rollbackError;
                }
            }
        }
        return false;
    }

    // Postcondition: re-read and verify the requested strategy is active.
    PamTopologyStatus after;
    if (!inspect(after, error)) {
        error = "pam-auth-update strategy activation succeeded but the "
            "topology verification failed: " + error;
        return false;
    }
    if (after.state != PamTopologyState::Enabled ||
        after.activeStrategy != strategy) {
        error = "pam-auth-update strategy activation did not produce the "
            "requested strategy " +
            fic::platform::pamFaillockStrategyName(strategy) +
            (after.detail.empty() ? "" : ": " + after.detail);
        return false;
    }
    error.clear();
    return true;
}

} // namespace fic::identity::pam
