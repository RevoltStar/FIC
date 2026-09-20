#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "rollback/DaemonMutationJournal.h"

#include <fic/policy/PolicyTypeValue.h>

#include <algorithm>
#include <optional>
#include <utility>
#include <vector>

namespace {

std::string supportedStrategyValues(
    const fic::platform::PamCapabilityConfig& capability) {
    std::string result;
    for (fic::platform::PamFaillockStrategy strategy :
         capability.supportedFaillockStrategies) {
        if (!result.empty()) {
            result += ", ";
        }
        result += fic::platform::pamFaillockStrategyName(strategy);
    }
    return result;
}

} // namespace

PamCapabilityActivationPolicy::PamCapabilityActivationPolicy(
    fic::platform::PamPlatformConfig platformConfig,
    fic::platform::PamCapability capability,
    PamCapabilityActivationPolicyOptions options)
    : PamPolicy(),
      platformConfig_(std::move(platformConfig)),
      capability_(capability),
      options_(std::move(options)) {
    policyName = pamCapabilityActivationPolicyName(capability_);
    if (capability_ != fic::platform::PamCapability::AuthenticationLockout) {
        policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
        return;
    }
    const fic::platform::PamCapabilityConfig* capabilityConfig =
        fic::identity::pam::capabilityConfig(platformConfig_, capability_);
    if (capabilityConfig == nullptr ||
        capabilityConfig->supportedFaillockStrategies.empty()) {
        // No strategy is supported on this platform profile: the policy is
        // unsupported here. It stays fail-closed (any apply attempt is
        // rejected with an explicit diagnostic) instead of pretending a
        // legacy fixed "ENABLE" topology exists. The daemon only registers
        // this policy when at least one strategy is declared.
        policyTypeValue = std::make_unique<FixedPolicyTypeValue>("DISABLED");
        return;
    }
    // The default strategy is presented first: PossibleListPolicyTypeValue
    // uses the first element as the default policy value.
    std::vector<std::string> possibleValues;
    const fic::platform::PamFaillockStrategy defaultStrategy =
        capabilityConfig->defaultFaillockStrategy;
    possibleValues.push_back(
        fic::platform::pamFaillockStrategyName(defaultStrategy));
    for (fic::platform::PamFaillockStrategy strategy :
         capabilityConfig->supportedFaillockStrategies) {
        if (strategy == defaultStrategy) {
            continue;
        }
        possibleValues.push_back(
            fic::platform::pamFaillockStrategyName(strategy));
    }
    policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
        possibleValues);
}

bool PamCapabilityActivationPolicy::strategyAware() const {
    if (capability_ !=
        fic::platform::PamCapability::AuthenticationLockout) {
        return false;
    }
    const fic::platform::PamCapabilityConfig* capabilityConfig =
        fic::identity::pam::capabilityConfig(platformConfig_, capability_);
    return capabilityConfig != nullptr &&
        !capabilityConfig->supportedFaillockStrategies.empty();
}

std::optional<fic::platform::PamFaillockStrategy>
PamCapabilityActivationPolicy::strategyForValue(
    const std::string& value) const {
    if (!strategyAware()) {
        return std::nullopt;
    }
    return fic::platform::parsePamFaillockStrategy(value);
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
    std::optional<fic::platform::PamFaillockStrategy> strategy;
    if (strategyAware()) {
        strategy = fic::platform::parsePamFaillockStrategy(expectedValue);
        if (!strategy.has_value()) {
            const fic::platform::PamCapabilityConfig* capabilityConfig =
                fic::identity::pam::capabilityConfig(platformConfig_,
                                                     capability_);
            const std::string supported = capabilityConfig == nullptr
                ? std::string()
                : supportedStrategyValues(*capabilityConfig);
            log("PAM authentication lockout value must be one of: " +
                    supported,
                logLevel::ERROR);
            return false;
        }
    } else if (expectedValue != "ENABLE") {
        log("PAM capability activation value must be ENABLE", logLevel::ERROR);
        return false;
    }
    if (capability_ ==
            fic::platform::PamCapability::AuthenticationLockout &&
        !strategyAware()) {
        log("PAM authentication lockout is not supported by this platform "
                "profile: no pam_faillock strategy is declared",
            logLevel::ERROR);
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

    const bool mutableTopology = capability->topology !=
        fic::platform::PamTopologyStrategyKind::StaticVerifyOnly;
    fic::rollback::MutationJournal* journal = nullptr;
    std::vector<fic::rollback::MutationRecord> active;
    const auto policy = policyRef();
    fic::rollback::UndoDisablePamCapability undo;
    undo.capability = policyName;
    if (mutableTopology) {
        undo.topology = capability->topology ==
                fic::platform::PamTopologyStrategyKind::PamAuthUpdate
            ? fic::rollback::PamTopologyKind::PamAuthUpdate
            : fic::rollback::PamTopologyKind::AltTcbManaged;
        undo.activationIdentifiers =
            fic::identity::pam::activationIdentifiers(*capability);
        journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        if (journal == nullptr) {
            log("PAM mutation journal unavailable: " + error, logLevel::ERROR);
            return false;
        }
        active = journal->activeRecords(policy);
        if (active.size() > 1) {
            log("Multiple active PAM topology mutations (fail closed)",
                logLevel::ERROR);
            return false;
        }
        if (!active.empty()) {
            const auto* recorded = std::get_if<
                fic::rollback::UndoDisablePamCapability>(
                    &active.front().undo.payload);
            if (active.front().undo.backend !=
                    fic::rollback::MutationBackend::Pam ||
                active.front().resource != "capability/" + policyName ||
                recorded == nullptr || recorded->capability != undo.capability ||
                recorded->topology != undo.topology ||
                recorded->activationIdentifiers != undo.activationIdentifiers) {
                log("Active PAM provenance does not match current profile "
                    "(fail closed)", logLevel::ERROR);
                return false;
            }
        }
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

    const auto proveEnabled = [&](bool durable) {
        fic::identity::pam::PamTopologyStatus current;
        std::string proofError;
        if (!manager->inspect(current, proofError) ||
            current.state != fic::identity::pam::PamTopologyState::Enabled ||
            ((durable || !active.empty()) && !current.manageable) ||
            (strategyAware() && current.activeStrategy != strategy)) {
            error = "PAM topology AFTER proof failed: " +
                (proofError.empty() ? current.detail : proofError);
            return false;
        }
        fic::identity::pam::PamCapabilityVerification verification;
        if (!verifyFresh(*capability, *services, verification)) {
            error = "PAM structural proof failed: " +
                fic::identity::pam::formatPamCapabilityVerification(
                    verification);
            return false;
        }
        if (durable && !manager->confirmDurable(error)) return false;
        return true;
    };

    if (!active.empty() && active.front().status ==
            fic::rollback::MutationStatus::RollbackFailed) {
        log("PAM rollback previously failed; active provenance requires "
            "rollback recovery before apply (fail closed)",
            logLevel::ERROR);
        return false;
    }

    if (!active.empty() && active.front().status ==
            fic::rollback::MutationStatus::Prepared) {
        if (status.state == fic::identity::pam::PamTopologyState::Enabled &&
            status.manageable &&
            (!strategyAware() || status.activeStrategy == strategy)) {
            if (!proveEnabled(true) ||
                !journal->setStatus(active.front().id,
                    fic::rollback::MutationStatus::Applied, error)) {
                log("PAM Prepared recovery failed: " + error, logLevel::ERROR);
                return false;
            }
            return true;
        }
        const auto* preparedUndo = std::get_if<
            fic::rollback::UndoDisablePamCapability>(
                &active.front().undo.payload);
        if (status.state == fic::identity::pam::PamTopologyState::Disabled &&
            preparedUndo != nullptr &&
            !preparedUndo->hadAppliedProvenance) {
            if (!journal->discard(active.front().id, error)) {
                log("PAM stale Prepared discard failed: " + error,
                    logLevel::ERROR);
                return false;
            }
            active.clear();
        } else {
            log("PAM Prepared topology is indeterminate (fail closed)",
                logLevel::ERROR);
            return false;
        }
    }

    if (!active.empty() &&
        (status.state != fic::identity::pam::PamTopologyState::Enabled ||
         !status.manageable)) {
        log("Active PAM provenance has no proven owned topology "
            "(fail closed)", logLevel::ERROR);
        return false;
    }
    if (active.empty() && mutableTopology &&
        status.state == fic::identity::pam::PamTopologyState::Enabled &&
        status.manageable) {
        log("FIC-owned PAM topology has no journal provenance "
            "(fail closed)", logLevel::ERROR);
        return false;
    }

    bool activated = false;
    const bool mutationRequired =
        status.state == fic::identity::pam::PamTopologyState::Disabled ||
        (status.state == fic::identity::pam::PamTopologyState::Enabled &&
         strategyAware() && status.activeStrategy != strategy);
    fic::rollback::MutationId mutationId = 0;
    const bool reused = !active.empty();
    const auto previous = reused ? active.front() : fic::rollback::MutationRecord{};
    if (mutationRequired && mutableTopology) {
        undo.hadAppliedProvenance = reused;
        fic::rollback::MutationRecord record;
        record.policy = policy;
        record.resource = "capability/" + policyName;
        record.undo = {fic::rollback::MutationBackend::Pam, undo};
        if (!journal->prepareMutation(record, mutationId, error)) {
            log("PAM journal prepare failed: " + error, logLevel::ERROR);
            return false;
        }
    }
    switch (status.state) {
    case fic::identity::pam::PamTopologyState::Enabled:
        // Strategy-aware idempotency: a mismatching active strategy is an
        // atomic transition; a matching one needs no mutation.
        if (strategyAware() && status.activeStrategy != strategy) {
            if (!manager->canEnableStrategy(*strategy, error)) {
                log("PAM topology cannot switch to strategy " +
                        fic::platform::pamFaillockStrategyName(*strategy) +
                        ": " + error,
                    logLevel::ERROR);
                goto mutation_failed;
            }
            if (!manager->enableStrategy(*strategy, error)) {
                log("PAM topology strategy transition to " +
                        fic::platform::pamFaillockStrategyName(*strategy) +
                        " failed: " + error,
                    logLevel::ERROR);
                goto mutation_failed;
            }
        }
        break;
    case fic::identity::pam::PamTopologyState::Disabled:
        if (strategyAware()) {
            if (!manager->canEnableStrategy(*strategy, error)) {
                log("PAM topology cannot be activated with strategy " +
                        fic::platform::pamFaillockStrategyName(*strategy) +
                        ": " + error,
                    logLevel::ERROR);
                goto mutation_failed;
            }
            if (!manager->enableStrategy(*strategy, error)) {
                log("PAM topology activation with strategy " +
                        fic::platform::pamFaillockStrategyName(*strategy) +
                        " failed: " + error,
                    logLevel::ERROR);
                goto mutation_failed;
            }
        } else {
            if (!manager->canEnable(error)) {
                log("PAM topology cannot be activated: " + error,
                    logLevel::ERROR);
                goto mutation_failed;
            }
            if (!manager->enable(error)) {
                log("PAM topology activation failed: " + error,
                    logLevel::ERROR);
                goto mutation_failed;
            }
        }
        activated = true;
        status = {};
        if (!manager->inspect(status, error)) {
            log("PAM topology activation succeeded but ownership/state "
                "verification failed: " +
                    (status.detail.empty() ? error : status.detail),
                logLevel::ERROR);
            goto mutation_failed;
        }
        if (status.state != fic::identity::pam::PamTopologyState::Enabled ||
            (strategyAware() && status.activeStrategy != strategy)) {
            log("PAM topology activation succeeded but ownership/state "
                "verification did not report the requested topology: " +
                    status.detail,
                logLevel::ERROR);
            goto mutation_failed;
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

    if (!proveEnabled(mutationRequired)) {
        log("PAM postcondition failed: " + error, logLevel::ERROR);
        return false;
    }
    if (mutationRequired &&
        !journal->setStatus(mutationId,
            fic::rollback::MutationStatus::Applied, error)) {
        log("PAM journal commit failed: " + error, logLevel::ERROR);
        return false;
    }
    log(activated
            ? "PAM capability topology was activated and structurally verified"
            : "PAM capability topology is enabled and structurally verified",
        logLevel::INFO);
    return true;

mutation_failed:
    if (mutationId != 0) {
        fic::identity::pam::PamTopologyStatus restored;
        std::string restoreError;
        const bool proven = manager->inspect(restored, restoreError) &&
            manager->confirmDurable(restoreError) &&
            (reused
                ? restored.state == fic::identity::pam::PamTopologyState::Enabled &&
                    restored.manageable &&
                    restored.activeStrategy == status.activeStrategy
                : restored.state == fic::identity::pam::PamTopologyState::Disabled);
        if (proven) {
            if (reused) {
                journal->setStatusWithMessage(mutationId, previous.status,
                    previous.error, restoreError);
            } else {
                journal->discard(mutationId, restoreError);
            }
        }
        if (!restoreError.empty()) {
            log("PAM mutation provenance remains Prepared: " + restoreError,
                logLevel::ERROR);
        }
    }
    return false;
}
