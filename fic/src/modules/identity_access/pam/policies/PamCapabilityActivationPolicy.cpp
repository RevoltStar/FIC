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
            // A fresh Prepared record alone cannot prove who selected a
            // shared distro profile after a crash. Only a durably confirmed
            // native writer can; an ambiguous fresh AFTER stays fail closed.
            manager->setJournalProvenance(
                !capability->activationOwnershipRequiresJournal ||
                recorded->confirmedNativeOwnership);
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

    const auto proveEnabled = [&](bool durable,
            std::optional<fic::platform::PamFaillockStrategy> expected) {
        fic::identity::pam::PamTopologyStatus current;
        std::string proofError;
        if (!manager->inspect(current, proofError) ||
            current.state != fic::identity::pam::PamTopologyState::Enabled ||
            ((durable || !active.empty()) && !current.manageable) ||
            (strategyAware() && current.activeStrategy != expected)) {
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
        const auto* preparedUndo = std::get_if<
            fic::rollback::UndoDisablePamCapability>(
                &active.front().undo.payload);
        const auto recordedTarget = preparedUndo != nullptr &&
                preparedUndo->targetStrategy
            ? fic::platform::parsePamFaillockStrategy(
                  *preparedUndo->targetStrategy)
            : std::optional<fic::platform::PamFaillockStrategy>{};
        const auto recordedPrevious = preparedUndo != nullptr &&
                preparedUndo->previousStrategy
            ? fic::platform::parsePamFaillockStrategy(
                  *preparedUndo->previousStrategy)
            : std::optional<fic::platform::PamFaillockStrategy>{};
        if (preparedUndo == nullptr ||
            (strategyAware() && !recordedTarget)) {
            log("PAM Prepared has no persisted target strategy (fail closed)",
                logLevel::ERROR);
            return false;
        }
        if (status.state == fic::identity::pam::PamTopologyState::Enabled &&
            status.manageable &&
            (!strategyAware() || status.activeStrategy == recordedTarget)) {
            if (!proveEnabled(true, recordedTarget) ||
                !journal->setStatus(active.front().id,
                    fic::rollback::MutationStatus::Applied, error)) {
                log("PAM Prepared AFTER recovery failed: " + error,
                    logLevel::ERROR);
                return false;
            }
            active = journal->activeRecords(policy);
        } else if (preparedUndo->hadAppliedProvenance &&
                   status.state ==
                       fic::identity::pam::PamTopologyState::Enabled &&
                   status.manageable && recordedPrevious &&
                   status.activeStrategy == recordedPrevious) {
            if (!proveEnabled(true, recordedPrevious) ||
                !journal->setStatusWithMessage(active.front().id,
                    fic::rollback::MutationStatus::Applied,
                    preparedUndo->previousError, error)) {
                log("PAM Prepared BEFORE recovery failed: " + error,
                    logLevel::ERROR);
                return false;
            }
            active = journal->activeRecords(policy);
        } else if (status.state ==
                       fic::identity::pam::PamTopologyState::Disabled &&
                   !preparedUndo->hadAppliedProvenance) {
            if (!manager->confirmDurable(error) ||
                !journal->discard(active.front().id, error)) {
                log("PAM stale Prepared discard failed: " + error,
                    logLevel::ERROR);
                return false;
            }
            active.clear();
            manager->setJournalProvenance(false);
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
    if (mutationRequired && status.state ==
            fic::identity::pam::PamTopologyState::Enabled &&
        !status.manageable) {
        log("External PAM topology has a different strategy; refusing "
            "ownership (no mutation)", logLevel::ERROR);
        return false;
    }
    if (mutationRequired &&
        !(strategyAware() ? manager->canEnableStrategy(*strategy, error)
                          : manager->canEnable(error))) {
        log("PAM topology preflight failed before journal prepare: " + error,
            logLevel::ERROR);
        return false;
    }
    fic::rollback::MutationId mutationId = 0;
    const bool reused = !active.empty();
    const auto previous = reused ? active.front() : fic::rollback::MutationRecord{};
    if (mutationRequired && mutableTopology) {
        undo.hadAppliedProvenance = reused;
        undo.confirmedNativeOwnership =
            reused && std::get<fic::rollback::UndoDisablePamCapability>(
                previous.undo.payload).confirmedNativeOwnership;
        undo.previousError = reused ? previous.error : std::string();
        if (strategyAware()) {
            undo.targetStrategy =
                fic::platform::pamFaillockStrategyName(*strategy);
            if (reused && status.activeStrategy)
                undo.previousStrategy =
                    fic::platform::pamFaillockStrategyName(
                        *status.activeStrategy);
        }
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

    if (!proveEnabled(mutationRequired, strategy)) {
        log("PAM postcondition failed: " + error, logLevel::ERROR);
        return false;
    }
    if (mutationRequired &&
        capability->activationOwnershipRequiresJournal) {
        // A second durable Prepared refresh records that this process ran
        // the native writer successfully. If this write fails, the earlier
        // intent-only Prepared remains fail closed and cannot claim a
        // concurrently selected administrator profile.
        undo.confirmedNativeOwnership = true;
        fic::rollback::MutationRecord confirmed;
        confirmed.policy = policy;
        confirmed.resource = "capability/" + policyName;
        confirmed.undo = {fic::rollback::MutationBackend::Pam, undo};
        fic::rollback::MutationId confirmedId = 0;
        if (!journal->prepareMutation(confirmed, confirmedId, error) ||
            confirmedId != mutationId) {
            log("PAM native ownership confirmation failed: " + error,
                logLevel::ERROR);
            return false;
        }
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
