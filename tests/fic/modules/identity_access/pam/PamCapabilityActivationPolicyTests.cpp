#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"
#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"
#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamTopologyManagerFactory.h"
#include "rollback/DaemonMutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::filesystem::path& path,
               const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::trunc);
    require(stream.is_open(), "could not write " + path.string());
    stream << content;
}

fic::platform::PamPlatformConfig makePlatform(
    const std::filesystem::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.scopes = {
        {fic::platform::PamScope::EffectiveAuthenticationStack, {"login"}},
        {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
    platform.capabilities = {
        {fic::platform::PamCapability::AuthenticationLockout,
         fic::platform::PamProviderKind::PamFaillock,
         fic::platform::PamScope::EffectiveAuthenticationStack,
         root / "security/faillock.conf",
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate},
        {fic::platform::PamCapability::PasswordHistory,
         fic::platform::PamProviderKind::PamPwhistory,
         fic::platform::PamScope::EffectivePasswordStack,
         root / "security/pwhistory.conf",
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate},
        {fic::platform::PamCapability::PasswordQuality,
         fic::platform::PamProviderKind::PamPwquality,
         fic::platform::PamScope::EffectivePasswordStack,
         root / "security/pwquality.conf",
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate}};
    platform.capabilities[0].supportedFaillockStrategies = {
        fic::platform::PamFaillockStrategy::PreauthRequired,
        fic::platform::PamFaillockStrategy::PreauthRequisite,
        fic::platform::PamFaillockStrategy::Authsucc};
    platform.capabilities[0].defaultFaillockStrategy =
        fic::platform::PamFaillockStrategy::PreauthRequired;
    platform.capabilities[0].strategyActivations = {
        {fic::platform::PamFaillockStrategy::PreauthRequisite,
         {"fic-faillock-notify", "fic-faillock-authfail"}},
        {fic::platform::PamFaillockStrategy::PreauthRequired,
         {"fic-faillock-preauth-required", "fic-faillock-authfail"}},
        {fic::platform::PamFaillockStrategy::Authsucc,
         {"fic-faillock-authsucc", "fic-faillock-authfail"}}};
    platform.capabilities[1].activationIdentifiers = {"fic-pwhistory"};
    platform.capabilities[2].activationIdentifiers = {"fic-pwquality"};
    return platform;
}

struct ManagerState {
    int factoryCalls = 0;
    int inspectCalls = 0;
    int canEnableCalls = 0;
    int enableCalls = 0;
    int disableCalls = 0;
    int canEnableStrategyCalls = 0;
    int enableStrategyCalls = 0;
    bool inspectResult = true;
    bool canEnableResult = true;
    bool enableResult = true;
    bool transitionToEnabled = true;
    bool canEnableStrategyResult = true;
    bool enableStrategyResult = true;
    bool manageable = true;
    bool journalBoundPhysicalOwnership = false;
    bool disableTransitionsToDisabled = false;
    std::optional<std::uint64_t> boundMutationId;
    std::function<void()> onConfirmDurable;
    std::optional<fic::platform::PamFaillockStrategy> activeStrategy;
    std::vector<fic::platform::PamFaillockStrategy> requestedStrategies;
    fic::identity::pam::PamTopologyState topologyState =
        fic::identity::pam::PamTopologyState::Disabled;
};

class FakeManager final : public fic::identity::pam::PamTopologyManager {
public:
    bool confirmDurable(std::string& error) const override {
        if (state_->onConfirmDurable) state_->onConfirmDurable();
        error.clear(); return true;
    }
    explicit FakeManager(std::shared_ptr<ManagerState> state)
        : state_(std::move(state)) {}

    bool inspect(fic::identity::pam::PamTopologyStatus& status,
                 std::string& error) override {
        ++state_->inspectCalls;
        status = {state_->topologyState, state_->manageable,
                  state_->activeStrategy,
                  "fake topology"};
        if (state_->journalBoundPhysicalOwnership &&
            state_->topologyState ==
                fic::identity::pam::PamTopologyState::Enabled) {
            status.ownershipMutationId = state_->boundMutationId;
        }
        error = state_->inspectResult ? "" : "inspection failed";
        return state_->inspectResult;
    }
    bool journalBindsPhysicalOwnership() const override {
        return state_->journalBoundPhysicalOwnership;
    }
    bool bindJournalMutationId(
        std::uint64_t mutationId, std::string& error) override {
        if (!state_->journalBoundPhysicalOwnership) {
            error = "fake manager has no physical ownership witness";
            return false;
        }
        state_->boundMutationId = mutationId;
        error.clear();
        return true;
    }
    bool canEnable(std::string& error) const override {
        ++state_->canEnableCalls;
        error = state_->canEnableResult ? "" : "cannot enable";
        return state_->canEnableResult;
    }
    bool enable(std::string& error) override {
        ++state_->enableCalls;
        error = state_->enableResult ? "" : "enable failed";
        if (state_->enableResult && state_->transitionToEnabled) {
            state_->topologyState =
                fic::identity::pam::PamTopologyState::Enabled;
            state_->manageable = true;
            state_->inspectResult = true;
        }
        return state_->enableResult;
    }
    bool disable(std::string& error) override {
        ++state_->disableCalls;
        if (state_->disableTransitionsToDisabled) {
            state_->topologyState =
                fic::identity::pam::PamTopologyState::Disabled;
            state_->manageable = false;
            state_->activeStrategy.reset();
            state_->inspectResult = true;
        }
        error.clear();
        return true;
    }
    bool canEnableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) const override {
        ++state_->canEnableStrategyCalls;
        if (!state_->canEnableStrategyResult) {
            error = "cannot enable strategy";
            return false;
        }
        error.clear();
        return true;
    }
    bool enableStrategy(
        fic::platform::PamFaillockStrategy strategy,
        std::string& error) override {
        ++state_->enableStrategyCalls;
        state_->requestedStrategies.push_back(strategy);
        if (!state_->enableStrategyResult) {
            error = "strategy transition failed";
            return false;
        }
        state_->activeStrategy = strategy;
        if (state_->transitionToEnabled) {
            state_->topologyState =
                fic::identity::pam::PamTopologyState::Enabled;
            state_->manageable = true;
            state_->inspectResult = true;
        }
        error.clear();
        return true;
    }

private:
    std::shared_ptr<ManagerState> state_;
};

PamCapabilityActivationPolicy makePolicy(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamCapability capability,
    const std::shared_ptr<ManagerState>& managerState,
    std::vector<bool> verificationResults,
    int& verifierCalls,
    fic::platform::PamCapability& factoryCapability,
    bool seedOwned = true) {
    static unsigned journalSequence = 0;
    const auto journalPath = fic::core::FicRuntimePaths::get().dataDir /
        ("pam-activation-" + std::to_string(++journalSequence) + ".json");
    std::filesystem::create_directories(journalPath.parent_path());
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(journalPath);
    if (seedOwned && managerState->topologyState ==
        fic::identity::pam::PamTopologyState::Enabled) {
        const auto* config = fic::identity::pam::capabilityConfig(
            platform, capability);
        require(config != nullptr, "missing PAM test capability");
        fic::rollback::UndoDisablePamCapability undo;
        undo.capability = pamCapabilityActivationPolicyName(capability);
        undo.topology = config->topology ==
                fic::platform::PamTopologyStrategyKind::PamAuthUpdate
            ? fic::rollback::PamTopologyKind::PamAuthUpdate
            : fic::rollback::PamTopologyKind::AltTcbManaged;
        for (const auto& activation : config->strategyActivations)
            for (const auto& id : activation.activationIdentifiers)
                if (std::find(undo.activationIdentifiers.begin(),
                              undo.activationIdentifiers.end(), id) ==
                    undo.activationIdentifiers.end())
                    undo.activationIdentifiers.push_back(id);
        for (const auto& id : config->activationIdentifiers)
            if (std::find(undo.activationIdentifiers.begin(),
                          undo.activationIdentifiers.end(), id) ==
                undo.activationIdentifiers.end())
                undo.activationIdentifiers.push_back(id);
        std::string journalError;
        auto* journal = fic::rollback::DaemonMutationJournal::instance()
            .tryGet(journalError);
        require(journal != nullptr, journalError);
        fic::rollback::MutationRecord record;
        record.policy = {"IDENTITY_ACCESS", "PAM", undo.capability};
        record.resource = "capability/" + undo.capability;
        record.undo = {fic::rollback::MutationBackend::Pam, undo};
        fic::rollback::MutationId id = 0;
        require(journal->prepareMutation(record, id, journalError),
                journalError);
        require(journal->setStatus(id, fic::rollback::MutationStatus::Applied,
                                   journalError), journalError);
    }
    auto results = std::make_shared<std::vector<bool>>(
        std::move(verificationResults));
    PamCapabilityActivationPolicyOptions options;
    options.verifier =
        [results, &verifierCalls](const auto&, const auto&,
                                  auto& verification) mutable {
            const std::size_t index = static_cast<std::size_t>(verifierCalls++);
            const bool result = index < results->size() && (*results)[index];
            verification.state = result
                ? fic::identity::pam::PamEnforcementState::Effective
                : fic::identity::pam::PamEnforcementState::Inactive;
            verification.detail = result ? "" : "inactive";
            return result;
        };
    options.managerFactory =
        [managerState, &factoryCapability](const auto& capabilityConfig,
                                           const auto&,
                                           std::string& error) {
            ++managerState->factoryCalls;
            factoryCapability = capabilityConfig.capability;
            error.clear();
            return std::make_unique<FakeManager>(managerState);
        };
    return PamCapabilityActivationPolicy(platform, capability,
                                         std::move(options));
}

fic::platform::PamPlatformConfig makeAltLockoutPlatform(
    const std::filesystem::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.scopes = {{
        fic::platform::PamScope::EffectiveAuthenticationStack,
        {"system-auth-local-only"}}};
    platform.capabilities = {{
        fic::platform::PamCapability::AuthenticationLockout,
        fic::platform::PamProviderKind::PamFaillock,
        fic::platform::PamScope::EffectiveAuthenticationStack,
        "/etc/security/faillock.conf",
        fic::platform::PamTopologyStrategyKind::AltTcbManaged}};
    platform.capabilities.front().managedTopologyTargets = {{
        root / "pam.d/system-auth-local-only",
        fic::platform::PamManagedTopologyTargetRole::AuthenticationAndAccount}};
    platform.capabilities.front().supportedFaillockStrategies = {
        fic::platform::PamFaillockStrategy::PreauthRequired,
        fic::platform::PamFaillockStrategy::PreauthRequisite,
        fic::platform::PamFaillockStrategy::Authsucc};
    platform.capabilities.front().defaultFaillockStrategy =
        fic::platform::PamFaillockStrategy::PreauthRequired;
    return platform;
}

fic::identity::pam::AltPamFaillockTopologyOptions altLockoutOptions(
    const std::filesystem::path& root) {
    fic::identity::pam::AltPamFaillockTopologyOptions options;
    options.lockFilePath = root / "run/pam-faillock.lock";
    options.lockDebugLogPath = root / "lock-debug.log";
    return options;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    require(stream.is_open(), "could not read " + path.string());
    return std::string(std::istreambuf_iterator<char>(stream),
                       std::istreambuf_iterator<char>());
}

PamCapabilityActivationPolicy makeAltLockoutPolicy(
    const fic::platform::PamPlatformConfig& platform,
    const std::filesystem::path& root) {
    PamCapabilityActivationPolicyOptions options;
    options.managerFactory =
        [platform, root](const auto&, const auto&, std::string& error) {
            error.clear();
            return std::make_unique<fic::identity::pam::
                AltPamFaillockTopologyManager>(
                    platform, altLockoutOptions(root));
        };
    return PamCapabilityActivationPolicy(
        platform, fic::platform::PamCapability::AuthenticationLockout,
        std::move(options));
}

void testPamJournalLifecycle(const std::filesystem::path& root,
                             const fic::platform::PamPlatformConfig& platform) {
    const auto setLockoutValue = [&](const std::string& value) {
        writeFile(root / "config/IDENTITY_ACCESS.conf",
                  "enable_authentication_lockout.status=ENABLE\n"
                  "enable_authentication_lockout.value=" + value + "\n");
    };
    setLockoutValue("preauth_required");
    auto state = std::make_shared<ManagerState>();
    int verifierCalls = 0;
    auto observed = fic::platform::PamCapability::PasswordQuality;
    auto policy = makePolicy(platform,
        fic::platform::PamCapability::AuthenticationLockout, state,
        {true, true, true}, verifierCalls, observed);
    const auto onCurrentJournal = [&]() {
        PamCapabilityActivationPolicyOptions options;
        options.managerFactory = [state](const auto&, const auto&,
                                         std::string& error) {
            error.clear();
            return std::make_unique<FakeManager>(state);
        };
        options.verifier = [](const auto&, const auto&,
                              auto& verification) {
            verification.state =
                fic::identity::pam::PamEnforcementState::Effective;
            verification.detail.clear();
            return true;
        };
        return PamCapabilityActivationPolicy(platform,
            fic::platform::PamCapability::AuthenticationLockout,
            std::move(options));
    };
    require(policy.apply(), "fresh PAM activation must succeed");
    std::string error;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    const PolicyRef ref{"IDENTITY_ACCESS", "PAM",
                        "enable_authentication_lockout"};
    auto records = journal->activeRecords(ref);
    require(records.size() == 1 &&
                records.front().status == fic::rollback::MutationStatus::Applied,
            "fresh PAM activation must commit exactly one Applied record");
    const auto id = records.front().id;
    setLockoutValue("authsucc");
    auto authsuccPolicy = onCurrentJournal();
    require(authsuccPolicy.apply(),
            "faillock strategy transition must succeed");
    records = journal->activeRecords(ref);
    require(records.size() == 1 && records.front().id == id &&
                records.front().status == fic::rollback::MutationStatus::Applied,
            "strategy transition must reuse the same MutationId");
    require(std::get<fic::rollback::UndoDisablePamCapability>(
                records.front().undo.payload).hadAppliedProvenance,
            "strategy transition must persist reused provenance marker");
    require(journal->setStatus(id, fic::rollback::MutationStatus::Prepared,
                               error), error);
    const int transitionsBeforeRecovery = state->enableStrategyCalls;
    require(authsuccPolicy.apply(), "Prepared AFTER must recover");
    require(state->enableStrategyCalls == transitionsBeforeRecovery &&
                journal->activeRecords(ref).front().status ==
                    fic::rollback::MutationStatus::Applied,
            "Prepared recovery must not invoke native writer again");
    setLockoutValue("preauth_requisite");
    auto requisitePolicy = onCurrentJournal();
    state->enableStrategyResult = false;
    require(!requisitePolicy.apply(),
            "failed strategy transition must be rejected");
    records = journal->activeRecords(ref);
    require(records.size() == 1 && records.front().id == id &&
                records.front().status == fic::rollback::MutationStatus::Applied,
            "fully compensated reused transition must restore Applied");
    require(journal->setStatus(id, fic::rollback::MutationStatus::Prepared,
                               error), error);
    state->topologyState = fic::identity::pam::PamTopologyState::Broken;
    require(!requisitePolicy.apply() &&
                journal->activeRecords(ref).size() == 1 &&
                journal->activeRecords(ref).front().status ==
                    fic::rollback::MutationStatus::Prepared,
            "Prepared drift must remain active and fail closed");
    state->topologyState = fic::identity::pam::PamTopologyState::Disabled;
    require(!requisitePolicy.apply() &&
                journal->activeRecords(ref).size() == 1 &&
                journal->activeRecords(ref).front().status ==
                    fic::rollback::MutationStatus::Prepared,
            "reused Prepared+Disabled must never discard established provenance");

    setLockoutValue("preauth_required");
    state = std::make_shared<ManagerState>();
    verifierCalls = 0;
    auto freshPolicy = makePolicy(platform,
        fic::platform::PamCapability::AuthenticationLockout, state,
        {true}, verifierCalls, observed);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    fic::rollback::MutationRecord stale;
    stale.policy = ref;
    stale.resource = "capability/enable_authentication_lockout";
    stale.undo = {fic::rollback::MutationBackend::Pam,
        fic::rollback::UndoDisablePamCapability{
            "enable_authentication_lockout",
            fic::rollback::PamTopologyKind::PamAuthUpdate,
            {"fic-faillock-notify", "fic-faillock-authfail",
             "fic-faillock-preauth-required", "fic-faillock-authsucc"}}};
    std::get<fic::rollback::UndoDisablePamCapability>(stale.undo.payload)
        .targetStrategy = "preauth_required";
    fic::rollback::MutationId staleId = 0;
    require(journal->prepareMutation(stale, staleId, error), error);
    require(freshPolicy.apply(), "Prepared BEFORE must be discarded and retried");
    records = journal->activeRecords(ref);
    require(records.size() == 1 && records.front().id != staleId &&
                records.front().status == fic::rollback::MutationStatus::Applied,
            "fresh stale Prepared must not be reused");

    // The durable transaction says A -> B, but no native writer ran before
    // restart. Recovery must resolve A first, even if the config now asks C.
    state = std::make_shared<ManagerState>();
    state->topologyState = fic::identity::pam::PamTopologyState::Enabled;
    state->activeStrategy =
        fic::platform::PamFaillockStrategy::PreauthRequired;
    verifierCalls = 0;
    auto beforeCrash = makePolicy(platform,
        fic::platform::PamCapability::AuthenticationLockout, state,
        {true}, verifierCalls, observed);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    records = journal->activeRecords(ref);
    require(records.size() == 1, "missing seeded transition provenance");
    const auto transitionId = records.front().id;
    require(journal->setStatusWithMessage(transitionId,
                fic::rollback::MutationStatus::Applied,
                "prior diagnostic", error), error);
    records = journal->activeRecords(ref);
    auto transition = records.front();
    auto& transitionUndo = std::get<fic::rollback::UndoDisablePamCapability>(
        transition.undo.payload);
    transitionUndo.hadAppliedProvenance = true;
    transitionUndo.previousStrategy = "preauth_required";
    transitionUndo.targetStrategy = "authsucc";
    transitionUndo.previousError = "prior diagnostic";
    require(journal->prepareMutation(transition, staleId, error) &&
                staleId == transitionId, error);
    setLockoutValue("preauth_requisite");
    state->canEnableStrategyResult = false;
    auto changedDesired = onCurrentJournal();
    require(!changedDesired.apply() && state->enableStrategyCalls == 0,
            "new desired preflight unexpectedly ran native writer");
    records = journal->activeRecords(ref);
    require(records.size() == 1 && records.front().id == transitionId &&
                records.front().status ==
                    fic::rollback::MutationStatus::Applied &&
                records.front().error == "prior diagnostic",
            "Prepared BEFORE did not restore previous status and error");
    state->canEnableStrategyResult = true;
    auto retryChangedDesired = onCurrentJournal();
    require(retryChangedDesired.apply() &&
                state->activeStrategy ==
                    fic::platform::PamFaillockStrategy::PreauthRequisite &&
                state->enableStrategyCalls == 1,
            "Prepared BEFORE was not resolved before new desired value");
    records = journal->activeRecords(ref);
    require(records.size() == 1 && records.front().id == transitionId &&
                records.front().status == fic::rollback::MutationStatus::Applied,
            "Prepared BEFORE recovery lost the original MutationId");

    // Persisted B is already effective, while config has moved on to A.
    transition = records.front();
    auto& afterUndo = std::get<fic::rollback::UndoDisablePamCapability>(
        transition.undo.payload);
    afterUndo.previousStrategy = "preauth_requisite";
    afterUndo.targetStrategy = "authsucc";
    require(journal->prepareMutation(transition, staleId, error), error);
    state->activeStrategy = fic::platform::PamFaillockStrategy::Authsucc;
    setLockoutValue("preauth_required");
    auto desiredAfterCrash = onCurrentJournal();
    require(desiredAfterCrash.apply() &&
                state->activeStrategy ==
                    fic::platform::PamFaillockStrategy::PreauthRequired &&
                state->enableStrategyCalls == 2,
            "Prepared AFTER was not resolved before new desired value");

    state = std::make_shared<ManagerState>();
    state->topologyState = fic::identity::pam::PamTopologyState::Enabled;
    state->manageable = false;
    state->activeStrategy =
        fic::platform::PamFaillockStrategy::PreauthRequired;
    setLockoutValue("authsucc");
    verifierCalls = 0;
    auto foreignStrategy = makePolicy(platform,
        fic::platform::PamCapability::AuthenticationLockout, state,
        {}, verifierCalls, observed, false);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(!foreignStrategy.apply() && state->enableStrategyCalls == 0 &&
                journal->activeRecords(ref).empty(),
            "external strategy mismatch created PAM provenance");

    // The native mutation has happened, but the Applied journal write loses
    // its durability proof. Prepared ownership must remain available to the
    // next daemon instance rather than being discarded as a failed apply.
    state = std::make_shared<ManagerState>();
    verifierCalls = 0;
    auto commitFailurePolicy = makePolicy(platform,
        fic::platform::PamCapability::AuthenticationLockout, state,
        {true}, verifierCalls, observed);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    state->onConfirmDurable = []() {
        AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string&) { return false; });
    };
    const bool commitSucceeded = commitFailurePolicy.apply();
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    state->onConfirmDurable = nullptr;
    // A failed post-rename fsync poisons the live journal. Recovery must
    // reload and prove the on-disk state before any ownership decision.
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, "PAM journal could not recover: " + error);
    records = journal->activeRecords(ref);
    require(!commitSucceeded && state->topologyState ==
                fic::identity::pam::PamTopologyState::Enabled &&
                records.size() == 1 &&
                (records.front().status ==
                     fic::rollback::MutationStatus::Prepared ||
                 records.front().status ==
                     fic::rollback::MutationStatus::Applied),
            "journal commit failure after native mutation lost active "
            "PAM provenance");
}

void testJournalBoundPreparedPartialRecovery(
    const std::filesystem::path& root,
    const fic::platform::PamPlatformConfig& platform) {
    auto state = std::make_shared<ManagerState>();
    state->journalBoundPhysicalOwnership = true;
    state->disableTransitionsToDisabled = true;
    state->topologyState = fic::identity::pam::PamTopologyState::Broken;
    state->inspectResult = false;

    int verifierCalls = 0;
    auto observed = fic::platform::PamCapability::PasswordQuality;
    auto policy = makePolicy(
        platform, fic::platform::PamCapability::AuthenticationLockout,
        state, {true}, verifierCalls, observed, false);

    std::string error;
    auto* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    const PolicyRef ref{
        "IDENTITY_ACCESS", "PAM", "enable_authentication_lockout"};
    const auto* config = fic::identity::pam::capabilityConfig(
        platform, fic::platform::PamCapability::AuthenticationLockout);
    require(config != nullptr, "missing lockout capability");

    fic::rollback::UndoDisablePamCapability undo;
    undo.capability = "enable_authentication_lockout";
    undo.topology = fic::rollback::PamTopologyKind::PamAuthUpdate;
    for (const auto& activation : config->strategyActivations) {
        for (const auto& id : activation.activationIdentifiers) {
            if (std::find(undo.activationIdentifiers.begin(),
                          undo.activationIdentifiers.end(), id) ==
                undo.activationIdentifiers.end()) {
                undo.activationIdentifiers.push_back(id);
            }
        }
    }
    undo.targetStrategy = "preauth_required";
    fic::rollback::MutationRecord record;
    record.policy = ref;
    record.resource = "capability/enable_authentication_lockout";
    record.undo = {fic::rollback::MutationBackend::Pam, undo};
    fic::rollback::MutationId staleId = 0;
    require(journal->prepareMutation(record, staleId, error), error);

    require(policy.apply(),
            "journal-bound crash-partial Prepared was not compensated/reapplied");
    const auto records = journal->activeRecords(ref);
    require(state->disableCalls == 1 &&
                state->enableStrategyCalls == 1 &&
                records.size() == 1 &&
                records.front().status ==
                    fic::rollback::MutationStatus::Applied &&
                records.front().id != staleId &&
                state->boundMutationId ==
                    std::optional<fic::rollback::MutationId>{
                        records.front().id},
            "Prepared partial recovery did not neutralize then create fresh "
            "physical provenance");
}

void testExternalPwquality(const std::filesystem::path& root) {
    const auto qualityRoot = root / "external-pwquality";
    writeFile(root / "config/IDENTITY_ACCESS.conf",
        "enable_password_quality.status=ENABLE\n"
        "enable_password_quality.value=ENABLE\n");
    writeFile(qualityRoot / "security/pam_pwquality.so", "fixture\n");
    writeFile(qualityRoot / "security/pam_unix.so", "fixture\n");
    writeFile(qualityRoot / "security/pwquality.conf", "minlen=8\n");
    writeFile(qualityRoot / "pam.d/passwd",
        "password requisite pam_pwquality.so\n"
        "password required pam_unix.so\n");
    writeFile(qualityRoot / "var/lib/pam/password",
              "Module: unix\nModule: pwquality\n");
    const auto executable = qualityRoot / "bin/pam-auth-update";
    writeFile(executable, "#!/bin/sh\nexit 0\n");
    require(::chmod(executable.c_str(), 0755) == 0,
            "could not prepare pam-auth-update fixture");
    auto platform = makePlatform(qualityRoot);
    fic::platform::PamProviderConfigTopology qualityConfig;
    qualityConfig.primaryPath = qualityRoot / "security/pwquality.conf";
    platform.capabilities[2].configTopology = qualityConfig;
    fic::platform::PlatformExecutables executableConfig;
    executableConfig.entries = {{fic::platform::ExecutableId::PamAuthUpdate,
                                 {executable}}};
    fic::platform::PlatformExecutableResolver resolver(
        executableConfig, {.enforceTrustedOwnership = false});
    int writerCalls = 0;
    fic::identity::pam::PamAuthUpdateTopologyManagerOptions managerOptions;
    managerOptions.stateDirectory = qualityRoot / "var/lib/pam";
    managerOptions.configDirectory = qualityRoot / "pam.d";
    managerOptions.runner = [&](const std::string&, const auto& arguments,
                                const ProcessOptions&) {
        ++writerCalls;
        if (std::find(arguments.begin(), arguments.end(), "--enable") !=
            arguments.end()) {
            writeFile(qualityRoot / "var/lib/pam/password",
                      "Module: unix\nModule: fic-pwquality\n");
            writeFile(qualityRoot / "pam.d/passwd",
                      "password requisite pam_pwquality.so\n"
                      "password required pam_unix.so\n");
        } else {
            writeFile(qualityRoot / "var/lib/pam/password",
                      "Module: unix\n");
            writeFile(qualityRoot / "pam.d/passwd",
                      "password required pam_unix.so\n");
        }
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    const auto factory = [&](const auto& capability, const auto& services,
                             std::string& error) {
        error.clear();
        return std::make_unique<fic::identity::pam::
            PamAuthUpdateTopologyManager>(platform, capability, services,
                                          resolver, managerOptions);
    };
    std::filesystem::create_directories(qualityRoot / "data");
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(
        qualityRoot / "data/mutations.json");
    PamCapabilityActivationPolicyOptions policyOptions;
    policyOptions.managerFactory = factory;
    policyOptions.verifier = [](const auto&, const auto&, auto& verification) {
        verification.state =
            fic::identity::pam::PamEnforcementState::Effective;
        return true;
    };
    // Joint C2 password topology contract: a password capability on a
    // PamAuthUpdate platform NEVER runs the legacy single-capability
    // activation path. Without the production coordinator factory the
    // apply fails closed WITHOUT adopting, rewriting or disabling the
    // foreign stock pwquality producer and without creating provenance
    // (the foreign-satisfaction no-op itself is covered end-to-end by
    // pam_password_wiring_tests / R11).
    PamCapabilityActivationPolicy policy(platform,
        fic::platform::PamCapability::PasswordQuality,
        std::move(policyOptions));
    require(!policy.apply() && writerCalls == 0,
            "password apply without the joint coordinator must fail closed");
    std::string error;
    auto* journal = fic::rollback::DaemonMutationJournal::instance()
        .tryGet(error);
    require(journal != nullptr &&
                journal->activeRecords({"IDENTITY_ACCESS", "PAM",
                    "enable_password_quality"}).empty(),
            "foreign pwquality was adopted or rewritten");
    auto manager = factory(platform.capabilities[2],
                           std::vector<std::string>{"passwd"}, error);
    fic::identity::pam::PamTopologyStatus status;
    require(manager->inspect(status, error) &&
                status.state == fic::identity::pam::PamTopologyState::Enabled &&
                !status.manageable && manager->disable(error) &&
                writerCalls == 0,
            "unrecorded pwquality was disabled");

    writeFile(qualityRoot / "var/lib/pam/password", "Module: unix\n");
    writeFile(qualityRoot / "pam.d/passwd",
              "password required pam_unix.so\n");
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(
        qualityRoot / "data/fresh-mutations.json");
    PamCapabilityActivationPolicyOptions freshOptions;
    freshOptions.managerFactory = factory;
    freshOptions.verifier = [](const auto&, const auto&, auto& verification) {
        verification.state =
            fic::identity::pam::PamEnforcementState::Effective;
        return true;
    };
    PamCapabilityActivationPolicy freshPolicy(platform,
        fic::platform::PamCapability::PasswordQuality,
        std::move(freshOptions));
    require(!freshPolicy.apply() && writerCalls == 0,
            "legacy pwquality profile activation created new destructive "
            "provenance");
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                journal->activeRecords({"IDENTITY_ACCESS", "PAM",
                    "enable_password_quality"}).empty(),
            "observation-only pwquality activation created PAM provenance");

    // Even the exact reserved identifier is not a causal witness.
    writeFile(qualityRoot / "var/lib/pam/password",
              "Module: unix\nModule: fic-pwquality\n");
    writeFile(qualityRoot / "pam.d/passwd",
              "password requisite pam_pwquality.so\n"
              "password required pam_unix.so\n");
    manager = factory(platform.capabilities[2],
                      std::vector<std::string>{"passwd"}, error);
    const bool inspected = manager->inspect(status, error);
    const bool disabled = inspected && manager->disable(error);
    require(inspected &&
                status.state ==
                    fic::identity::pam::PamTopologyState::Enabled &&
                status.manageable && !disabled && writerCalls == 0,
            "exact legacy pwquality profile contract mismatch: manageable=" +
                std::string(status.manageable ? "true" : "false") +
                " disabled=" + (disabled ? "true" : "false") +
                " writer_calls=" + std::to_string(writerCalls) +
                " error=" + error);
}

} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-pam-activation-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    try {
        auto paths = fic::core::FicProductPaths::production();
        paths.configDir = root / "config";
        paths.logDir = root / "log";
        paths.dataDir = root / "data";
        paths.runtimeDir = root / "run";
        paths.commandHashFile = root / "data/commandhash.txt";
        std::string error;
        require(fic::core::FicRuntimePaths::initialize(paths, error), error);
        writeFile(
            root / "config/IDENTITY_ACCESS.conf",
            "enable_authentication_lockout.status=ENABLE\n"
            "enable_authentication_lockout.value=preauth_required\n"
            "enable_password_history.status=ENABLE\n"
            "enable_password_history.value=ENABLE\n"
            "enable_password_quality.status=DISABLE\n"
            "enable_password_quality.value=ENABLE\n");
        const auto platform = makePlatform(root);
        require(
            fic::identity::pam::pamPolicySupport(
                platform,
                fic::platform::PamPolicyFeature::PasswordHistoryDepth) ==
                fic::platform::PamPolicySupport::ReadOnly &&
            fic::identity::pam::pamPolicySupport(
                platform,
                fic::platform::PamPolicyFeature::PasswordMinLength) ==
                fic::platform::PamPolicySupport::ReadOnly,
            "legacy pam-auth-update password capabilities must be observation-only");

        auto state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
        state->activeStrategy =
            fic::platform::PamFaillockStrategy::PreauthRequired;
        int verifierCalls = 0;
        auto factoryCapability =
            fic::platform::PamCapability::PasswordQuality;
        auto alreadyEnabled = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {true, true}, verifierCalls, factoryCapability);
        require(alreadyEnabled.policyName == "enable_authentication_lockout" &&
                    alreadyEnabled.capability() ==
                        fic::platform::PamCapability::AuthenticationLockout &&
                    alreadyEnabled.getDefaultValue() == "preauth_required" &&
                    alreadyEnabled.apply() && alreadyEnabled.apply() &&
                    verifierCalls == 2 &&
                    state->factoryCalls == 2 && state->inspectCalls == 4 &&
                    state->canEnableCalls == 0 && state->enableCalls == 0 &&
                    state->enableStrategyCalls == 0,
                "manager-first repeated activation was not idempotent");

        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
        state->activeStrategy =
            fic::platform::PamFaillockStrategy::PreauthRequired;
        verifierCalls = 0;
        auto enabledButStructurallyInvalid = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {false}, verifierCalls, factoryCapability);
        require(!enabledButStructurallyInvalid.apply() &&
                    state->factoryCalls == 1 && state->inspectCalls == 2 &&
                    state->enableCalls == 0 && verifierCalls == 1,
                "manager-enabled topology bypassed fresh verification");

        // Strategy mismatch on an already-enabled topology: the activation
        // policy must request an atomic strategy transition.
        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
        state->activeStrategy =
            fic::platform::PamFaillockStrategy::PreauthRequisite;
        verifierCalls = 0;
        auto strategyMismatch = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {true}, verifierCalls, factoryCapability);
        require(strategyMismatch.apply() &&
                    state->enableCalls == 0 &&
                    state->enableStrategyCalls == 1 &&
                    state->requestedStrategies.size() == 1 &&
                    state->requestedStrategies.front() ==
                        fic::platform::PamFaillockStrategy::PreauthRequired,
                "strategy mismatch did not request the configured strategy");

        // A refused strategy transition must fail the activation without
        // any non-strategy mutation.
        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
        state->activeStrategy =
            fic::platform::PamFaillockStrategy::PreauthRequisite;
        state->canEnableStrategyResult = false;
        verifierCalls = 0;
        auto strategyRefused = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {true}, verifierCalls, factoryCapability);
        require(!strategyRefused.apply() &&
                    state->enableStrategyCalls == 0 &&
                    state->enableCalls == 0 && verifierCalls == 0,
                "refused strategy transition was bypassed");

        // A failing strategy transition must fail the activation.
        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
        state->activeStrategy =
            fic::platform::PamFaillockStrategy::Authsucc;
        state->enableStrategyResult = false;
        verifierCalls = 0;
        auto strategyTransitionFailed = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {}, verifierCalls, factoryCapability);
        require(!strategyTransitionFailed.apply() &&
                    state->enableStrategyCalls == 1 && verifierCalls == 0,
                "failed strategy transition was accepted");

        // An unsupported strategy value must be rejected before any
        // manager call; the legacy ENABLE value is not a strategy.
        writeFile(
            root / "config/IDENTITY_ACCESS.conf",
            "enable_authentication_lockout.status=ENABLE\n"
            "enable_authentication_lockout.value=ENABLE\n"
            "enable_password_history.status=ENABLE\n"
            "enable_password_history.value=ENABLE\n"
            "enable_password_quality.status=DISABLE\n"
            "enable_password_quality.value=ENABLE\n");
        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
        state->activeStrategy =
            fic::platform::PamFaillockStrategy::PreauthRequired;
        verifierCalls = 0;
        auto unsupportedValue = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {}, verifierCalls, factoryCapability);
        require(!unsupportedValue.apply() && state->inspectCalls == 0 &&
                    !unsupportedValue.strategyForValue("ENABLE").has_value() &&
                    unsupportedValue.strategyForValue("authsucc").has_value(),
                "legacy ENABLE value was accepted as a faillock strategy");
        writeFile(
            root / "config/IDENTITY_ACCESS.conf",
            "enable_authentication_lockout.status=ENABLE\n"
            "enable_authentication_lockout.value=preauth_required\n"
            "enable_password_history.status=ENABLE\n"
            "enable_password_history.value=ENABLE\n"
            "enable_password_quality.status=DISABLE\n"
            "enable_password_quality.value=ENABLE\n");

        // Joint C2 password topology contract: password capabilities NEVER
        // reach the legacy single-capability manager path. Without the
        // production coordinator factory the apply fails closed BEFORE any
        // manager interaction. (The activation success/failure matrix of
        // the joint path is covered by pam_password_wiring_tests; the
        // legacy manager path below stays exercised by the authentication
        // lockout cases.)
        state = std::make_shared<ManagerState>();
        state->inspectResult = false;
        verifierCalls = 0;
        auto inspectionFailure = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {}, verifierCalls, factoryCapability);
        require(!inspectionFailure.apply() && state->inspectCalls == 0 &&
                    state->canEnableCalls == 0 && state->enableCalls == 0 &&
                    state->disableCalls == 0 && verifierCalls == 0,
                "password capability reached the legacy manager path");

        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Broken;
        verifierCalls = 0;
        auto broken = makePolicy(
            platform, fic::platform::PamCapability::PasswordQuality,
            state, {}, verifierCalls, factoryCapability);
        require(!broken.apply() && state->inspectCalls == 0 &&
                    state->canEnableCalls == 0 && state->enableCalls == 0 &&
                    verifierCalls == 0,
                "password capability mutated a broken topology");

        state = std::make_shared<ManagerState>();
        verifierCalls = 0;
        auto disabled = makePolicy(
            platform, fic::platform::PamCapability::PasswordQuality,
            state, {false}, verifierCalls, factoryCapability);
        require(!disabled.isEnabled() && state->disableCalls == 0 &&
                    disabled.getDefaultValue() == "ENABLE",
                "disabled activation policy changed topology semantics");

        const fs::path externalAltRoot = root / "alt-external";
        writeFile(externalAltRoot / "security/pam_faillock.so", "fixture\n");
        writeFile(externalAltRoot / "security/pam_tcb.so", "fixture\n");
        writeFile(externalAltRoot / "pam.d/system-auth-local-only",
                  "#%PAM-1.0\n"
                  "auth required pam_tcb.so shadow fork nullok\n"
                  "account required pam_tcb.so shadow fork\n");
        fs::create_directories(externalAltRoot / "run");
        const auto externalAltPlatform =
            makeAltLockoutPlatform(externalAltRoot);
        fic::identity::pam::AltPamFaillockTopologyManager seedExternalManager(
            externalAltPlatform, altLockoutOptions(externalAltRoot));
        require(seedExternalManager.enable(error), error);
        std::istringstream managedInput(readFile(
            externalAltRoot / "pam.d/system-auth-local-only"));
        std::string externalAltFaillock;
        std::string managedLine;
        while (std::getline(managedInput, managedLine)) {
            if (managedLine.rfind("# BEGIN FIC ", 0) == 0 ||
                managedLine.rfind("# END FIC ", 0) == 0 ||
                managedLine.rfind("# FIC ORIGINAL ", 0) == 0) {
                continue;
            }
            externalAltFaillock += managedLine + "\n";
        }
        writeFile(externalAltRoot / "pam.d/system-auth-local-only",
                  externalAltFaillock);
        fic::identity::pam::PamConfiguration externalAltConfiguration(
            externalAltPlatform);
        fic::identity::pam::PamCapabilityVerification externalVerification;
        require(fic::identity::pam::PamCapabilityVerifier::verify(
                    externalAltConfiguration, externalAltPlatform,
                    {"system-auth-local-only"},
                    fic::platform::PamCapability::AuthenticationLockout,
                    fic::platform::PamProviderKind::PamFaillock,
                    externalVerification,
                    fic::identity::pam::
                        PamCapabilityVerificationMode::Structural),
                "external ALT faillock fixture was not structurally effective: " +
                    fic::identity::pam::formatPamCapabilityVerification(
                        externalVerification));
        fic::identity::pam::AltPamFaillockTopologyManager externalManager(
            externalAltPlatform, altLockoutOptions(externalAltRoot));
        fic::identity::pam::PamTopologyStatus externalStatus;
        require(externalManager.inspect(externalStatus, error) &&
                    externalStatus.state !=
                        fic::identity::pam::PamTopologyState::Enabled,
                "ALT manager reported external structurally valid faillock as "
                "FIC-owned enabled topology");
        auto externalAltPolicy = makeAltLockoutPolicy(
            externalAltPlatform, externalAltRoot);
        require(!externalAltPolicy.apply() &&
                    readFile(externalAltRoot /
                             "pam.d/system-auth-local-only") ==
                        externalAltFaillock,
                "activation policy bypassed ALT faillock ownership or mutated it");

        const fs::path ownedAltRoot = root / "alt-owned";
        writeFile(ownedAltRoot / "security/pam_faillock.so", "fixture\n");
        writeFile(ownedAltRoot / "security/pam_tcb.so", "fixture\n");
        writeFile(
            ownedAltRoot / "pam.d/system-auth-local-only",
            "#%PAM-1.0\n"
            "auth required pam_tcb.so shadow fork nullok\n"
            "account required pam_tcb.so shadow fork\n");
        fs::create_directories(ownedAltRoot / "run");
        const auto ownedAltPlatform = makeAltLockoutPlatform(ownedAltRoot);
        fic::identity::pam::AltPamFaillockTopologyManager ownedManager(
            ownedAltPlatform, altLockoutOptions(ownedAltRoot));
        require(ownedManager.enable(error), error);
        const std::string ownedAltFaillock = readFile(
            ownedAltRoot / "pam.d/system-auth-local-only");
        auto ownedAltPolicy = makeAltLockoutPolicy(
            ownedAltPlatform, ownedAltRoot);
        require(!ownedAltPolicy.apply() &&
                    readFile(ownedAltRoot /
                             "pam.d/system-auth-local-only") ==
                        ownedAltFaillock,
                "orphaned FIC-owned ALT faillock must fail closed without mutation");

        const fs::path externalHistoryRoot = root / "alt-external-history";
        writeFile(externalHistoryRoot / "security/pam_pwhistory.so",
                  "fixture\n");
        writeFile(externalHistoryRoot / "security/pam_tcb.so", "fixture\n");
        const std::string externalHistory =
            "#%PAM-1.0\n"
            "password required pam_pwhistory.so use_authtok "
            "conf=/etc/security/fic-pwhistory.conf\n"
            "password required pam_tcb.so use_authtok shadow fork nullok "
            "write_to=tcb\n";
        writeFile(externalHistoryRoot / "pam.d/system-auth-local-only",
                  externalHistory);
        fs::create_directories(externalHistoryRoot / "run");
        fic::platform::PamPlatformConfig externalHistoryPlatform;
        externalHistoryPlatform.configDirectories = {
            externalHistoryRoot / "pam.d"};
        externalHistoryPlatform.moduleDirectories = {
            externalHistoryRoot / "security"};
        externalHistoryPlatform.scopes = {{
            fic::platform::PamScope::LocalPasswordChange,
            {"system-auth-local-only"}}};
        externalHistoryPlatform.capabilities = {{
            fic::platform::PamCapability::PasswordHistory,
            fic::platform::PamProviderKind::PamPwhistory,
            fic::platform::PamScope::LocalPasswordChange,
            "/etc/security/fic-pwhistory.conf",
            fic::platform::PamTopologyStrategyKind::AltTcbManaged,
            externalHistoryRoot / "pam.d/system-auth-local-only"}};
        fic::identity::pam::PamConfiguration externalHistoryConfiguration(
            externalHistoryPlatform);
        fic::identity::pam::PamCapabilityVerification historyVerification;
        require(fic::identity::pam::PamCapabilityVerifier::verify(
                    externalHistoryConfiguration, externalHistoryPlatform,
                    {"system-auth-local-only"},
                    fic::platform::PamCapability::PasswordHistory,
                    fic::platform::PamProviderKind::PamPwhistory,
                    historyVerification,
                    fic::identity::pam::
                        PamCapabilityVerificationMode::Structural),
                "external ALT password-history fixture was not structurally "
                "effective: " +
                    fic::identity::pam::formatPamCapabilityVerification(
                        historyVerification));
        fic::identity::pam::AltPamPasswordHistoryTopologyOptions historyOptions;
        historyOptions.lockFilePath = externalHistoryRoot / "run/topology.lock";
        historyOptions.lockDebugLogPath =
            externalHistoryRoot / "lock-debug.log";
        historyOptions.stateDirectory = externalHistoryRoot / "state";
        historyOptions.historyFile = historyOptions.stateDirectory / "opasswd";
        historyOptions.transactionLockFile =
            historyOptions.stateDirectory / ".lock";
        historyOptions.storageOwner = ::geteuid();
        historyOptions.storageGroup = ::getegid();
        historyOptions.semanticVerifier = [](std::string& semanticError) {
            semanticError.clear();
            return true;
        };
        fic::identity::pam::AltPamPasswordHistoryTopologyManager historyManager(
            externalHistoryPlatform, historyOptions);
        fic::identity::pam::PamTopologyStatus historyStatus;
        require(!historyManager.inspect(historyStatus, error) &&
                    historyStatus.state ==
                        fic::identity::pam::PamTopologyState::Broken,
                "ALT manager accepted external structurally valid password "
                "history");
        PamCapabilityActivationPolicyOptions historyPolicyOptions;
        historyPolicyOptions.managerFactory =
            [externalHistoryPlatform, historyOptions](
                const auto&, const auto&, std::string& factoryError) {
                factoryError.clear();
                return std::make_unique<fic::identity::pam::
                    AltPamPasswordHistoryTopologyManager>(
                        externalHistoryPlatform, historyOptions);
            };
        PamCapabilityActivationPolicy externalHistoryPolicy(
            externalHistoryPlatform,
            fic::platform::PamCapability::PasswordHistory,
            std::move(historyPolicyOptions));
        require(!externalHistoryPolicy.apply() &&
                    readFile(externalHistoryRoot /
                             "pam.d/system-auth-local-only") ==
                        externalHistory &&
                    !fs::exists(historyOptions.stateDirectory),
                "activation policy bypassed ALT password-history ownership or "
                "mutated it");

        writeFile(
            root / "config/IDENTITY_ACCESS.conf",
            "enable_authentication_lockout.status=ENABLE\n"
            "enable_authentication_lockout.value=ENABLE\n"
            "enable_password_history.status=ENABLE\n"
            "enable_password_history.value=ENABLE\n"
            "enable_password_quality.status=ENABLE\n"
            "enable_password_quality.value=ENABLE\n");
        const fs::path staticRoot = root / "static-passwdqc";
        writeFile(staticRoot / "security/pam_passwdqc.so", "fixture\n");
        writeFile(staticRoot / "passwdqc.conf",
                  "min=disabled,24,11,8,7\n");
        writeFile(staticRoot / "pam.d/passwd",
                  "password required pam_passwdqc.so config=" +
                      (staticRoot / "passwdqc.conf").string() + "\n");
        fic::platform::PamPlatformConfig staticPlatform;
        staticPlatform.configDirectories = {staticRoot / "pam.d"};
        staticPlatform.moduleDirectories = {staticRoot / "security"};
        staticPlatform.scopes = {{
            fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
        staticPlatform.capabilities = {{
            fic::platform::PamCapability::PasswordQuality,
            fic::platform::PamProviderKind::PamPasswdqc,
            fic::platform::PamScope::EffectivePasswordStack,
            staticRoot / "passwdqc.conf",
            fic::platform::PamTopologyStrategyKind::StaticVerifyOnly}};
        fic::platform::PlatformExecutableResolver staticResolver(
            {}, {.enforceTrustedOwnership = false});
        PamCapabilityActivationPolicyOptions staticOptions;
        staticOptions.managerFactory =
            [&staticPlatform, &staticResolver](const auto& capability,
                                               const auto& services,
                                               std::string& factoryError) {
                return fic::identity::pam::createPamTopologyManager(
                    staticPlatform, capability, services, staticResolver,
                    factoryError);
            };
        const std::string staticPamBefore =
            readFile(staticRoot / "pam.d/passwd");
        PamCapabilityActivationPolicy staticPolicy(
            staticPlatform, fic::platform::PamCapability::PasswordQuality,
            std::move(staticOptions));
        require(staticPolicy.apply() &&
                    readFile(staticRoot / "pam.d/passwd") == staticPamBefore,
                "StaticVerifyOnly passwdqc was mutated or rejected");
        {
            std::string journalError;
            auto* journal = fic::rollback::DaemonMutationJournal::instance()
                .tryGet(journalError);
            require(journal != nullptr &&
                        journal->activeRecords({"IDENTITY_ACCESS", "PAM",
                            "enable_password_quality"}).empty(),
                    "StaticVerifyOnly must not create PAM provenance");
        }

        writeFile(
            root / "config/IDENTITY_ACCESS.conf",
            "enable_authentication_lockout.status=ENABLE\n"
            "enable_authentication_lockout.value=preauth_required\n"
            "enable_password_history.status=ENABLE\n"
            "enable_password_history.value=ENABLE\n"
            "enable_password_quality.status=DISABLE\n"
            "enable_password_quality.value=ENABLE\n");

        const fs::path pamAuthUpdate = root / "bin/pam-auth-update";
        writeFile(pamAuthUpdate, "#!/bin/sh\nexit 0\n");
        require(::chmod(pamAuthUpdate.c_str(), 0755) == 0,
                "could not make fake pam-auth-update executable");
        fic::platform::PlatformExecutables executableConfig;
        executableConfig.entries = {{
            fic::platform::ExecutableId::PamAuthUpdate,
            {pamAuthUpdate}}};
        fic::platform::PlatformExecutableResolver resolver(
            executableConfig, {.enforceTrustedOwnership = false});
        std::string observedExecutable;
        std::vector<std::string> observedArguments;
        bool observedClearEnvironment = false;
        const fs::path pamAuthUpdateState = root / "var/lib/pam";
        fs::create_directories(pamAuthUpdateState);
        writeFile(root / "security/pam_faillock.so", "fixture\n");
        writeFile(root / "security/pam_unix.so", "fixture\n");
        const std::string faillockConfigArgument =
            " conf=" + (root / "security/faillock.conf").string();
        // Effective login stacks as pam-auth-update would generate them for
        // each strategy (simplified: pam-auth-update template boilerplate
        // omitted, module order preserved).
        const std::string lockoutPreauthRequisite =
            "auth requisite pam_faillock.so preauth" +
            faillockConfigArgument + "\n"
            "auth [success=2 default=ignore] pam_unix.so nullok\n"
            "auth [default=die] pam_faillock.so authfail" +
            faillockConfigArgument + "\n"
            "auth requisite pam_deny.so\n"
            "auth required pam_permit.so\n"
            "account required pam_faillock.so" +
            faillockConfigArgument + "\n"
            "account required pam_unix.so\n";
        const std::string lockoutPreauthRequired =
            "auth required pam_faillock.so preauth" +
            faillockConfigArgument + "\n"
            "auth [success=2 default=ignore] pam_unix.so nullok\n"
            "auth [default=die] pam_faillock.so authfail" +
            faillockConfigArgument + "\n"
            "auth requisite pam_deny.so\n"
            "auth required pam_permit.so\n"
            "account required pam_faillock.so" +
            faillockConfigArgument + "\n"
            "account required pam_unix.so\n";
        const std::string lockoutAuthsucc =
            "auth [success=2 default=ignore] pam_unix.so nullok\n"
            "auth [default=die] pam_faillock.so authfail" +
            faillockConfigArgument + "\n"
            "auth requisite pam_deny.so\n"
            "auth required pam_permit.so\n"
            "auth required pam_faillock.so authsucc" +
            faillockConfigArgument + "\n";
        struct StrategyRecipe {
            std::vector<std::string> ids;
            std::string content;
        };
        const std::map<fic::platform::PamFaillockStrategy, StrategyRecipe>
            recipes = {
                {fic::platform::PamFaillockStrategy::PreauthRequisite,
                 {{"fic-faillock-notify", "fic-faillock-authfail"},
                  lockoutPreauthRequisite}},
                {fic::platform::PamFaillockStrategy::PreauthRequired,
                 {{"fic-faillock-preauth-required", "fic-faillock-authfail"},
                  lockoutPreauthRequired}},
                {fic::platform::PamFaillockStrategy::Authsucc,
                 {{"fic-faillock-authsucc", "fic-faillock-authfail"},
                  lockoutAuthsucc}}};
        // Simulated pam-auth-update: applies the --disable/--enable profile
        // selection, rewrites the effective stack and the state database.
        const auto applyPamAuthUpdate =
            [&](const std::vector<std::string>& arguments)
            -> std::optional<fic::platform::PamFaillockStrategy> {
            std::vector<std::string> enableIds;
            bool collecting = false;
            for (const std::string& argument : arguments) {
                if (argument == "--enable") {
                    collecting = true;
                    continue;
                }
                if (argument == "--disable") {
                    collecting = false;
                    continue;
                }
                if (collecting) {
                    enableIds.push_back(argument);
                }
            }
            std::sort(enableIds.begin(), enableIds.end());
            std::optional<fic::platform::PamFaillockStrategy> applied;
            for (const auto& [strategy, recipe] : recipes) {
                std::vector<std::string> sortedIds = recipe.ids;
                std::sort(sortedIds.begin(), sortedIds.end());
                if (sortedIds == enableIds) {
                    applied = strategy;
                }
            }
            if (!applied.has_value()) {
                return std::nullopt;
            }
            const StrategyRecipe& recipe = recipes.at(*applied);
            writeFile(root / "pam.d/login", recipe.content);
            std::string stateContent;
            for (const std::string& id : recipe.ids) {
                stateContent += "Module: " + id + "\n";
            }
            writeFile(pamAuthUpdateState / "auth",
                      "Module: unix\n" + stateContent);
            writeFile(pamAuthUpdateState / "account",
                      "Module: unix\n" + stateContent);
            return applied;
        };
        fic::identity::pam::PamAuthUpdateTopologyManagerOptions commandOptions;
        commandOptions.stateDirectory = pamAuthUpdateState;
        commandOptions.configDirectory = root / "pam.d";
        commandOptions.runner =
            [&](const std::string& executable,
                const std::vector<std::string>& arguments,
                const ProcessOptions& processOptions) {
                observedExecutable = executable;
                observedArguments = arguments;
                observedClearEnvironment = processOptions.clearEnvironment;
                ProcessResult result;
                result.started = true;
                if (!arguments.empty() && arguments.front() == "--disable" &&
                    std::find(arguments.begin(), arguments.end(),
                              "--enable") == arguments.end()) {
                    writeFile(root / "pam.d/login",
                              "auth required pam_unix.so nullok\n"
                              "account required pam_unix.so\n");
                    writeFile(pamAuthUpdateState / "auth", "Module: unix\n");
                    writeFile(pamAuthUpdateState / "account", "Module: unix\n");
                    result.exitCode = 0;
                    return result;
                }
                result.exitCode =
                    applyPamAuthUpdate(arguments).has_value() ? 0 : 1;
                return result;
            };
        fic::identity::pam::PamAuthUpdateTopologyManager commandManager(
            platform, platform.capabilities[0], {"login"}, resolver,
            commandOptions);
        writeFile(root / "pam.d/login",
                  "auth required pam_unix.so nullok\n"
                  "account required pam_unix.so\n");
        std::error_code ignored;
        fs::remove(pamAuthUpdateState / "auth", ignored);
        fs::remove(pamAuthUpdateState / "account", ignored);
        require(commandManager.enable(error) &&
                    observedExecutable == pamAuthUpdate.string() &&
                    observedClearEnvironment,
                "pam-auth-update activation did not use typed argv");
        require(observedArguments == std::vector<std::string>{
                    "--disable", "fic-faillock-notify",
                    "fic-faillock-authsucc",
                    "--enable", "fic-faillock-preauth-required",
                    "fic-faillock-authfail"},
                "pam-auth-update activation did not combine the disable and "
                "enable selection in a single invocation");
        // Idempotency at the manager level.
        require(commandManager.enable(error) &&
                    observedArguments.front() == "--disable",
                "repeated pam-auth-update activation was not idempotent");
        require(commandManager.disable(error) &&
                    observedArguments.front() == "--disable" &&
                    observedArguments.size() == 3,
                "pam-auth-update did not release only FIC selections");
        require(commandManager.enable(error), error);

        int pamAuthUpdateCalls = 0;
        fic::identity::pam::PamAuthUpdateTopologyManagerOptions policyCommand;
        policyCommand.stateDirectory = pamAuthUpdateState;
        policyCommand.configDirectory = root / "pam.d";
        policyCommand.runner =
            [&](const std::string&,
                const std::vector<std::string>& arguments,
                const ProcessOptions&) {
                ++pamAuthUpdateCalls;
                ProcessResult result;
                result.started = true;
                result.exitCode =
                    applyPamAuthUpdate(arguments).has_value() ? 0 : 1;
                return result;
            };
        const auto makePamAuthUpdatePolicy = [&]() {
            PamCapabilityActivationPolicyOptions policyOptions;
            policyOptions.managerFactory =
                [&](const auto& capability, const auto& services,
                    std::string& factoryError) {
                    factoryError.clear();
                    return std::make_unique<fic::identity::pam::
                        PamAuthUpdateTopologyManager>(
                            platform, capability, services, resolver,
                            policyCommand);
                };
            return PamCapabilityActivationPolicy(
                platform,
                fic::platform::PamCapability::AuthenticationLockout,
                std::move(policyOptions));
        };

        writeFile(root / "pam.d/login", lockoutPreauthRequired);
        auto pamAuthUpdateAlreadyEnabled = makePamAuthUpdatePolicy();
        const bool alreadyEnabledApplied = pamAuthUpdateAlreadyEnabled.apply();
        require(
            !alreadyEnabledApplied && pamAuthUpdateCalls == 0,
            "orphaned pam-auth-update topology was accepted or mutated: apply=" +
                std::string(alreadyEnabledApplied ? "true" : "false") +
                " calls=" + std::to_string(pamAuthUpdateCalls) +
                " error=" + error);

        writeFile(root / "pam.d/login",
                  "auth required pam_unix.so nullok\n"
                  "account required pam_unix.so\n");
        fs::remove(pamAuthUpdateState / "auth");
        fs::remove(pamAuthUpdateState / "account");
        auto pamAuthUpdateDisabled = makePamAuthUpdatePolicy();
        require(pamAuthUpdateDisabled.apply() && pamAuthUpdateCalls == 1,
                "disabled pam-auth-update topology was not activated once");
        require(pamAuthUpdateDisabled.apply() && pamAuthUpdateCalls == 1,
                "repeated pam-auth-update activation was not idempotent");
        {
            std::string journalError;
            auto* journal = fic::rollback::DaemonMutationJournal::instance()
                .tryGet(journalError);
            require(journal != nullptr, journalError);
            const auto records = journal->activeRecords(
                {"IDENTITY_ACCESS", "PAM", "enable_authentication_lockout"});
            require(records.size() == 1 &&
                        records.front().status ==
                            fic::rollback::MutationStatus::Applied,
                    "native PAM activation must commit Applied provenance");
        }

        writeFile(root / "pam.d/login", "auth include login\n");
        auto pamAuthUpdateBroken = makePamAuthUpdatePolicy();
        require(!pamAuthUpdateBroken.apply() && pamAuthUpdateCalls == 1,
                "broken pam-auth-update topology was mutated");

        auto factoryManager =
            fic::identity::pam::createPamTopologyManager(
                platform, platform.capabilities[0], {"login"}, resolver,
                error);
        require(dynamic_cast<fic::identity::pam::
                    PamAuthUpdateTopologyManager*>(factoryManager.get()) !=
                    nullptr,
                "factory did not select pam-auth-update by typed strategy");

        auto staticQuality = platform.capabilities[2];
        staticQuality.topology =
            fic::platform::PamTopologyStrategyKind::StaticVerifyOnly;
        staticQuality.activationIdentifiers.clear();
        factoryManager = fic::identity::pam::createPamTopologyManager(
            platform, staticQuality, {"passwd"}, resolver, error);
        require(factoryManager != nullptr &&
                    !factoryManager->canEnable(error),
                "StaticVerifyOnly factory result allowed topology mutation");

        auto altLockout = platform.capabilities[0];
        altLockout.topology =
            fic::platform::PamTopologyStrategyKind::AltTcbManaged;
        altLockout.activationIdentifiers.clear();
        factoryManager = fic::identity::pam::createPamTopologyManager(
            platform, altLockout, {"login"}, resolver, error);
        require(dynamic_cast<fic::identity::pam::
                    AltPamFaillockTopologyManager*>(factoryManager.get()) !=
                    nullptr,
                "factory did not select the ALT faillock manager");
        testPamJournalLifecycle(root, platform);
        testJournalBoundPreparedPartialRecovery(root, platform);
        testExternalPwquality(root);
    } catch (const std::exception& exception) {
        std::cerr << "PamCapabilityActivationPolicyTests failed: "
                  << exception.what() << '\n';
        fs::remove_all(root);
        return EXIT_FAILURE;
    }
    fs::remove_all(root);
    std::cout << "PamCapabilityActivationPolicyTests passed\n";
    return EXIT_SUCCESS;
}
