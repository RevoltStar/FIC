#include "modules/identity_access/pam/PamPasswordTopologyCoordinator.h"

#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/policies/PamPasswordHistoryDepthPolicy.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

#include <rollback/DaemonMutationJournal.h>

#include <charconv>
#include <optional>
#include <utility>

namespace fic::identity::pam {
namespace {

constexpr const char* kQualityActivationPolicyName =
    "enable_password_quality";
constexpr const char* kHistoryActivationPolicyName =
    "enable_password_history";
constexpr const char* kHistoryDepthPolicyName = "password_history_depth";
constexpr const char* kHistoryEnforcePolicyName =
    "password_history_enforce_for_root";

bool parseUnsignedFull(const std::string& text, unsigned& value) {
    if (text.empty()) {
        return false;
    }
    const char* first = text.data();
    const char* last = first + text.size();
    const auto result = std::from_chars(first, last, value);
    return result.ec == std::errc{} && result.ptr == last;
}

} // namespace

bool readJointPasswordConfigIntent(
    PamPasswordRequestedState& requested, std::string& error,
    std::filesystem::path identityConfigDirectory) {
    std::optional<ModuleConfigFileHandler> config;
    if (identityConfigDirectory.empty()) {
        config.emplace("IDENTITY_ACCESS");
    } else {
        config.emplace(identityConfigDirectory, "IDENTITY_ACCESS");
    }
    if (!config->loadConfig()) {
        error = "could not load the IDENTITY_ACCESS module configuration: "
                "the joint password topology requested state is unknown";
        return false;
    }
    requested.qualityRequested =
        config->getPolicyStatus(kQualityActivationPolicyName) == "ENABLE";
    requested.historyRequested =
        config->getPolicyStatus(kHistoryActivationPolicyName) == "ENABLE";
    error.clear();
    return true;
}

bool readJointPasswordDesiredState(
    PamPasswordRequestedState& requested,
    const fic::platform::PamPlatformConfig& platform,
    std::string& error,
    std::filesystem::path identityConfigDirectory) {
    requested = PamPasswordRequestedState{};
    // ONE configuration snapshot: the joint (Q, H) request and the managed
    // history options come from the SAME loaded ModuleConfigFileHandler,
    // never from two independent reads of different config generations.
    std::optional<ModuleConfigFileHandler> config;
    if (identityConfigDirectory.empty()) {
        config.emplace("IDENTITY_ACCESS");
    } else {
        config.emplace(identityConfigDirectory, "IDENTITY_ACCESS");
    }
    if (!config->loadConfig()) {
        error = "could not load the IDENTITY_ACCESS module configuration: "
                "the joint password desired state is unknown";
        return false;
    }
    requested.qualityRequested =
        config->getPolicyStatus(kQualityActivationPolicyName) == "ENABLE";
    requested.historyRequested =
        config->getPolicyStatus(kHistoryActivationPolicyName) == "ENABLE";

    const auto* historyCapability = capabilityConfig(
        platform, fic::platform::PamCapability::PasswordHistory);
    if (historyCapability == nullptr ||
        historyCapability->configurationMode !=
            fic::platform::PamCapabilityConfigurationMode::
                ModuleArguments) {
        // Provider-config-file (and absent) capabilities: the slot bodies
        // carry no optional arguments; the options are governed by the
        // provider config file through the classic option-policy path.
        error.clear();
        return true;
    }

    // Step 6 follow-up (P3): the pwhistoryRemember evidence flag is the
    // mandatory gate of the module-arguments remember rendering. Without
    // the platform evidence the reader must NEVER silently render a
    // default or configured remember=N token (the platform profile itself
    // asserts the absence of the supporting evidence), so the whole
    // module-arguments desired state fails closed.
    if (!historyCapability->moduleArgumentSupport.pwhistoryRemember) {
        error = "the platform profile does not evidence the pam_pwhistory "
                "`remember` module-argument support for the "
                "module-arguments configuration mode: the joint password "
                "desired state is unknown (fail closed)";
        return false;
    }

    // remember=N. An unconfigured depth uses the explicit POLICY default
    // (kPasswordHistoryDepthDefault — the same value the policy type
    // reports as effective); a configured value must satisfy the existing
    // policy contract range or the whole intent fails closed.
    requested.historyOptions.remember = kPasswordHistoryDepthDefault;
    if (config->hasConfiguredValue(kHistoryDepthPolicyName)) {
        const std::string raw =
            config->getPolicyValue(kHistoryDepthPolicyName);
        unsigned depth = 0;
        if (!parseUnsignedFull(raw, depth) ||
            depth < kPasswordHistoryDepthMin ||
            depth > kPasswordHistoryDepthMax) {
            error = "configured " + std::string(kHistoryDepthPolicyName) +
                " value \"" + raw +
                "\" violates the policy contract (" +
                std::to_string(kPasswordHistoryDepthMin) + ".." +
                std::to_string(kPasswordHistoryDepthMax) +
                "): the joint password desired state is unknown "
                "(fail closed)";
            return false;
        }
        requested.historyOptions.remember = depth;
    }

    // enforce_for_root: bare-token grammar — true -> token present,
    // false -> token absent. Never rendered as `enforce_for_root=0`.
    // The token is only accepted when the platform profile evidences the
    // argument support; an unsupported but configured `yes` fails closed
    // instead of writing a token the module may not accept.
    if (config->hasConfiguredValue(kHistoryEnforcePolicyName)) {
        const std::string raw =
            config->getPolicyValue(kHistoryEnforcePolicyName);
        if (raw == "yes") {
            if (!historyCapability->moduleArgumentSupport
                     .pwhistoryEnforceForRoot) {
                error = "configured " +
                    std::string(kHistoryEnforcePolicyName) +
                    "=yes is not supported by the "
                    "platform evidence (fail closed)";
                return false;
            }
            requested.historyOptions.enforceForRoot = true;
        } else if (raw == "no") {
            requested.historyOptions.enforceForRoot = false;
        } else {
            error = "configured " +
                std::string(kHistoryEnforcePolicyName) + " value \"" +
                raw + "\" is not yes/no: the joint password desired "
                      "state is unknown (fail closed)";
            return false;
        }
    }
    error.clear();
    return true;
}

PamPasswordTopologyCoordinator::PamPasswordTopologyCoordinator(
    fic::rollback::MutationJournal& journal,
    const fic::platform::PlatformExecutableResolver& executables,
    Options options)
    : journal_(journal),
      executables_(executables),
      options_(std::move(options)),
      executor_(journal_, executables_, options_.executorOptions,
                options_.configDirectory, options_.stateDirectory) {}

bool PamPasswordTopologyCoordinator::readDesiredState(
    PamPasswordRequestedState& requested, std::string& error) const {
    if (options_.desiredStateReader) {
        return options_.desiredStateReader(requested, error);
    }
    return readJointPasswordConfigIntent(
        requested, error, options_.identityConfigDirectory);
}

std::string PamPasswordTopologyCoordinator::classifyFailure(
    const std::string& executorError) const {
    std::string classification =
        "C2 joint password topology transition failed";
    if (lastResult_.compensated) {
        classification += lastResult_.compensatedStateProven
            ? " (attempted changes compensated; pre-transition topology "
              "proven restored)"
            : " (COMPENSATION STOPPED: joint password topology NOT proven "
              "restored; fail closed)";
    } else if (lastResult_.changedSystemState) {
        classification += " (partial mutation may be installed)";
    }
    if (!lastResult_.executedActions.empty()) {
        classification += "; proven actions:";
        for (const std::string& action : lastResult_.executedActions) {
            classification += " " + action;
        }
    }
    return classification + ": " + executorError;
}

bool PamPasswordTopologyCoordinator::transition(
    const PamPasswordRequestedState& requested, std::string& error) {
    lastResult_ = PamPasswordTransitionResult{};
    if (!executor_.transition(
            requested.qualityRequested, requested.historyRequested,
            requested.historyOptions, lastResult_, error)) {
        error = classifyFailure(error);
        return false;
    }
    error.clear();
    return true;
}

bool PamPasswordTopologyCoordinator::applyJointRequestedState(
    std::string& error) {
    PamPasswordRequestedState requested;
    if (!readDesiredState(requested, error)) {
        return false;
    }
    return transition(requested, error);
}

void PamPasswordTopologyCoordinator::
    setHistoryJournalCompletionFaultHookForTests(
        PamManagedPasswordSlotWriter::JournalCompletionFaultHook hook) {
    executor_.setHistoryJournalCompletionFaultHookForTests(std::move(hook));
}

std::unique_ptr<PamPasswordTopologyCoordinator>
PamPasswordTopologyCoordinator::makeProduction(
    const fic::platform::PlatformExecutableResolver& executables,
    const fic::platform::PlatformProfile& platform,
    std::string& error) {
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (journal == nullptr) {
        error = "PAM mutation journal unavailable: " + error;
        return nullptr;
    }
    std::unique_ptr<PamPasswordTopologyCoordinator> coordinator(
        new PamPasswordTopologyCoordinator(*journal, executables));
    // Production desired-state reader: ONE configuration snapshot carries
    // the joint (Q, H) request AND the managed history options (per the
    // platform pwhistory capability mode).
    const fic::platform::PamPlatformConfig pamConfig = platform.pam;
    coordinator->options_.desiredStateReader =
        [pamConfig](PamPasswordRequestedState& requested,
                    std::string& readerError) {
            return readJointPasswordDesiredState(
                requested, pamConfig, readerError);
        };
    return coordinator;
}

} // namespace fic::identity::pam