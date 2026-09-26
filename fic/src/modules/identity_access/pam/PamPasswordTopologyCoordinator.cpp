#include "modules/identity_access/pam/PamPasswordTopologyCoordinator.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

#include <rollback/DaemonMutationJournal.h>

#include <optional>
#include <utility>

namespace fic::identity::pam {
namespace {

constexpr const char* kQualityActivationPolicyName =
    "enable_password_quality";
constexpr const char* kHistoryActivationPolicyName =
    "enable_password_history";

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
            lastResult_, error)) {
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

std::unique_ptr<PamPasswordTopologyCoordinator>
PamPasswordTopologyCoordinator::makeProduction(
    const fic::platform::PlatformExecutableResolver& executables,
    std::string& error) {
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (journal == nullptr) {
        error = "PAM mutation journal unavailable: " + error;
        return nullptr;
    }
    return std::unique_ptr<PamPasswordTopologyCoordinator>(
        new PamPasswordTopologyCoordinator(*journal, executables));
}

} // namespace fic::identity::pam