#include "modules/dac/sudo/policies/DAC_sudo_disable_scoped_defaults.h"
#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersScopedDefaultsLifecycle.h"
#include "rollback/DaemonMutationJournal.h"

#include <filesystem>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace {

// Scoped-Defaults backend access is serialized by the SHARED SUDO mutation
// mutex, so apply and rollback cannot interleave on the same sudoers graph.
std::mutex& scopedDefaultsMutex() {
    return SudoersConfiguration::mutationMutex();
}

} // namespace

DAC_sudo_disable_scoped_defaults::DAC_sudo_disable_scoped_defaults(
    const fic::platform::SudoPlatformConfig& platformConfig,
    const fic::platform::PlatformExecutableResolver& executables)
    : Sudo(platformConfig, executables) {
    this->policyName = "sudo_disable_scoped_defaults";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

DAC_sudo_disable_scoped_defaults::~DAC_sudo_disable_scoped_defaults() {

}

bool DAC_sudo_disable_scoped_defaults::apply() {
    const auto configured = this->getValue();
    if (!configured || *configured != "ENABLE") {
        this->log("Эталон политики запрета контекстных Defaults не равен ENABLE",
                  logLevel::ERROR);
        return false;
    }

    const std::lock_guard<std::mutex> lock(scopedDefaultsMutex());

    SudoersConfigurationOptions options;
    options.mainPath = platformConfig_.mainConfigPath;
    options.managedPath = platformConfig_.managedConfigPath;
    std::filesystem::path validator;
    std::string resolverError;
    if (!executables_.resolve(fic::platform::ExecutableId::Visudo, validator,
                              resolverError)) {
        this->log("Не удалось выбрать visudo: " + resolverError, logLevel::ERROR);
        return false;
    }
    options.validatorPath = validator.string();

    SudoersConfiguration configuration(std::move(options));

    // The journal state machine (Prepared recovery, ownership validation,
    // planning, prepare -> mutate -> commit/discard) lives in
    // ScopedDefaultsLifecycle so it can be driven directly by tests. The policy
    // only resolves options, serializes on the shared SUDO mutation lock, calls
    // the lifecycle and logs the result.
    fic::sudoers::ScopedDefaultsLifecycleDeps deps;
    deps.configuration = &configuration;

    std::string journalError;
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr) {
        this->log("Mutation journal недоступен: " + journalError,
                  logLevel::ERROR);
        return false;
    }
    const PolicyRef policyRef = this->policyRef();
    deps.journal.activeRecords = [journal, policyRef](const PolicyRef&) {
        return journal->activeRecords(policyRef);
    };
    deps.journal.prepare = [](const PolicyRef& policy,
                              const std::string& resource,
                              const fic::rollback::UndoAction& undo,
                              fic::rollback::MutationId& id,
                              std::string& error) {
        return fic::rollback::recordPreparedMutation(policy, resource, undo, id,
                                                    error);
    };
    deps.journal.commit = [](fic::rollback::MutationId id, std::string& error) {
        return fic::rollback::commitMutation(id, error);
    };
    deps.journal.discard = [](fic::rollback::MutationId id, std::string& error) {
        return fic::rollback::discardMutation(id, error);
    };
        deps.journal.normalizePreparedToPrevious =
        [](fic::rollback::MutationId id,
           const std::vector<fic::sudoers::SudoScopedDefaultsWrapperProof>& proven,
           std::string& error) {
            std::string journalError;
            fic::rollback::MutationJournal* instance =
                fic::rollback::DaemonMutationJournal::instance().tryGet(
                    journalError);
            if (instance == nullptr) {
                error = journalError;
                return false;
            }
            return instance->normalizeSudoScopedDefaultsPreparedToPrevious(
                id, proven, error);
        };
    deps.journal.proveDurable = [](const std::vector<std::filesystem::path>& paths,
                                   std::string& error) {
        return fic::sudoers::proveObservedStateDurable(paths, error);
    };
deps.hooks.validate = [&configuration](std::string& error) {
        return configuration.validateConfiguration(error);
    };
    deps.hooks.reloadAndVerify = [&configuration](std::string& error) {
        if (!configuration.load(error)) {
            return false;
        }
        return configuration.scopedDefaultsViolations().empty();
    };

    fic::sudoers::ScopedDefaultsLifecycle lifecycle(std::move(deps));
    const fic::sudoers::ScopedDefaultsLifecycleOutcome outcome =
        lifecycle.reconcile(this->policyName);
    for (const std::string& diagnostic : outcome.diagnostics) {
        this->log(diagnostic, logLevel::WARN);
    }
    if (!outcome.ok) {
        this->log(outcome.message, logLevel::ERROR);
        return false;
    }
    this->log(outcome.message, logLevel::INFO);
    return true;
}
