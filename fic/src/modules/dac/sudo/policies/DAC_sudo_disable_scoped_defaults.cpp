#include "modules/dac/sudo/policies/DAC_sudo_disable_scoped_defaults.h"
#include "modules/dac/sudo/SudoersConfiguration.h"
#include "rollback/DaemonMutationJournal.h"

#include <filesystem>
#include <mutex>
#include <string>
#include <utility>

namespace {

// Serializes scoped-Defaults backend access against the rollback executor,
// exactly like the managed-Defaults path in Sudo.cpp.
std::mutex& scopedDefaultsMutex() {
    static std::mutex mutex;
    return mutex;
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
    std::string loadError;
    if (!configuration.load(loadError)) {
        this->log("Не удалось проанализировать sudoers: " + loadError,
                  logLevel::ERROR);
        return false;
    }

    const std::vector<std::string> violations =
        configuration.scopedDefaultsViolations();
    if (violations.empty()) {
        this->log("Активных контекстных Defaults не обнаружено", logLevel::INFO);
        return true;
    }
    for (const std::string& violation : violations) {
        this->log("Контекстные Defaults: " + violation, logLevel::WARN);
    }

    // Crash-consistent journaling: the record is prepared BEFORE the
    // filesystem mutation, so a crash in between still leaves provenance that
    // the rollback executor can resolve. The provenance ids are generated HERE,
    // before the mutation, and handed to the backend, so the prepared payload
    // is already complete and never has to be rewritten afterwards.
    const std::vector<std::string> wrapperIds =
        SudoersConfiguration::planScopedDefaultsWrapperIds(violations.size());
    fic::rollback::MutationId mutationId = 0;
    std::string journalError;
    fic::rollback::UndoAction undo{
        fic::rollback::MutationBackend::Sudo,
        fic::rollback::UndoReleaseSudoScopedDefaults{this->policyName, wrapperIds}};
    if (!fic::rollback::recordPreparedMutation(
            this->policyRef(), this->policyName, undo, mutationId, journalError)) {
        this->log("Не удалось подготовить запись mutation journal: " +
                      journalError,
                  logLevel::ERROR);
        return false;
    }

    const SudoersOperationResult operation =
        configuration.disableScopedDefaults(this->policyName, wrapperIds);
    if (!operation.ok) {
        std::string discardError;
        if (!fic::rollback::discardMutation(mutationId, discardError)) {
            this->log("Ошибка удаления подготовленной записи mutation journal: " +
                          discardError,
                      logLevel::WARN);
        }
        for (const std::string& diagnostic : operation.diagnostics) {
            this->log(diagnostic, logLevel::WARN);
        }
        this->log(operation.message, logLevel::ERROR);
        return false;
    }

    if (!fic::rollback::commitMutation(mutationId, journalError)) {
        this->log("Мутация применена, но запись mutation journal не зафиксирована: " +
                      journalError,
                  logLevel::ERROR);
        return false;
    }

    for (const std::string& diagnostic : operation.diagnostics) {
        this->log(diagnostic, logLevel::INFO);
    }
    this->log(operation.message, logLevel::INFO);
    return true;
}
