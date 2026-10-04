#include "modules/dac/sudo/policies/DAC_sudo_disable_scoped_defaults.h"
#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersScopedDefaultsTransaction.h"
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
    std::string loadError;
    if (!configuration.load(loadError)) {
        this->log("Не удалось проанализировать sudoers: " + loadError,
                  logLevel::ERROR);
        return false;
    }

    fic::sudoers::ScopedDefaultsTransaction transaction(
        configuration, this->policyName);

    // Current proven ownership: the target proofs of the ACTIVE journal record,
    // which is exactly the set a refresh must carry forward.
    std::vector<fic::rollback::SudoScopedDefaultsWrapperProof> owned;
    {
        std::string journalError;
        fic::rollback::MutationJournal* journal =
            fic::rollback::DaemonMutationJournal::instance().tryGet(journalError);
        if (journal == nullptr) {
            this->log("Mutation journal недоступен: " + journalError,
                      logLevel::ERROR);
            return false;
        }
        for (const fic::rollback::MutationRecord& record :
             journal->activeRecords(this->policyRef())) {
            const auto* payload = std::get_if<
                fic::rollback::UndoReleaseSudoScopedDefaults>(
                    &record.undo.payload);
            if (payload == nullptr) {
                continue;
            }
            for (const fic::rollback::SudoScopedDefaultsWrapperProof& proof :
                 payload->targetProofs) {
                owned.push_back({proof.wrapperId, proof.payloadDigest});
            }
        }
    }

    const std::vector<fic::sudoers::ScopedDefaultsTarget> physical =
        transaction.targets();
    if (physical.empty()) {
        // No violations is NOT success: the preflight proves the wrapper grammar
        // and the journal ownership. An orphan wrapper fails closed and is
        // never adopted here.
        std::string validationError;
        if (!configuration.validateConfiguration(validationError)) {
            this->log("Sudoers не прошёл проверку: " + validationError,
                      logLevel::ERROR);
            return false;
        }
        const std::string refusal = transaction.noopPreflight(owned);
        if (!refusal.empty()) {
            this->log("Отказ: контекстных Defaults нет, но состояние FIC-owned "
                      "не доказано: " + refusal, logLevel::ERROR);
            return false;
        }
        this->log("Активных контекстных Defaults не обнаружено", logLevel::INFO);
        return true;
    }
    for (const std::string& violation :
         configuration.scopedDefaultsViolations()) {
        this->log("Контекстные Defaults: " + violation, logLevel::WARN);
    }

    // The new transition GROWS the ownership set: every wrapper FIC already
    // owns is carried into previousProofs and stays in targetProofs, so a
    // repeated reconciliation can never orphan a previously created wrapper.
    const std::vector<fic::sudoers::SudoScopedDefaultsWrapperProof> targetProofs =
        transaction.planRefresh(owned);
    const std::vector<fic::rollback::SudoScopedDefaultsWrapperProof> newOnes(
        targetProofs.begin() + static_cast<std::ptrdiff_t>(owned.size()),
        targetProofs.end());

    fic::rollback::MutationId mutationId = 0;
    std::string journalError;
    fic::rollback::UndoAction undo{
        fic::rollback::MutationBackend::Sudo,
        // The FULL ownership set is journaled (previous wrappers included):
        // the record must keep authorizing the wrappers FIC created earlier.
        fic::rollback::UndoReleaseSudoScopedDefaults{
            this->policyName, owned, targetProofs}};
    if (!fic::rollback::recordPreparedMutation(
            this->policyRef(),
            fic::sudoers::kScopedDefaultsResource, undo, mutationId,
            journalError)) {
        this->log("Не удалось подготовить запись mutation journal: " +
                      journalError, logLevel::ERROR);
        return false;
    }

    fic::sudoers::SudoScopedDefaultsHooks hooks;
    hooks.validate = [&configuration](std::string& error) {
        return configuration.validateConfiguration(error);
    };
    hooks.reloadAndVerify = [&configuration](std::string& error) {
        if (!configuration.load(error)) {
            return false;
        }
        return configuration.scopedDefaultsViolations().empty();
    };

    fic::sudoers::SudoScopedDefaultsOutcome outcome =
        fic::sudoers::SudoScopedDefaultsOutcome::NoMutation;
    const SudoersOperationResult operation =
        transaction.apply(newOnes, outcome, hooks);
    if (!operation.ok) {
        // The Prepared record may be discarded ONLY when the typed outcome
        // proves no FIC-owned filesystem state remains.
        if (fic::sudoers::outcomeAllowsDiscard(outcome)) {
            std::string discardError;
            if (!fic::rollback::discardMutation(mutationId, discardError)) {
                this->log("Ошибка удаления подготовленной записи mutation "
                          "journal: " + discardError, logLevel::WARN);
            }
        } else {
            this->log("Мутация не была компенсирована; подготовленная запись "
                      "mutation journal остаётся активной", logLevel::ERROR);
        }
        for (const std::string& diagnostic : operation.diagnostics) {
            this->log(diagnostic, logLevel::WARN);
        }
        this->log(operation.message, logLevel::ERROR);
        return false;
    }

    if (!fic::rollback::commitMutation(mutationId, journalError)) {
        this->log("Мутация применена, но запись mutation journal не "
                  "зафиксирована: " + journalError, logLevel::ERROR);
        return false;
    }

    for (const std::string& diagnostic : operation.diagnostics) {
        this->log(diagnostic, logLevel::INFO);
    }
    this->log(operation.message, logLevel::INFO);
    return true;
}
