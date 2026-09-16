#include "modules/net/ssh/Ssh.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/net/ssh/SshRuntime.h"

#include "rollback/DaemonMutationJournal.h"

#include <fic/core/i18n/LocalizationManager.h>

#include <mutex>
#include <utility>

namespace {

// Serializes sshd_config access between policy apply and the rollback
// executor's SSH undo path within this process.
std::mutex& sshBackendMutex() {
    static std::mutex mutex;
    return mutex;
}

std::string sshMutationResource(const std::filesystem::path& configPath,
                                const std::string& parameter) {
    return "ssh:" + configPath.string() + ":" + parameter;
}

} // namespace

Ssh::~Ssh() = default;

Ssh::Ssh(fic::platform::SshPlatformConfig platformConfig,
         const fic::platform::PlatformExecutableResolver& executables)
    : Net(),
      platformConfig_(std::move(platformConfig)),
      executables_(executables),
      runtimeOptions_(std::make_unique<SshRuntimeOptions>(SshRuntimeOptions{
          platformConfig_.configPath,
          platformConfig_.includeBasePath,
          platformConfig_.serviceUnits
      })),
      sshConfig_(std::make_unique<SshConfigFileHandler>(
          platformConfig_.configPath.string())) {
    this->submoduleName = "SshEdit";
}

bool Ssh::apply() {
    if (this->sshParameter.empty()) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:parameter_not_configured_part1]") +
                      this->policyName +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:parameter_not_configured_part2]"),
                  logLevel::FATAL);
        return false;
    }

    const std::lock_guard<std::mutex> lock(sshBackendMutex());

    const std::optional valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    const std::string expectedValue = *valueOpt;
    if (expectedValue.empty() || expectedValue == "[NO VALUE SET]") {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:reference_value_empty_part1]") +
                      this->policyName +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:reference_value_empty_part2]"),
                  logLevel::ERROR);
        return false;
    }

    SshRuntime runtime(*runtimeOptions_, executables_, commandRunner_);

    // Effective state first: a configuration that already complies (even via
    // sshd defaults without an explicit directive) must not be mutated,
    // recorded or reloaded — FIC must not claim foreign compliance.
    const SshComplianceResult compliance =
        runtime.policyValueCompliance(this->sshParameter, expectedValue);
    if (compliance.compliance == SshCompliance::Compliant) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:no_deviations_part1]") +
                      this->sshParameter +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:no_deviations_part2]"),
                  logLevel::INFO);
        return true;
    }
    if (compliance.compliance == SshCompliance::Unknown) {
        this->log("Не удалось определить effective-состояние sshd: " +
                      compliance.error,
                  logLevel::ERROR);
        return false;
    }

    const std::string sshPath = platformConfig_.configPath.string();
    if (!this->sshConfig_->loadConfig()) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:load_failed]"),
                  logLevel::ERROR);
        return false;
    }
    // The handler captured an exact optimistic snapshot of the file; the
    // pre-attempt content for compensation comes from the same snapshot.
    std::string originalContent;
    if (this->sshConfig_->loadSnapshot().has_value()) {
        originalContent = this->sshConfig_->loadSnapshot()->content;
    }

    const std::string currentValue = this->sshConfig_->getValue(this->sshParameter);
    if (currentValue == expectedValue) {
        // The main config already carries the expected directive; the
        // effective mismatch comes from an external include or a Match block.
        // FIC owns neither and must not record a no-op mutation.
        this->log("Effective-значение SSH-параметра '" + this->sshParameter +
                      "' не соответствует политике из-за внешней конфигурации "
                      "(Include/Match); main sshd_config уже содержит "
                      "ожидаемую директиву",
                  logLevel::ERROR);
        return false;
    }

    this->log(LocalizationManager::getLang(
                  "[module:NET][submodule:SshEdit][message:deviation_detected_part1]") +
                  this->sshParameter +
                  LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:deviation_detected_part2]") +
                  currentValue +
                  LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:deviation_detected_part3]") +
                  expectedValue +
                  LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:deviation_detected_part4]"),
              logLevel::WARN);

    // Build the in-memory mutation plan BEFORE anything touches the disk:
    // the journal record must describe the exact reverse delta first.
    SshDirectiveMutationPlan plan;
    if (!this->sshConfig_->planSetValue(this->sshParameter, expectedValue, plan)) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:update_failed_part1]") +
                      this->sshParameter +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:update_failed_part2]"),
                  logLevel::ERROR);
        return false;
    }

    // Crash-consistent journaling: record Prepared before the system
    // mutation. An existing active record for the same resource keeps its
    // original rollback baseline across repeated applies.
    fic::rollback::MutationId mutationId = 0;
    bool newRecord = false;
    {
        std::string journalError;
        fic::rollback::MutationJournal* journal =
            fic::rollback::DaemonMutationJournal::instance().tryGet(journalError);
        if (journal == nullptr) {
            this->log("Mutation journal недоступен" +
                          std::string(journalError.empty() ? "" : ": " + journalError),
                      logLevel::ERROR);
            return false;
        }
        const std::string resource =
            sshMutationResource(platformConfig_.configPath, this->sshParameter);
        for (const fic::rollback::MutationRecord& record :
             journal->activeRecords(this->policyRef())) {
            if (record.undo.backend == fic::rollback::MutationBackend::Ssh &&
                record.resource == resource) {
                mutationId = record.id;
                break;
            }
        }
        if (mutationId == 0) {
            fic::rollback::UndoAction undo{
                fic::rollback::MutationBackend::Ssh,
                fic::rollback::UndoRestoreSshDirective{
                    plan.parameter,
                    plan.appliedValue,
                    plan.occurrences}};
            if (!fic::rollback::recordPreparedMutation(
                    this->policyRef(), resource, undo, mutationId, journalError)) {
                this->log("Не удалось подготовить запись mutation journal: " +
                              journalError,
                          logLevel::ERROR);
                return false;
            }
            newRecord = true;
        }
    }

    const auto dropNewPrepared = [this, newRecord, mutationId](
                                     const std::string& context) {
        if (!newRecord) {
            return;
        }
        std::string discardError;
        if (!fic::rollback::discardMutation(mutationId, discardError)) {
            this->log(context + ": ошибка удаления подготовленной записи "
                              "mutation journal: " + discardError,
                      logLevel::WARN);
        }
    };

    // Apply the planned mutation and persist it atomically with an
    // optimistic precondition: the write is refused when sshd_config changed
    // between the planning snapshot and the write (TOCTOU).
    if (!this->sshConfig_->setValue(this->sshParameter, expectedValue)) {
        dropNewPrepared("SSH-мутация не выполнена");
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:update_failed_part1]") +
                      this->sshParameter +
                      LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:update_failed_part2]"),
                  logLevel::ERROR);
        return false;
    }
    if (this->beforeWriteHook_) {
        this->beforeWriteHook_();
    }
    std::string saveError;
    const FileHandler::FileSaveResult saveResult =
        this->sshConfig_->saveFileIfUnchanged(saveError);
    if (saveResult != FileHandler::FileSaveResult::Installed) {
        if (saveResult == FileHandler::FileSaveResult::RefusedChanged) {
            // The write was refused before anything was installed: the
            // system was not mutated, so a new Prepared record is safely
            // discarded and the apply fails closed.
            dropNewPrepared("sshd_config изменился во время применения");
            this->log("sshd_config изменился между планированием и записью; "
                          "конкурентная запись отклонена, файл не изменён: " +
                              saveError,
                      logLevel::ERROR);
        } else {
            // The write failed; AtomicFileWriter reports installed=false in
            // this case, but the provenance is kept fail closed.
            this->log(LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:save_failed]") +
                          ". Ошибка: " + saveError +
                          ". Prepared mutation остаётся активной",
                      logLevel::ERROR);
        }
        return false;
    }

    // Post-write verification: persistent content and effective configuration.
    std::string failureContext;
    SshConfigFileHandler verification(sshPath);
    if (!verification.loadConfig() ||
        verification.getValue(this->sshParameter) != expectedValue) {
        failureContext = "Не удалось подтвердить записанное значение SSH-политики";
    } else {
        std::string runtimeError;
        if (!runtime.verifyPolicyValue(this->sshParameter, expectedValue, runtimeError)) {
            failureContext =
                "Проверка effective-конфигурации sshd не пройдена: " + runtimeError;
        }
    }

    if (!failureContext.empty()) {
        // Apply-time restore (§11): put the pre-attempt content back. The new
        // Prepared record of this attempt is removed only after the complete
        // compensation is confirmed (restore write + sshd validation +
        // restored activation when the service is active); otherwise the
        // provenance stays active so the next disable can resolve it.
        std::string restoreError;
        const bool restored = restoreSshConfigContent(
            platformConfig_.configPath, originalContent, restoreError);
        if (!restored) {
            this->log(failureContext + ". Ошибка отката: " + restoreError +
                          ". Prepared mutation остаётся активной",
                      logLevel::ERROR);
            return false;
        }
        std::string validationError;
        if (!runtime.validateConfiguration(validationError)) {
            this->log(failureContext + ". Исходная конфигурация восстановлена, "
                          "но sshd её не принимает: " + validationError +
                          ". Prepared mutation остаётся активной",
                      logLevel::ERROR);
            return false;
        }
        // Restore the runtime state of the restored configuration.
        // activateIfRunning() is a no-op for an inactive service and reloads
        // the restored configuration when the service is active.
        const SshActivationResult restoredActivation =
            runtime.activateIfRunning();
        if (!restoredActivation.ok) {
            this->log(failureContext + ". Исходная конфигурация восстановлена "
                          "на диске, но перезагрузка не удалась: " +
                              restoredActivation.message +
                              ". Prepared mutation остаётся активной",
                      logLevel::ERROR);
            return false;
        }
        this->log(failureContext + ". Исходная конфигурация восстановлена и "
                      "активирована",
                  logLevel::INFO);
        dropNewPrepared(failureContext);
        return false;
    }

    const SshActivationResult activation = runtime.activateIfRunning();
    if (!activation.ok) {
        this->log("Persistent-конфигурация SSH подготовлена, но обязательная "
                      "runtime-активация не завершена: " + activation.message,
                  logLevel::ERROR);
        // Runtime activation failure (§12): try to fully restore the
        // pre-attempt configuration before reporting failure.
        std::string restoreError;
        const bool restored = restoreSshConfigContent(
            platformConfig_.configPath, originalContent, restoreError);
        if (!restored) {
            this->log("Ошибка восстановления исходной SSH-конфигурации: " +
                          restoreError +
                          ". Prepared mutation остаётся активной",
                      logLevel::ERROR);
            return false;
        }
        std::string validationError;
        if (!runtime.validateConfiguration(validationError)) {
            this->log("Исходная конфигурация восстановлена, но sshd её не "
                          "принимает: " + validationError +
                          ". Prepared mutation остаётся активной",
                      logLevel::ERROR);
            return false;
        }
        if (activation.serviceActive) {
            // The service kept running while the file was mutated: reload
            // the restored configuration to undo the failed attempt.
            const SshActivationResult restoredActivation =
                runtime.activateIfRunning();
            if (!restoredActivation.ok) {
                this->log("Исходная конфигурация восстановлена на диске, но "
                              "перезагрузка не удалась: " +
                              restoredActivation.message +
                              ". Prepared mutation остаётся активной",
                          logLevel::ERROR);
                return false;
            }
            this->log(restoredActivation.message, logLevel::INFO);
        }
        dropNewPrepared("Runtime-активация не удалась, исходная конфигурация "
                        "восстановлена");
        return false;
    }
    this->log(activation.message, logLevel::INFO);

    // Commit provenance only after write + verification + activation. A
    // failed commit keeps the Prepared record active and fails the apply.
    std::string commitError;
    if (!fic::rollback::commitMutation(mutationId, commitError)) {
        this->log("Ошибка фиксации записи mutation journal: " + commitError,
                  logLevel::ERROR);
        return false;
    }

    this->log(LocalizationManager::getLang(
                  "[module:NET][submodule:SshEdit][message:deviation_fixed]"),
              logLevel::INFO);
    return true;
}
