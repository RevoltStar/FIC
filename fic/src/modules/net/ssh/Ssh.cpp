#include "modules/net/ssh/Ssh.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/net/ssh/SshRuntime.h"

#include "rollback/DaemonMutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
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

    const std::string resource =
        sshMutationResource(platformConfig_.configPath, this->sshParameter);

    // Crash-consistent journaling: resolve the provenance BEFORE the
    // compliance decision and before any mutation. A crash can leave a
    // Prepared record with the file already written while the reload / the
    // journal commit never happened; the compliance fast-path must never
    // bypass such a record, otherwise a prepared-but-not-reloaded change
    // would be reported as applied without a runtime reload. An existing
    // active record for the same resource keeps its original rollback
    // baseline across repeated applies and forces the repeated-apply path
    // below: the current target-resource state must be matched against the
    // recorded mutation, because a generic apply would mutate every
    // occurrence of the keyword — including untracked ones the journal has
    // no undo provenance for. Untracked occurrences fail closed instead of
    // being mutated without persisted provenance.
    fic::rollback::MutationId mutationId = 0;
    bool newRecord = false;
    bool hasExistingRecord = false;
    fic::rollback::MutationStatus existingStatus =
        fic::rollback::MutationStatus::Applied;
    fic::rollback::UndoRestoreSshDirective existingUndo;
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
        for (const fic::rollback::MutationRecord& record :
             journal->activeRecords(this->policyRef())) {
            if (record.undo.backend == fic::rollback::MutationBackend::Ssh &&
                record.resource == resource) {
                mutationId = record.id;
                existingStatus = record.status;
                if (const auto* sshUndo =
                        std::get_if<fic::rollback::UndoRestoreSshDirective>(
                            &record.undo.payload)) {
                    existingUndo = *sshUndo;
                    hasExistingRecord = true;
                }
                break;
            }
        }
    }

    const auto dropNewPrepared = [this, &newRecord, &mutationId](
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

    // Compensation restore with fully proven durability: the conditional
    // restore must be installed (rename) AND durably confirmed (parent
    // directory fsync). A non-durable restore rename is completed by the
    // recovery barrier — only when the target still is exactly the restored
    // FIC-installed state; otherwise the compensation is not proven.
    const auto restoreWithProvenDurability =
        [this, &originalContent](const AtomicTargetState& expectedState,
                                 std::string& restoreError) -> bool {
            if (this->beforeRestoreHook_) {
                this->beforeRestoreHook_();
            }
            const SshRestoreOutcome restored =
                restoreSshConfigContentIfCurrentState(
                    platformConfig_.configPath, originalContent, expectedState,
                    restoreError);
            if (!restored.installed) {
                return false;
            }
            if (restored.durable) {
                return true;
            }
            return ensureSshConfigDurableIfCurrentState(
                platformConfig_.configPath, *restored.installedState,
                restoreError);
        };

    // Prepared recovery state machine. A Prepared record means the journal
    // was persisted but the mutation was never proven complete: the file
    // write, the runtime reload and the journal commit form the recovery
    // transaction, and each step must be confirmed before the record status
    // changes. The recovery runs BEFORE the compliance fast-path so a
    // crash between the file write and the reload can never be reported as
    // a successful apply without a runtime reload.
    if (hasExistingRecord &&
        existingStatus == fic::rollback::MutationStatus::Prepared) {
        std::vector<std::size_t> recoveryLineIndices;
        std::string classifyError;
        const SshMutationState recordedState =
            this->sshConfig_->classifyRecordedMutation(
                existingUndo, recoveryLineIndices, classifyError);

        const auto failRecovery = [this](const std::string& reason) {
            this->log("Prepared SSH mutation не восстановлена, запись "
                      "остаётся активной: " + reason,
                  logLevel::ERROR);
            return false;
        };

        if (recordedState == SshMutationState::Conflict) {
            // The persistent state matches neither BEFORE nor AFTER: the
            // provenance of the prepared record cannot be proven, so the
            // recovery must not guess and must not repair automatically.
            return failRecovery(
                "Prepared SSH mutation cannot be recovered because "
                "persistent state drifted: " + classifyError);
        }

        // Prepared + AFTER: the recovery must never commit with a weaker
        // postcondition than the original apply. verifyPolicyValue proves
        // the same policy postcondition the first apply proves after its
        // write (effective value semantics, scalar match, Match/Include
        // conditional overrides, audit overrides) — a mere sshd -T parse
        // acceptance is NOT enough. The recorded appliedValue is used: the
        // recovery finishes the OLD persisted transaction first, the current
        // desired value is checked later (active value-change refusal).
        std::string policyError;
        if (recordedState == SshMutationState::After &&
            !runtime.verifyPolicyValue(existingUndo.parameter,
                                       existingUndo.appliedValue,
                                       policyError)) {
            return failRecovery("effective-состояние sshd не подтверждает "
                                "записанное значение политики '" +
                                existingUndo.parameter + " = " +
                                existingUndo.appliedValue + ": " +
                                policyError);
        }

        if (recordedState == SshMutationState::Before) {
            // BEFORE means no FIC mutation is active, so the AFTER policy
            // postcondition does not apply; the current configuration must
            // still be syntactically accepted by sshd.
            std::string validationError;
            if (!runtime.validateConfiguration(validationError)) {
                return failRecovery("sshd не принял текущую конфигурацию: " +
                                    validationError);
            }
        }

        // Durability barrier: the observed AFTER/BEFORE state may have been
        // published by a rename whose parent directory fsync never completed
        // (crash between rename and fsync). The journal status must not
        // resolve (commit Applied / discard) a persistent state whose
        // durability is not proven.
        std::string barrierError;
        if (!AtomicFileWriter::ensureTargetDurable(sshPath, &barrierError)) {
            return failRecovery("durability текущего состояния sshd_config "
                                "не подтверждена: " + barrierError);
        }

        const SshActivationResult recoveryActivation =
            runtime.activateIfRunning();
        if (!recoveryActivation.ok) {
            return failRecovery("перезагрузка не удалась: " +
                                recoveryActivation.message);
        }

        if (recordedState == SshMutationState::Before) {
            // BEFORE can mean the write never happened or the persistent
            // compensation already restored the baseline; only a confirmed
            // runtime reconciliation proves no active FIC mutation remains.
            // The stale Prepared record is discarded afterwards and the
            // apply continues as a fresh first apply of the desired value.
            std::string discardError;
            if (!fic::rollback::discardMutation(mutationId, discardError)) {
                return failRecovery(
                    "ошибка удаления устаревшей Prepared записи: " +
                    discardError);
            }
            this->log("Устаревшая Prepared SSH-мутация согласована "
                      "(конфигурация проверена, runtime активирован) и "
                      "удалена из journal; выполняется обычное применение",
                  logLevel::INFO);
            hasExistingRecord = false;
        } else {
            // AFTER: the system write may already have happened while the
            // reload / the journal commit did not. Validate + reload, then
            // commit Prepared → Applied; the recovered mutation keeps its
            // original rollback baseline.
            std::string commitError;
            if (!fic::rollback::commitMutation(mutationId, commitError)) {
                return failRecovery(
                    "ошибка фиксации восстановленной Prepared записи: " +
                    commitError);
            }
            this->log("Prepared SSH-мутация восстановлена: конфигурация "
                      "проверена, runtime активирован, journal переведён "
                      "в Applied",
                  logLevel::INFO);
            existingStatus = fic::rollback::MutationStatus::Applied;
        }
    }

    // An unfinished rollback must never be silently treated as a normal
    // Applied baseline: the actual persistent state is not proven.
    if (hasExistingRecord &&
        existingStatus == fic::rollback::MutationStatus::RollbackFailed) {
        this->log("Active SSH mutation is in state RollbackFailed; повторное "
                      "применение отклонено (файл и journal не изменены). "
                      "Требуется разрешение состояния отката",
                  logLevel::ERROR);
        return false;
    }

    // Active value change: the recorded baseline describes the currently
    // owned system state. Retargeting it without a full crash-safe
    // transaction protocol would create ambiguous provenance, so the apply
    // fails closed and the rollback baseline is preserved unchanged
    // (disable → change value → enable is required).
    if (hasExistingRecord &&
        expectedValue != existingUndo.appliedValue) {
        this->log("SSH policy value changed while an active rollback baseline "
                      "exists. Disable the policy first, then change the "
                      "value and enable it again. (Параметр '" +
                          this->sshParameter + "': желаемое значение '" +
                          expectedValue + "', активная мутация '" +
                          existingUndo.appliedValue +
                          "'); файл и journal не изменены",
                  logLevel::ERROR);
        return false;
    }

    // Effective state: a configuration that already complies (even via
    // sshd defaults without an explicit directive) must not be mutated,
    // recorded or reloaded — FIC must not claim foreign compliance. This
    // fast-path is safe only after the journal provenance above: a Prepared
    // record never reaches it unreconciled.
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

    if (hasExistingRecord) {
        // Repeated apply with an active recorded mutation. The generic
        // setValue() must not run here: it would mutate every occurrence of
        // the keyword in the current file, creating system mutations the
        // journal has no provenance for. Instead the current projection is
        // mapped onto the recorded slots; only owned drifted slots are
        // repaired to the recorded AFTER representation while the journal
        // keeps the original BEFORE baseline.
        std::vector<std::optional<std::size_t>> slotLineIndices;
        bool needsWrite = false;
        std::string matchError;
        if (!this->sshConfig_->matchRecordedMutationForRepair(
                existingUndo, slotLineIndices, needsWrite, matchError)) {
            this->log("Повторное применение SSH-политики отменено (файл не "
                          "изменён, journal baseline сохранён): " + matchError,
                      logLevel::ERROR);
            return false;
        }
        if (!needsWrite) {
            // The target resource already matches the recorded AFTER state;
            // the effective mismatch comes from an external include, a Match
            // block or a pending service reload. FIC owns neither include
            // nor Match and must not record a no-op mutation.
            this->log("Effective-значение SSH-параметра '" + this->sshParameter +
                          "' не соответствует политике из-за внешней конфигурации "
                          "(Include/Match); main sshd_config уже содержит "
                          "ожидаемую директиву",
                      logLevel::ERROR);
            return false;
        }
        if (!this->sshConfig_->applyRecordedRepairEdits(
                existingUndo, slotLineIndices, matchError)) {
            this->log("Повторное применение SSH-политики отменено (файл не "
                          "изменён): " + matchError,
                      logLevel::ERROR);
            return false;
        }
        this->log("Обнаружен дрейф FIC-owned директивы '" + this->sshParameter +
                      "'; выполняется ремонт до записанного AFTER-состояния",
                  logLevel::WARN);
    } else {
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

        // Mutation-identity preflight (planner → classifier invariant):
        // prove on an in-memory simulation that the plan about to be
        // persisted produces a state the production rollback classifier
        // immediately recognizes as the recorded AFTER. Otherwise the first
        // apply is refused with no journal record and no system write — FIC
        // must never create a mutation it cannot classify itself (for
        // example when a pre-existing foreign line collides exactly with a
        // planned FIC-generated comment).
        std::string identityError;
        if (!this->sshConfig_->validatePlannedRollbackIdentity(
                plan, identityError)) {
            this->log("Применение SSH-политики '" + this->sshParameter +
                          "' отменено: " + identityError,
                      logLevel::ERROR);
            return false;
        }

        // Crash-consistent journaling: record Prepared before the system
        // mutation so the persisted undo provenance always exists before the
        // first textual change of the shared sshd_config.
        {
            std::string journalError;
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

        // Apply the planned mutation in memory; persistence happens below
        // with an optimistic precondition: the write is refused when
        // sshd_config changed between the planning snapshot and the write
        // (TOCTOU).
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
    }
    if (this->beforeWriteHook_) {
        this->beforeWriteHook_();
    }
    std::string saveError;
    const FileHandler::FileSaveOutcome saveOutcome =
        this->sshConfig_->saveFileIfUnchanged(saveError);
    const FileHandler::FileSaveResult saveResult = saveOutcome.result;
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
        } else if (saveOutcome.installed) {
            // Post-install durability failure: the rename already succeeded,
            // so the target may already carry the new content. It must never
            // be reported as "file unchanged". When the exact installed
            // state is known, attempt a conditional compensation of that
            // state; otherwise the provenance record stays active fail
            // closed.
            if (saveOutcome.installedTargetState.has_value()) {
                this->log("Ошибка durable-записи sshd_config после успешной "
                              "замены файла (" + saveError +
                              "); выполняется компенсация установленного "
                              "состояния",
                          logLevel::ERROR);
                std::string restoreError;
                const bool restored = restoreWithProvenDurability(
                    *saveOutcome.installedTargetState, restoreError);
                if (!restored) {
                    this->log("Ошибка компенсации после post-install "
                                  "сбоя записи: " + restoreError +
                                  ". Provenance-запись остаётся активной",
                              logLevel::ERROR);
                    return false;
                }
                std::string validationError;
                if (!runtime.validateConfiguration(validationError)) {
                    this->log("Исходная конфигурация восстановлена после "
                                  "post-install сбоя, но sshd её не "
                                  "принимает: " + validationError +
                                  ". Provenance-запись остаётся активной",
                              logLevel::ERROR);
                    return false;
                }
                const SshActivationResult restoredActivation =
                    runtime.activateIfRunning();
                if (!restoredActivation.ok) {
                    this->log("Исходная конфигурация восстановлена после "
                                  "post-install сбоя, но перезагрузка не "
                                  "удалась: " + restoredActivation.message +
                                  ". Provenance-запись остаётся активной",
                              logLevel::ERROR);
                    return false;
                }
                // The compensation is fully proven: a new Prepared record of
                // this attempt is discarded; an existing baseline record
                // stays active unchanged.
                dropNewPrepared(
                    "Post-install сбой записи, исходная конфигурация "
                    "восстановлена");
                this->log("Post-install сбой записи sshd_config: исходная "
                              "конфигурация восстановлена и активирована",
                          logLevel::ERROR);
            } else {
                this->log("Ошибка записи sshd_config: " + saveError +
                              ". Замена файла уже могла произойти "
                              "(post-install сбой); provenance-запись "
                              "остаётся активной",
                          logLevel::ERROR);
            }
        } else {
            // The write failed before anything was installed; the
            // provenance is kept fail closed.
            this->log(LocalizationManager::getLang(
                          "[module:NET][submodule:SshEdit][message:save_failed]") +
                          ". Ошибка: " + saveError +
                          ". Prepared mutation остаётся активной",
                      logLevel::ERROR);
        }
        return false;
    }
    const std::optional<AtomicTargetState>& installedState =
        saveOutcome.installedTargetState;

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
        const bool restored = restoreWithProvenDurability(*installedState,
                                                          restoreError);
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
        const bool restored = restoreWithProvenDurability(*installedState,
                                                          restoreError);
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
