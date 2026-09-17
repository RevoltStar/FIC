#include "modules/net/ssh/Ssh.h"

#include "modules/net/ssh/SshConfigSyntax.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/net/ssh/SshRuntime.h"

#include "rollback/DaemonMutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/i18n/LocalizationManager.h>

#include <algorithm>
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

// Ownership state of the current configuration against one journal payload.
struct SshOwnershipState {
    bool blockPresent = false;
    bool blockOwned = false;   // sub-block line == recorded applied line
    bool wrappersPresent = false;
    bool wrappersValid = false;
    bool malformed = false;
    std::string error;
};

SshOwnershipState analyzeOwnership(const std::vector<std::string>& lines,
                                   const fic::rollback::UndoRemoveSshManagedPolicy& undo) {
    SshOwnershipState state;
    SshManagedModel model;
    std::string error;
    const SshManagedParseStatus status =
        parseSshManagedModel(lines, model, error);
    if (status != SshManagedParseStatus::Ok) {
        state.malformed = true;
        state.error = error;
        return state;
    }
    const std::string expectedLine =
        sshManagedDirectiveLine(undo.directive, undo.appliedValue);
    for (const SshManagedPolicyBlock& block : model.policies) {
        if (block.name == undo.policyName) {
            state.blockPresent = true;
            state.blockOwned = block.directiveLine == expectedLine;
            break;
        }
    }
    for (const SshDisabledBlock& disabled : model.disabled) {
        if (disabled.policy == undo.policyName) {
            state.wrappersPresent = true;
        }
    }
    // Ownership-release provenance proof (subset semantics): when any
    // FIC-owned state of the policy is present, every wrapper that still
    // exists must be proven by the journal payload. Payload ids whose
    // wrappers have already disappeared are treated as released and are not
    // an error. When nothing is owned (no block, no wrappers), the payload
    // describes state that was never applied or already rolled back /
    // externally cleaned.
    state.wrappersValid = true;
    if (state.blockPresent || state.wrappersPresent) {
        const SshDisabledProvenanceCheck provenance =
            checkSshDisabledProvenance(model, undo.policyName,
                                       undo.disabledMutationIds);
        if (!provenance.safeToRelease()) {
            state.wrappersValid = false;
            state.error =
                describeSshDisabledProvenance(provenance, undo.policyName);
        }
    }
    return state;
}

// Port is multi-value: the policy postcondition is that the effective port
// set is exactly the configured value.
bool verifyEffectiveValue(SshRuntime& runtime,
                          SshDirectiveSemantics semantics,
                          const std::string& directive,
                          const std::string& expectedValue,
                          std::string& error) {
    if (semantics == SshDirectiveSemantics::MultiValue) {
        std::vector<std::string> values;
        if (!runtime.effectiveValues(directive, values, error)) {
            return false;
        }
        if (values.size() == 1 && values.front() == expectedValue) {
            return true;
        }
        error = "effective-набор значений '" + directive + "' не соответствует "
                "политике";
        return false;
    }
    return runtime.verifyPolicyValue(directive, expectedValue, error);
}

bool isEffectivelyCompliant(SshRuntime& runtime,
                            SshDirectiveSemantics semantics,
                            const std::string& directive,
                            const std::string& expectedValue) {
    if (semantics == SshDirectiveSemantics::MultiValue) {
        std::vector<std::string> values;
        std::string error;
        if (!runtime.effectiveValues(directive, values, error)) {
            return false;
        }
        return values.size() == 1 && values.front() == expectedValue;
    }
    const SshComplianceResult compliance =
        runtime.policyValueCompliance(directive, expectedValue);
    return compliance.compliance == SshCompliance::Compliant;
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

SshRollbackOptions Ssh::makeRollbackOptions() const {
    SshRollbackOptions options;
    options.configPath = platformConfig_.configPath;
    options.includeBasePath = platformConfig_.includeBasePath;
    options.serviceUnits = platformConfig_.serviceUnits;
    options.executables = &executables_;
    options.runner = commandRunner_;
    options.beforeWrite = beforeWriteHook_;
    options.beforeRestore = beforeRestoreHook_;
    return options;
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

    // Explicit directive semantics: an unclassified SSH policy must fail
    // closed instead of assuming scalar first-obtained-value behavior.
    const SshDirectiveSemantics semantics =
        sshPolicyDirectiveSemantics(this->policyName);
    if (semantics == SshDirectiveSemantics::Unsupported) {
        this->log("SSH-политика '" + this->policyName +
                      "' не имеет объявленной семантики директивы; применение "
                      "отклонено",
                  logLevel::ERROR);
        return false;
    }

    SshRuntime runtime(*runtimeOptions_, executables_, commandRunner_);
    const std::string sshPath = platformConfig_.configPath.string();
    const std::string resource =
        sshMutationResource(platformConfig_.configPath, this->sshParameter);

    if (!this->sshConfig_->loadConfig()) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:load_failed]"),
                  logLevel::ERROR);
        return false;
    }

    // Crash-consistent journaling: resolve the provenance BEFORE the
    // compliance decision and before any mutation.
    fic::rollback::MutationId mutationId = 0;
    bool newRecord = false;
    std::vector<fic::rollback::MutationRecord> activeRecords;
    std::string journalError;
    fic::rollback::MutationJournal* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr) {
        this->log("Mutation journal недоступен" +
                      std::string(journalError.empty() ? "" : ": " + journalError),
                  logLevel::ERROR);
        return false;
    }
    activeRecords = journal->activeRecords(this->policyRef());

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

    fic::rollback::UndoRemoveSshManagedPolicy payload;
    payload.policyName = this->policyName;
    payload.directive = this->sshParameter;
    payload.appliedValue = expectedValue;
    // Ownership analysis of the current configuration against the newest
    // active record (all active records of the policy share the same
    // policyName/directive; only appliedValue and wrapper ids differ).
    SshOwnershipState ownership;
    bool hasExistingRecord = !activeRecords.empty();
    if (hasExistingRecord) {
        const fic::rollback::MutationRecord& newest = activeRecords.back();
        if (newest.undo.backend != fic::rollback::MutationBackend::Ssh) {
            this->log("Активная запись mutation journal политики '" +
                          this->policyName + "' имеет неожиданный backend",
                  logLevel::ERROR);
            return false;
        }
        const auto* newestPayload = std::get_if<
            fic::rollback::UndoRemoveSshManagedPolicy>(&newest.undo.payload);
        if (newestPayload == nullptr) {
            this->log("Активная запись mutation journal политики '" +
                          this->policyName + "' повреждена",
                  logLevel::ERROR);
            return false;
        }
        mutationId = newest.id;
        ownership = analyzeOwnership(this->sshConfig_->lines(), *newestPayload);
        if (ownership.malformed) {
            this->log("Структура FIC-маркеров sshd_config повреждена: " +
                          ownership.error,
                  logLevel::ERROR);
            return false;
        }
        if (newest.status == fic::rollback::MutationStatus::Prepared &&
            ownership.blockPresent && !ownership.blockOwned) {
            this->log("Prepared SSH-мутация не восстановлена: содержимое "
                      "FIC-блока изменено вручную; требуется ручное разрешение",
                  logLevel::ERROR);
            return false;
        }
        if (newest.status == fic::rollback::MutationStatus::Prepared &&
            !ownership.wrappersValid) {
            this->log("Prepared SSH-мутация не восстановлена: владение "
                      "существующими FIC_DISABLED блоками не доказано "
                      "journal payload'ом: " +
                          ownership.error,
                  logLevel::ERROR);
            return false;
        }
        if (newest.status != fic::rollback::MutationStatus::Prepared &&
            ((ownership.blockPresent && !ownership.blockOwned) ||
             !ownership.wrappersValid)) {
            // A drift of the FIC-owned state (for example a manually edited
            // block or an unproven wrapper id) must never be silently
            // overwritten. Wrappers that merely disappeared externally are
            // not a drift: ownership-release semantics treats them as
            // already released.
            this->log("FIC-владение политикой '" + this->policyName +
                          "' не может быть доказано (изменённый FIC-блок или "
                          "несовпадающий провенанс DISABLED маркеров): " +
                          ownership.error + "; применение отклонено",
                  logLevel::ERROR);
            return false;
        }
    }
    // Finish an interrupted transaction: validate, durability, reload and
    // commit the journal record. Returns nullopt on hard failure.
    const auto finishPrepared = [this, &runtime, &sshPath](
                                    const fic::rollback::MutationRecord& record,
                                    bool owned) -> std::optional<bool> {
        std::string validationError;
        if (!runtime.validateConfiguration(validationError)) {
            this->log("Prepared SSH-мутация не восстановлена: sshd не "
                      "принимает текущую конфигурацию: " + validationError,
                  logLevel::ERROR);
            return false;
        }
        if (owned && this->sshConfig_->loadSnapshot().has_value()) {
            std::string barrierError;
            if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                    sshPath, *this->sshConfig_->loadSnapshot(),
                    &barrierError)) {
                this->log("Prepared SSH-мутация не восстановлена: durability "
                          "не подтверждена: " + barrierError,
                      logLevel::ERROR);
                return false;
            }
        }
        const SshActivationResult activation = runtime.activateIfRunning();
        if (!activation.ok) {
            this->log("Prepared SSH-мутация не восстановлена: перезагрузка "
                      "не удалась: " + activation.message,
                  logLevel::ERROR);
            return false;
        }
        std::string commitError;
        if (!fic::rollback::commitMutation(record.id, commitError)) {
            this->log("Ошибка фиксации восстановленной Prepared записи: " +
                          commitError,
                  logLevel::ERROR);
            return false;
        }
        return true;
    };

    if (hasExistingRecord) {
        const fic::rollback::MutationRecord& newest = activeRecords.back();
        if (newest.status == fic::rollback::MutationStatus::Prepared) {
            if (ownership.blockOwned || ownership.wrappersPresent) {
                const std::optional<bool> recovery =
                    finishPrepared(newest, true);
                if (!recovery.has_value() || !*recovery) {
                    return false;
                }
                this->log("Prepared SSH-мутация восстановлена и зафиксирована",
                          logLevel::INFO);
            } else {
                const std::optional<bool> recovery =
                    finishPrepared(newest, false);
                if (!recovery.has_value() || !*recovery) {
                    return false;
                }
                std::string discardError;
                if (!fic::rollback::discardMutation(newest.id, discardError)) {
                    this->log("Ошибка удаления устаревшей Prepared записи: " +
                                  discardError,
                          logLevel::ERROR);
                    return false;
                }
                this->log("Устаревшая Prepared SSH-мутация согласована и "
                          "удалена из journal; выполняется обычное применение",
                      logLevel::INFO);
                activeRecords.pop_back();
                hasExistingRecord = !activeRecords.empty();
            }
        }
    }
    // A value change requires the previous owned state to be rolled back
    // first: the managed block line must match the undo payload's applied
    // value for ownership to be provable.
    if (hasExistingRecord) {
        bool valueChanged = false;
        for (const fic::rollback::MutationRecord& record : activeRecords) {
            const auto* recordPayload = std::get_if<
                fic::rollback::UndoRemoveSshManagedPolicy>(&record.undo.payload);
            if (recordPayload != nullptr &&
                recordPayload->appliedValue != expectedValue) {
                valueChanged = true;
            }
        }
        if (valueChanged) {
            SshRollbackOptions rollbackOptions = makeRollbackOptions();
            for (const fic::rollback::MutationRecord& record : activeRecords) {
                const auto* recordPayload = std::get_if<
                    fic::rollback::UndoRemoveSshManagedPolicy>(
                    &record.undo.payload);
                if (recordPayload == nullptr) {
                    this->log("Активная запись mutation journal политики '" +
                                  this->policyName + "' повреждена",
                          logLevel::ERROR);
                    return false;
                }
                const SshRollbackResult rollback = undoSshManagedPolicyMutation(
                    rollbackOptions, *recordPayload);
                // Ownership-release semantics: NothingToDo means every
                // previously owned artifact is already gone (external edit,
                // earlier rollback + crash, ...) — the old state counts as
                // released, and the new value must be applied to the actual
                // current configuration, not to a reconstructed one.
                if (!rollback.ok && !rollback.nothingToDo) {
                    this->log("Не удалось откатить предыдущее состояние "
                              "политики '" + this->policyName + "': " +
                                  rollback.message,
                          logLevel::ERROR);
                    return false;
                }
                std::string statusError;
                if (!journal->setStatus(
                        record.id, fic::rollback::MutationStatus::RolledBack,
                        statusError)) {
                    this->log("Ошибка фиксации статуса отката в mutation "
                              "journal: " + statusError,
                          logLevel::ERROR);
                    return false;
                }
            }
            activeRecords.clear();
            hasExistingRecord = false;
            // The rollback of the previous owned state changed the on-disk
            // file behind this handler's back: reload it before planning the
            // new state so the conditional atomic write compares against the
            // actual current state.
            if (!this->sshConfig_->loadConfig()) {
                this->log(LocalizationManager::getLang(
                              "[module:NET][submodule:SshEdit][message:load_failed]"),
                          logLevel::ERROR);
                return false;
            }
        }
    }

    // Ownership sanity BEFORE the compliance fast-path: a malformed FIC
    // ownership structure, or a stale/orphan FIC policy block or
    // FIC_DISABLED wrapper of this policy without an active journal record,
    // must never be silently accepted just because sshd -T shows a
    // compliant effective value.
    {
        SshManagedModel model;
        std::string modelError;
        if (parseSshManagedModel(this->sshConfig_->lines(), model,
                                 modelError) != SshManagedParseStatus::Ok) {
            this->log("Структура FIC-маркеров sshd_config повреждена: " +
                          modelError,
                  logLevel::ERROR);
            return false;
        }
        if (!hasExistingRecord &&
            (sshManagedModelHasPolicy(model, this->policyName) ||
             sshManagedModelHasDisabledForPolicy(model, this->policyName))) {
            this->log("Обнаружены FIC-маркеры политики '" + this->policyName +
                          "' без активной записи mutation journal; применение "
                          "отклонено",
                  logLevel::ERROR);
            return false;
        }
    }

    // Compliance fast-path: a configuration that already satisfies the
    // policy must not be rewritten (idempotent re-apply).
    if (isEffectivelyCompliant(runtime, semantics, this->sshParameter,
                               expectedValue)) {
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:already_configured]") +
                      this->sshParameter + " = " + expectedValue,
                  logLevel::INFO);
        return true;
    }
    // ---- Planning (in-memory, on a copy of the loaded snapshot) ----
    // (Ownership sanity — malformed markers and orphan FIC state — has
    // already been proven before the compliance fast-path.)

    std::vector<std::string> planned = this->sshConfig_->lines();
    bool changed = false;
    std::string planError;
    std::vector<std::string> newWrapperIds;

    if (!upsertSshManagedPolicyBlock(
            planned, this->policyName,
            sshManagedDirectiveLine(this->sshParameter, expectedValue),
            changed, planError)) {
        this->log("Не удалось спланировать FIC policy-блок: " + planError,
                  logLevel::ERROR);
        return false;
    }

    if (semantics == SshDirectiveSemantics::MultiValue) {
        // Every other effective occurrence of the directive (outside the FIC
        // managed block and outside FIC_DISABLED wrappers) must be disabled
        // with a fresh provenance id. Covered line ranges come from the
        // parsed model of the planned content.
        SshManagedModel model;
        std::string modelError;
        if (parseSshManagedModel(planned, model, modelError) !=
            SshManagedParseStatus::Ok) {
            this->log("Внутренняя ошибка планирования FIC-маркеров: " +
                          modelError,
                  logLevel::ERROR);
            return false;
        }
        std::vector<bool> covered(planned.size(), false);
        if (model.blockPresent) {
            for (std::size_t i = model.blockBegin; i <= model.blockEnd; ++i) {
                covered[i] = true;
            }
        }
        for (const SshDisabledBlock& disabled : model.disabled) {
            for (std::size_t i = disabled.beginLine; i <= disabled.endLine;
                 ++i) {
                covered[i] = true;
            }
        }
        int ordinal = 1;
        for (std::size_t i = planned.size(); i-- > 0;) {
            if (covered[i]) {
                continue;
            }
            const SshLineParseResult parsed = parseSshConfigLine(planned[i]);
            if (!parsed.ok || !parsed.hasDirective) {
                continue;
            }
            if (normalizeSshKeyword(parsed.directive.keyword) !=
                normalizeSshKeyword(this->sshParameter)) {
                continue;
            }
            const std::string wrapperId =
                generateSshDisabledMutationId(ordinal++);
            disableSshLine(planned, i, this->policyName, wrapperId);
            newWrapperIds.push_back(wrapperId);
            changed = true;
        }
    }

    if (!changed && hasExistingRecord) {
        // Nothing to change and the state is already owned: idempotent.
        this->log(LocalizationManager::getLang(
                      "[module:NET][submodule:SshEdit][message:already_configured]") +
                      this->sshParameter + " = " + expectedValue,
                  logLevel::INFO);
        return true;
    }
    // ---- Journal: prepare BEFORE touching the system (crash consistency) ----

    payload.disabledMutationIds = newWrapperIds;
    std::string recordError;
    if (!fic::rollback::recordPreparedMutation(this->policyRef(), resource,
                                               fic::rollback::UndoAction{
                                                   fic::rollback::MutationBackend::Ssh,
                                                   payload},
                                               mutationId, recordError)) {
        this->log("Не удалось подготовить запись mutation journal: " +
                      recordError,
                  logLevel::ERROR);
        return false;
    }
    newRecord = true;

    // ---- Transaction: conditional atomic write -> durability -> verify ->
    //      reload; compensation restores the exact pre-attempt snapshot ----

    SshConfigTransactionHooks hooks;
    hooks.beforeWrite = beforeWriteHook_;
    hooks.beforeRestore = beforeRestoreHook_;

    SshConfigTransactionResult transaction = runSshConfigTransaction(
        *this->sshConfig_, runtime, hooks,
        // Plan: apply the planned edits to the live handler state.
        [this, &planned](std::string& error) {
            this->sshConfig_->lines() = planned;
            (void)error;
            return true;
        },
        // Postcondition: the managed block carries the exact policy line and
        // the effective runtime state satisfies the policy (for Port the
        // effective value set must be exactly the configured value).
        [&runtime, &semantics, &expectedValue, this](std::string& error) {
            SshManagedModel model;
            if (parseSshManagedModel(this->sshConfig_->lines(), model, error) !=
                SshManagedParseStatus::Ok) {
                error = "повреждённая структура FIC-маркеров после записи: " +
                        error;
                return false;
            }
            bool found = false;
            for (const SshManagedPolicyBlock& block : model.policies) {
                if (block.name == this->policyName) {
                    found = block.directiveLine ==
                            sshManagedDirectiveLine(this->sshParameter,
                                                    expectedValue);
                    break;
                }
            }
            if (!found) {
                error = "FIC policy-блок политики '" + this->policyName +
                        "' не подтверждён в записанном файле";
                return false;
            }
            return verifyEffectiveValue(runtime, semantics, this->sshParameter,
                                        expectedValue, error);
        },
        "Политика '" + this->policyName + "' применена к sshd_config");

    if (!transaction.ok) {
        dropNewPrepared(transaction.message);
        this->log("Применение политики '" + this->policyName +
                      "' не выполнено: " + transaction.message,
                  logLevel::ERROR);
        return false;
    }

    std::string commitError;
    if (!fic::rollback::commitMutation(mutationId, commitError)) {
        this->log("SSH-мутация применена, но запись mutation journal не "
                  "зафиксирована: " + commitError,
              logLevel::ERROR);
        return false;
    }
    newRecord = false;

    this->log(transaction.message, logLevel::INFO);
    return true;
}