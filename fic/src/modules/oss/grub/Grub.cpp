#include "modules/oss/grub/Grub.h"
#include "modules/oss/grub/GrubConfiguration.h"
#include "modules/oss/grub/GrubRollback.h"

#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"

#include <mutex>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

namespace {

GrubManagedConfigurationOptions makeManagedOptions(
    const fic::platform::GrubPlatformConfig& platform,
    const std::filesystem::path& rebuildExecutable,
    bool enforceOwnership) {
    GrubManagedConfigurationOptions options;
    options.managedPath = platform.managedConfigPath;
    options.rebuildExecutable = rebuildExecutable;
    options.rebuildArguments = platform.rebuildArguments;
    options.enforceOwnership = enforceOwnership;
    options.baseDefaultsPath = platform.baseDefaultsPath;
    options.sharedDefaultsPath = platform.sharedDefaultsPath;
    return options;
}

GrubRollbackOptions makeRollbackOptions(
    const fic::platform::GrubPlatformConfig& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    bool enforceOwnership) {
    GrubRollbackOptions options;
    options.platform = platform;
    options.executables = &executables;
    options.enforceOwnership = enforceOwnership;
    return options;
}

} // namespace

namespace {

// Forward declaration: the AFTER/BEFORE transition helper lives below.
bool finishGrubJournalReconciliation(
    fic::rollback::MutationJournal* journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoRemoveGrubManagedSetting& undo,
    const GrubManagedConfigurationOptions& options,
    const GrubRollbackOptions& rollbackOptions,
    bool matchesDesiredValue,
    std::vector<std::string>& diagnostics,
    std::string& error);

// Journal reconciliation before every GRUB apply (crash recovery, value
// change release, drift detection). Fail closed. May perform a rebuild, a
// stale-record resolution and/or a full ownership release of a previous
// applied value through the shared rollback backend.
bool reconcileGrubJournal(
    const GrubManagedConfigurationOptions& options,
    const GrubRollbackOptions& rollbackOptions,
    const PolicyRef& policyRef,
    const std::string& key,
    const std::string& desiredValue,
    std::vector<std::string>& diagnostics,
    std::string& error) {
    std::string journalError;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(
        journalError);
    if (!journal) {
        if (!journalError.empty()) {
            error = "Mutation journal недоступен: " + journalError;
            return false; // fail closed: no journal — no apply
        }
        // Unit-test environment without initialized runtime paths.
        return true;
    }

    for (const fic::rollback::MutationRecord& record :
         journal->activeRecords(policyRef)) {
        if (record.undo.backend != fic::rollback::MutationBackend::Grub) {
            continue;
        }
        const auto* undo = std::get_if<
            fic::rollback::UndoRemoveGrubManagedSetting>(
            &record.undo.payload);
        if (!undo || undo->key != key) {
            continue;
        }

        // Single classification of the recorded appliedValue against the
        // CURRENT managed source state.
        GrubValueObservation observed;
        const GrubManagedJournalState state = classifyGrubManagedJournalState(
            options, key, undo->appliedValue, &observed);
        switch (state) {
        case GrubManagedJournalState::Invalid:
            error = "Не удалось классифицировать managed source GRUB для "
                    "recovery: " + observed.error;
            return false;
        case GrubManagedJournalState::Drift:
            // DRIFT: the managed value was changed externally — never
            // rewritten, never overwritten.
            error = "Managed GRUB значение '" + key +
                "' изменено вне FIC (journal: '" + undo->appliedValue +
                "', фактическое: '" + observed.value + "'); apply отклонён";
            return false;
        case GrubManagedJournalState::Before:
        case GrubManagedJournalState::After:
        case GrubManagedJournalState::Ineffective:
            // Ineffective: the recorded value is still FIC-owned, but the
            // ALT block is displaced from EOF. Ownership reconciliation
            // proceeds like After; effective compliance is re-established
            // by the journaled apply that follows this reconciliation.
            break;
        }
        return finishGrubJournalReconciliation(
            journal, record, *undo, options, rollbackOptions,
            undo->appliedValue == desiredValue, diagnostics, error);
    }
    return true;
}

} // namespace

namespace {

// AFTER/BEFORE transition of an active GRUB journal record: mandatory
// rebuild first, then resolve the record (and release old ownership on a
// value change through the shared rollback backend).
bool finishGrubJournalReconciliation(
    fic::rollback::MutationJournal* journal,
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoRemoveGrubManagedSetting& undo,
    const GrubManagedConfigurationOptions& options,
    const GrubRollbackOptions& rollbackOptions,
    bool matchesDesiredValue,
    std::vector<std::string>& diagnostics,
    std::string& error) {
    // P0 invariant: the mandatory rebuild runs only on currently validated
    // inputs, re-proven immediately before it.
    std::string validateError;
    if (!validateGrubRebuildInputs(options, validateError)) {
        error = "Входные данные пересборки GRUB не прошли проверку "
                "безопасности; journal запись не разрешалась, пересборка "
                "не запускалась: " + validateError;
        return false;
    }
    // Mandatory rebuild before any journal transition: the derived grub.cfg
    // must be proven current for both AFTER and BEFORE classifications.
    std::string rebuildError;
    if (!runGrubRebuild(
            options.rebuildExecutable, options.rebuildArguments,
            defaultGrubCommandRunner(), rebuildError)) {
        error = "Обязательная пересборка grub.cfg при reconciliation GRUB "
                "journal завершилась ошибкой: " + rebuildError;
        return false;
    }

    // Full post-rebuild re-proof: the journal record may be resolved only
    // from a fresh classification of the recorded appliedValue AFTER the
    // rebuild. DRIFT or an unclassifiable source fail closed: no resolution,
    // no commit, no new Prepared.
    GrubValueObservation observed;
    const GrubManagedJournalState state = classifyGrubManagedJournalState(
        options, undo.key, undo.appliedValue, &observed);
    if (state == GrubManagedJournalState::Invalid) {
        error = "Не удалось повторно классифицировать managed source GRUB "
                "после пересборки; journal запись остаётся активной: " +
            observed.error;
        return false;
    }
    if (state == GrubManagedJournalState::Drift) {
        error = "Managed GRUB значение '" + undo.key +
            "' изменено вне FIC после пересборки (journal: '" +
            undo.appliedValue + "', фактическое: '" + observed.value +
            "'); journal запись не разрешалась";
        return false;
    }

    if (state == GrubManagedJournalState::Before) {
        // BEFORE: the mutation never installed or was fully compensated.
        std::string resolveError;
        const bool resolved = record.status ==
                fic::rollback::MutationStatus::Prepared
            ? journal->discard(record.id, resolveError)
            : journal->setStatus(
                record.id, fic::rollback::MutationStatus::RolledBack,
                resolveError);
        if (!resolved) {
            error = "Ошибка разрешения stale GRUB journal записи: " +
                resolveError;
            return false;
        }
        diagnostics.push_back(
            "Stale GRUB journal запись разрешена: managed значение '" +
            undo.key + "' отсутствует, grub.cfg пересобран");
        return true;
    }

    if (state == GrubManagedJournalState::Ineffective) {
        // INEFFECTIVE proves OWNERSHIP, never Applied-compliance: the
        // recorded value is still FIC-owned, but the ALT block is displaced
        // from EOF. The record must NOT be promoted to Applied here — only
        // a journaled relocation followed by a successful rebuild and a
        // fresh EOF placement proof may commit Applied.
        if (matchesDesiredValue) {
            // Preserve the current active provenance untouched and return
            // to the normal apply: it will see a non-compliant source
            // (needsChange), reuse this record as its repair Prepared,
            // perform the journaled relocation to EOF and finish the
            // lifecycle (Applied) only after the fresh post-rebuild proof.
            diagnostics.push_back(
                "FIC managed block содержит записанное значение '" +
                undo.key + "', но смещён с EOF (foreign content после "
                "END-маркера): journal запись " +
                std::to_string(record.id) +
                " сохраняется без promotion в Applied, эффективное "
                "размещение восстановит следующий journaled apply");
            return true;
        }
        // Value change: release the old FIC-owned value WITHOUT promoting
        // the record to Applied (rollback ownership release does not
        // require EOF placement), then resolve the old record as RolledBack
        // directly from its current active status.
        const GrubRollbackResult release = undoGrubManagedSetting(
            rollbackOptions, undo);
        if (!release.ok) {
            error = "Не удалось освободить предыдущее FIC-owned значение '" +
                undo.key + "': " + release.message;
            return false;
        }
        std::string resolveError;
        if (!journal->setStatus(
                record.id, fic::rollback::MutationStatus::RolledBack,
                resolveError)) {
            error = "Ошибка разрешения освобождённой GRUB journal записи: " +
                resolveError;
            return false;
        }
        diagnostics.push_back(
            "Предыдущее FIC-owned значение '" + undo.key +
            "' освобождено перед новым apply (без промежуточного "
            "promotion в Applied)");
        return true;
    }

    // AFTER: the source mutation is installed — commit Prepared (or a
    // RollbackFailed record whose compensation returned the applied value)
    // to Applied.
    if (record.status == fic::rollback::MutationStatus::Prepared ||
        record.status == fic::rollback::MutationStatus::RollbackFailed) {
        std::string commitError;
        if (!journal->setStatus(
                record.id, fic::rollback::MutationStatus::Applied,
                commitError)) {
            error = "Ошибка фиксации GRUB journal записи при recovery: " +
                commitError;
            return false;
        }
    }
    if (matchesDesiredValue) {
        diagnostics.push_back(
            "Prepared GRUB mutation recovery: значение '" + undo.key +
            "' установлено и grub.cfg пересобран");
        return true;
    }

    // Value change: release the old FIC-owned value through the same shared
    // backend operation used by disable rollback, then resolve the old
    // record before the new apply.
    const GrubRollbackResult release = undoGrubManagedSetting(
        rollbackOptions, undo);
    if (!release.ok) {
        error = "Не удалось освободить предыдущее FIC-owned значение '" +
            undo.key + "': " + release.message;
        return false;
    }
    std::string resolveError;
    if (!journal->setStatus(
            record.id, fic::rollback::MutationStatus::RolledBack,
            resolveError)) {
        error = "Ошибка разрешения освобождённой GRUB journal записи: " +
            resolveError;
        return false;
    }
    diagnostics.push_back(
        "Предыдущее FIC-owned значение '" + undo.key + "' освобождено перед "
        "новым apply");
    return true;
}

} // namespace

namespace {

// FRESH PREPARED AND REUSED ACTIVE PROVENANCE ARE NOT THE SAME THING.
//
// Repair provenance context: distinguishes a Prepared record that was
// created FRESH for this operation from an existing active ownership
// record (Applied / Prepared / RollbackFailed) that this operation
// temporarily reuses as its Prepared repair record (the same MutationId
// survives the whole repair — no second active record for the same
// logical mutation resource is ever created).
//
// A REPAIR OPERATION MUST NEVER DESTROY PRE-EXISTING ACTIVE PROVENANCE:
// after a no-op failure (Unchanged) or a fully compensated failure
// (Compensated: source restored AND compensating rebuild succeeded) a
// fresh Prepared may be discarded, but a reused record must be restored
// to its pre-repair logical state. The transient context lives only in
// memory for the duration of the current operation — the persistent
// journal carries no extra repair fields; a crash after the durable
// previousStatus → Prepared transition leaves the ordinary active
// Prepared record that the existing recovery model already handles.
enum class GrubPreparedRecordOrigin {
    Fresh,
    ReusedActive
};

struct GrubMutationPreparation {
    fic::rollback::MutationId id = 0;
    GrubPreparedRecordOrigin origin = GrubPreparedRecordOrigin::Fresh;
    // Meaningful only for ReusedActive.
    fic::rollback::MutationStatus previousStatus =
        fic::rollback::MutationStatus::Prepared;
    std::string previousError;
};

// The active GRUB record that may be reused as the repair Prepared record
// for (policy, backend=Grub, resource=key): payload must be
// UndoRemoveGrubManagedSetting with the matching key. At most one such
// active record exists (MutationJournal invariant: one active record per
// logical mutation resource).
std::optional<fic::rollback::MutationRecord> findReusableGrubRecord(
    fic::rollback::MutationJournal& journal,
    const PolicyRef& policyRef,
    const std::string& key) {
    for (const fic::rollback::MutationRecord& record :
         journal.activeRecords(policyRef)) {
        if (record.undo.backend != fic::rollback::MutationBackend::Grub) {
            continue;
        }
        const auto* undo = std::get_if<
            fic::rollback::UndoRemoveGrubManagedSetting>(
            &record.undo.payload);
        if (undo != nullptr && undo->key == key) {
            return record;
        }
    }
    return std::nullopt;
}

// Prepares the journaled mutation BEFORE the source mutation. When no
// active provenance exists, a fresh Prepared record is created. When an
// active ownership record already exists (Applied / Prepared /
// RollbackFailed), it is NOT duplicated and NOT discarded: its pre-repair
// status and error are captured transiently and the record is durably
// transitioned to Prepared. The undo payload is never rewritten — for a
// same-value repair the existing payload already carries the correct
// key + appliedValue. An active record with an unexpected payload fails
// closed.
bool prepareGrubMutation(
    const PolicyRef& policyRef,
    const std::string& key,
    const std::string& actualExpected,
    GrubMutationPreparation& preparation,
    std::string& error) {
    std::string journalError;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(
        journalError);
    if (journal == nullptr) {
        error = journalError.empty()
            ? "Mutation journal недоступен: runtime paths не инициализированы"
            : journalError;
        return false; // fail closed: no journal — no mutation
    }
    const std::optional<fic::rollback::MutationRecord> existing =
        findReusableGrubRecord(*journal, policyRef, key);
    if (!existing.has_value()) {
        const fic::rollback::UndoAction undo{
            fic::rollback::MutationBackend::Grub,
            fic::rollback::UndoRemoveGrubManagedSetting{key, actualExpected}};
        preparation = GrubMutationPreparation{};
        return fic::rollback::recordPreparedMutation(
            policyRef, key, undo, preparation.id, error);
    }
    const auto* undo = std::get_if<
        fic::rollback::UndoRemoveGrubManagedSetting>(
        &existing->undo.payload);
    if (undo == nullptr || undo->key != key ||
        undo->appliedValue != actualExpected) {
        error = "Active GRUB journal запись " +
            std::to_string(existing->id) +
            " имеет неожиданный undo payload; repair отклонён (fail closed)";
        return false;
    }
    preparation.id = existing->id;
    preparation.origin = GrubPreparedRecordOrigin::ReusedActive;
    preparation.previousStatus = existing->status;
    preparation.previousError = existing->error;
    // Durable transient transition: previousStatus → Prepared. The payload
    // is untouched; the captured pre-repair logical state is restored by
    // restoreGrubMutationAfterNoopOrCompensation() when the repair proves
    // that the system was not mutated or was fully compensated.
    return journal->setStatus(
        preparation.id, fic::rollback::MutationStatus::Prepared, error);
}

// Restores the pre-repair journal state of a REUSED active ownership
// record after the repair proved that the system was NOT mutated
// (Unchanged) or was fully compensated (Compensated). The previous status
// and error message are restored durably; the payload is untouched;
// timestamps may naturally advance. Only a provably finished operation may
// restore: any Installed / Indeterminate /
// CompensatedPendingRebuild outcome keeps the durable Prepared status
// instead (recovery still required).
bool restoreGrubMutationAfterNoopOrCompensation(
    const GrubMutationPreparation& preparation,
    std::string& error) {
    std::string journalError;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(
        journalError);
    if (journal == nullptr) {
        error = journalError.empty()
            ? "Mutation journal недоступен: runtime paths не инициализированы"
            : journalError;
        return false;
    }
    return journal->setStatusWithMessage(
        preparation.id, preparation.previousStatus,
        preparation.previousError, error);
}

} // namespace

Grub::Grub(
    fic::platform::GrubPlatformConfig platformConfig,
    const fic::platform::PlatformExecutableResolver& executables,
    bool enforceOwnership)
    : OSS(),
      platformConfig_(std::move(platformConfig)),
      executables_(executables),
      enforceOwnership_(enforceOwnership) {
    this->submoduleName = "Grub";
}

bool Grub::apply() {
    std::optional<std::string> value;
    try {
        value = this->getValue();
    } catch (const std::exception& error) {
        this->log(
            "Не удалось декодировать значение политики GRUB: " +
                std::string(error.what()),
            logLevel::ERROR);
        return false;
    }
    if (!value.has_value()) {
        return false;
    }

    // Shared GRUB backend mutex: apply and rollback are serialized through
    // the same intra-process lock (see grubBackendMutex()). Cross-process
    // correctness rests on CAS-based atomic writes and the journal.
    const std::lock_guard<std::mutex> lock(grubBackendMutex());
    return this->applyGrub(*value);
}

bool Grub::applyGrubValue(
    const std::string& grubKey,
    const std::string& expectedValue,
    const std::function<std::string(const std::string&)>& normalizeExpected)
{
    const std::string actualExpected = normalizeExpected
        ? normalizeExpected(expectedValue)
        : expectedValue;

    std::filesystem::path rebuildExecutable;
    std::string resolverError;
    if (!executables_.resolve(
            fic::platform::ExecutableId::UpdateGrub,
            rebuildExecutable,
            resolverError)) {
        this->log(
            "Не удалось найти проверенную команду пересборки GRUB: " +
                resolverError,
            logLevel::ERROR);
        return false;
    }

    const GrubManagedConfigurationOptions options = makeManagedOptions(
        platformConfig_, rebuildExecutable, enforceOwnership_);
    const GrubRollbackOptions rollbackOptions = makeRollbackOptions(
        platformConfig_, executables_, enforceOwnership_);

    // Journal reconciliation first: prepared crash recovery, value change
    // release and drift detection happen BEFORE the new Prepared record.
    // (The GRUB backend mutex is already held by apply().)
    std::vector<std::string> reconciliationDiagnostics;
    std::string reconciliationError;
    if (!reconcileGrubJournal(
            options, rollbackOptions, this->policyRef(), grubKey,
            actualExpected, reconciliationDiagnostics,
            reconciliationError)) {
        this->log(reconciliationError, logLevel::ERROR);
        return false;
    }
    for (const std::string& diagnostic : reconciliationDiagnostics) {
        this->log(diagnostic, logLevel::INFO);
    }
    // Current FIC-owned managed value under the platform topology.
    const GrubValueObservation observed =
        inspectGrubManagedValue(options, grubKey);
    if (!observed.valid) {
        this->log("Не удалось проанализировать FIC managed GRUB source: " +
                      observed.error,
                  logLevel::ERROR);
        return false;
    }

    // Prepared is recorded BEFORE the source mutation and ONLY when the
    // source is not EFFECTIVELY compliant; a compliant source creates no
    // new journal record. For ALT this includes a valid same-value block
    // displaced from EOF: relocating it to EOF is a real system mutation
    // and must never happen without a Prepared record.
    const bool needsChange =
        !grubManagedValueCompliant(observed, actualExpected);
    GrubMutationPreparation preparation;
    bool mutationPrepared = false;
    if (needsChange) {
        std::string journalError;
        if (!prepareGrubMutation(
                this->policyRef(), grubKey, actualExpected, preparation,
                journalError)) {
            this->log("Не удалось подготовить запись mutation journal: " +
                          journalError,
                      logLevel::ERROR);
            return false;
        }
        mutationPrepared = true;
    }

    GrubOperationResult operation;
    switch (platformConfig_.topology) {
    case fic::platform::GrubConfigTopology::OwnedDefaultsDropIn:
        operation = ensureManagedGrubDropInValue(
            options, grubKey, actualExpected);
        break;
    case fic::platform::GrubConfigTopology::SharedDefaultsFile: {
        GrubConfiguration configuration(GrubConfigurationOptions{
            platformConfig_.sharedDefaultsPath,
            rebuildExecutable,
            platformConfig_.rebuildArguments,
            enforceOwnership_});
        std::string error;
        if (!configuration.load(error)) {
            operation.message =
                "Не удалось загрузить shared GRUB defaults: " + error;
            break;
        }
        operation = configuration.ensureManagedValue(grubKey, actualExpected);
        break;
    }
    default:
        operation.message = "Неизвестная topology GRUB-конфигурации";
        break;
    }

    for (const std::string& diagnostic : operation.diagnostics) {
        this->log(diagnostic, operation.ok ? logLevel::INFO : logLevel::WARN);
    }

    // Journal lifecycle matrix (docs/rollback.md, GRUB backend):
    //   failure + Unchanged/Compensated source ->
    //     FRESH Prepared: discard (the transaction never installed or was
    //       fully compensated: Compensated means source restored AND
    //       compensating rebuild succeeded);
    //     REUSED active provenance: restore the pre-repair status and
    //       error — a repair operation must never destroy pre-existing
    //       active ownership provenance;
    //   failure + CompensatedPendingRebuild    -> keep Prepared active
    //     (source restored, but the derived grub.cfg state is unresolved);
    //   failure + Installed/Indeterminate      -> keep Prepared active;
    //   success + Installed                    -> commit Applied;
    //   success + Unchanged (defensive)        -> discard a fresh Prepared
    //     / restore a reused record, never discard reused provenance.
    // Any journal commit/discard/restore failure is fail closed
    // (apply == false).
    const auto settleNoopOrCompensated = [&]() -> bool {
        std::string journalError;
        if (preparation.origin == GrubPreparedRecordOrigin::ReusedActive) {
            if (restoreGrubMutationAfterNoopOrCompensation(
                    preparation, journalError)) {
                return true;
            }
            this->log("Ошибка восстановления предыдущего состояния записи "
                      "mutation journal: " + journalError,
                      logLevel::ERROR);
            return false;
        }
        if (fic::rollback::discardMutation(preparation.id, journalError)) {
            return true;
        }
        this->log("Ошибка удаления подготовленной записи mutation "
                  "journal: " + journalError,
                  logLevel::ERROR);
        return false;
    };
    if (!operation.ok) {
        if (mutationPrepared &&
            (operation.sourceState == GrubSourceMutationState::Unchanged ||
             operation.sourceState == GrubSourceMutationState::Compensated)) {
            // The apply already fails here; a failed settlement leaves the
            // active record in place for recovery (fail closed).
            settleNoopOrCompensated();
        }
        this->log(operation.message, logLevel::ERROR);
        return false;
    }

    this->log(operation.message, logLevel::INFO);
    if (mutationPrepared) {
        std::string journalError;
        if (operation.sourceState == GrubSourceMutationState::Installed) {
            if (!fic::rollback::commitMutation(preparation.id, journalError)) {
                // The source mutation already happened: apply must not
                // report success without reliable provenance. The Prepared
                // record stays active and remains resolvable.
                this->log("Ошибка фиксации записи mutation journal: " +
                              journalError,
                          logLevel::ERROR);
                return false;
            }
        } else if (!settleNoopOrCompensated()) {
            return false;
        }
    }

    if (operation.changed) {
        this->notify(
            "Исправлена конфигурация GRUB для политики: " + this->policyName,
            notifyLevel::WARN);
    }
    return true;
}
