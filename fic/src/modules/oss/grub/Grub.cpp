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
    // source actually needs a change; a compliant source creates no new
    // journal record.
    const bool needsChange =
        !observed.found || observed.value != actualExpected;
    fic::rollback::MutationId mutationId = 0;
    bool mutationPrepared = false;
    if (needsChange) {
        std::string journalError;
        const fic::rollback::UndoAction undo{
            fic::rollback::MutationBackend::Grub,
            fic::rollback::UndoRemoveGrubManagedSetting{
                grubKey, actualExpected}};
        if (!fic::rollback::recordPreparedMutation(
                this->policyRef(), grubKey, undo, mutationId, journalError)) {
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
    //   failure + Unchanged/Compensated source -> discard Prepared;
    //   failure + Installed/Indeterminate      -> keep Prepared active;
    //   success + Installed                    -> commit Applied;
    //   success + Unchanged                    -> discard the unnecessary
    //                                             Prepared (defensive).
    // Any journal commit/discard failure is fail closed (apply == false).
    if (!operation.ok) {
        std::string journalError;
        if (mutationPrepared &&
            (operation.sourceState == GrubSourceMutationState::Unchanged ||
             operation.sourceState == GrubSourceMutationState::Compensated)) {
            if (!fic::rollback::discardMutation(mutationId, journalError)) {
                this->log("Ошибка удаления подготовленной записи mutation "
                          "journal: " + journalError,
                          logLevel::ERROR);
            }
        }
        this->log(operation.message, logLevel::ERROR);
        return false;
    }

    this->log(operation.message, logLevel::INFO);
    if (mutationPrepared) {
        std::string journalError;
        if (operation.sourceState == GrubSourceMutationState::Installed) {
            if (!fic::rollback::commitMutation(mutationId, journalError)) {
                // The source mutation already happened: apply must not
                // report success without reliable provenance. The Prepared
                // record stays active and remains resolvable.
                this->log("Ошибка фиксации записи mutation journal: " +
                              journalError,
                          logLevel::ERROR);
                return false;
            }
        } else {
            if (!fic::rollback::discardMutation(mutationId, journalError)) {
                this->log("Ошибка удаления подготовленной записи mutation "
                          "journal: " + journalError,
                          logLevel::ERROR);
                return false;
            }
        }
    }

    if (operation.changed) {
        this->notify(
            "Исправлена конфигурация GRUB для политики: " + this->policyName,
            notifyLevel::WARN);
    }
    return true;
}
