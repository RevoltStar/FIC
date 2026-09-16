#include "modules/net/ssh/SshRollback.h"

#include "modules/net/ssh/SshConfigFile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <fstream>
#include <sstream>
#include <utility>

namespace {

SshRuntime makeRuntime(const SshRollbackOptions& options) {
    SshRuntimeOptions runtimeOptions;
    runtimeOptions.configPath = options.configPath;
    runtimeOptions.includeBasePath = options.includeBasePath;
    runtimeOptions.serviceUnits = options.serviceUnits;
    return SshRuntime(runtimeOptions, *options.executables, options.runner);
}

} // namespace

bool restoreSshConfigContentIfCurrentState(
    const std::filesystem::path& path,
    const std::string& content,
    const AtomicTargetState& expectedTargetState,
    std::string& error) {
    // Conditional restore: the replacement happens only when the target is
    // still exactly the state FIC proved to install (expectedTargetState —
    // the state captured at rename time, never a fresh capture, which could
    // silently legitimize an external modification made after the FIC write).
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    options.expectedTargetState = expectedTargetState;
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(
            path.string(), content, options, &error, &result)) {
        if (result.preconditionFailed) {
            error = "Файл изменился после FIC-записи; восстановление отменено, "
                    "внешнее содержимое сохранено: " + error;
        }
        return false;
    }
    return true;
}

SshRollbackResult undoSshDirectiveMutation(
    const SshRollbackOptions& options,
    const fic::rollback::UndoRestoreSshDirective& undo) {
    SshRollbackResult result;
    // Defensive re-validation: the journal load already enforces this, but the
    // undo must never run with an incomplete payload.
    if (options.executables == nullptr ||
        options.configPath.empty() ||
        undo.parameter.empty() ||
        undo.appliedValue.empty() ||
        undo.occurrences.empty()) {
        result.message = "SSH rollback backend настроен неполно или undo payload "
                         "повреждён";
        return result;
    }

    SshConfigFileHandler handler(options.configPath.string());
    if (!handler.loadConfig()) {
        result.message = "Не удалось проанализировать " +
                         options.configPath.string();
        return result;
    }

    // Mutation-local drift detection: classify the current global section
    // against the recorded BEFORE/AFTER representations of this concrete
    // mutation. Unrelated changes (other FIC SSH policies, comments, edits of
    // other directives, Match blocks, includes) do not affect the result.
    std::vector<std::size_t> afterLineIndices;
    std::string classifyError;
    const SshMutationState state = handler.classifyRecordedMutation(
        undo, afterLineIndices, classifyError);
    if (state == SshMutationState::Before) {
        // The file already matches the recorded pre-FIC state: either the
        // mutation was never applied or a previous undo wrote the file but
        // crashed before the journal update / service reload. BEFORE means
        // the persistent undo succeeded, so the runtime sshd must still be
        // reconciled: validate the current configuration and reload it when
        // the service is active. Only a fully successful runtime
        // reconciliation resolves the mutation; a failed validation or a
        // failed reload leaves the journal active and refuses the rollback.
        result.nothingToDo = true;
        SshRuntime runtime = makeRuntime(options);
        std::string validationError;
        if (!runtime.validateConfiguration(validationError)) {
            result.nothingToDo = false;
            result.message = "Состояние директивы " + undo.parameter +
                             " уже соответствует состоянию до FIC-мутации, но "
                             "sshd -T не принимает текущую конфигурацию; откат "
                             "не подтверждён, мутация остаётся активной: " +
                             validationError;
            return result;
        }
        const SshActivationResult activation = runtime.activateIfRunning();
        if (!activation.ok) {
            result.nothingToDo = false;
            result.message = "Состояние директивы " + undo.parameter +
                             " уже соответствует состоянию до FIC-мутации, но "
                             "перезагрузка SSH-сервиса не удалась; откат не "
                             "подтверждён, мутация остаётся активной: " +
                             activation.message;
            return result;
        }
        result.message = "Состояние директивы " + undo.parameter +
                         " уже соответствует состоянию до FIC-мутации" +
                         (activation.reloaded
                              ? "; SSH-сервис перезагружен (crash recovery)"
                              : "; SSH-сервис неактивен, перезагрузка не требуется") +
                         "; откат не требуется";
        return result;
    }
    if (state == SshMutationState::Conflict) {
        result.conflict = true;
        result.message = "Откат SSH-мутации отменён (файл не изменён): " +
                         classifyError;
        return result;
    }

    // In-memory pre-rollback copy (the exact loaded snapshot content) used
    // for transactional compensation.
    const std::string preRollbackContent =
        handler.loadSnapshot().has_value() ? handler.loadSnapshot()->content
                                           : std::string();

    if (options.beforeWrite) {
        options.beforeWrite();
    }

    std::string error;
    std::optional<AtomicTargetState> installedState;
    if (!handler.applyRecordedReverseEdits(undo, afterLineIndices, error)) {
        result.message = "Откат SSH-мутации отменён (файл не изменён): " + error;
        return result;
    }
    const FileHandler::FileSaveResult saveResult =
        handler.saveFileIfUnchanged(error, &installedState);
    if (saveResult != FileHandler::FileSaveResult::Installed) {
        if (saveResult == FileHandler::FileSaveResult::RefusedChanged) {
            // The shared sshd_config changed concurrently after the snapshot
            // was captured: refuse without overwriting the external change.
            result.conflict = true;
            result.message = "sshd_config изменился во время отката; "
                             "конкурентная запись отклонена, файл не изменён: " +
                             error;
        } else {
            result.message = "Не удалось записать откат SSH-мутации в " +
                             options.configPath.string() + ": " + error;
        }
        return result;
    }

    SshRuntime runtime = makeRuntime(options);
    const auto runBeforeRestore = [&options]() {
        if (options.beforeRestore) {
            options.beforeRestore();
        }
    };
    std::string validationError;
    if (!runtime.validateConfiguration(validationError)) {
        // Post-rollback validation failed: restore the pre-rollback (FIC)
        // state. Do not reload a configuration sshd does not accept. The
        // restore is conditional on the target still being the exact state
        // FIC installed through the reverse write; an external modification
        // made after that write is never overwritten.
        std::string restoreError;
        runBeforeRestore();
        const bool stateRestored = restoreSshConfigContentIfCurrentState(
            options.configPath, preRollbackContent, *installedState,
            restoreError);
        if (stateRestored) {
            result.message = "Откат SSH-мутации записан, но sshd -T не принял "
                             "результат; состояние до отката восстановлено: " +
                             validationError;
        } else {
            result.message = "Откат SSH-мутации не прошёл валидацию (" +
                             validationError + "); восстановить состояние до " +
                             "отката не удалось, мутация остаётся активной: " +
                             restoreError;
        }
        return result;
    }

    const SshActivationResult activation = runtime.activateIfRunning();
    if (!activation.ok) {
        std::string restoreError;
        runBeforeRestore();
        const bool stateRestored = restoreSshConfigContentIfCurrentState(
            options.configPath, preRollbackContent, *installedState,
            restoreError);
        if (!stateRestored) {
            result.message = "Перезагрузка SSH-сервиса не удалась (" +
                             activation.message +
                             "); восстановить состояние до отката не удалось, "
                             "мутация остаётся активной: " +
                             restoreError;
            return result;
        }
        // Reload the restored (pre-rollback) configuration when the service
        // is active; activateIfRunning is a no-op for an inactive service.
        std::string restoredValidationError;
        if (!runtime.validateConfiguration(restoredValidationError)) {
            result.message = "Перезагрузка SSH-сервиса не удалась (" +
                             activation.message + "); состояние до отката " +
                             "восстановлено, но sshd его не принимает: " +
                             restoredValidationError;
            return result;
        }
        const SshActivationResult restoredActivation = runtime.activateIfRunning();
        if (!restoredActivation.ok) {
            result.message = "Перезагрузка SSH-сервиса не удалась (" +
                             activation.message + "); состояние до отката " +
                             "восстановлено на диске, но не активировано: " +
                             restoredActivation.message;
            return result;
        }
        result.message = "Откат SSH-мутации отменён: перезагрузка SSH-сервиса "
                         "не удалась (" + activation.message +
                         "); состояние до отката восстановлено и активировано";
        return result;
    }

    result.ok = true;
    result.message = "FIC-мутация sshd_config отменена (" + undo.parameter +
                     "); изменения вне записанной дельты не затронуты" +
                     (activation.reloaded
                          ? "; SSH-сервис перезагружен"
                          : "; SSH-сервис неактивен, перезагрузка не требуется");
    return result;
}