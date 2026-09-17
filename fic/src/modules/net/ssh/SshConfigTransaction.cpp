#include "modules/net/ssh/SshConfigTransaction.h"

#include "modules/net/ssh/SshRollback.h"

#include <fic/core/fs/AtomicFileWriter.h>

namespace {

// Conditional compensation of the exact installed state: restores the
// pre-attempt snapshot, proves its durability and returns true only when the
// restore is fully proven. On success the caller is responsible for the
// runtime validation / reload of the restored configuration.
bool compensateRestore(SshConfigFileHandler& handler,
                       const SshRuntime& runtime,
                       const SshConfigTransactionHooks& hooks,
                       const AtomicTargetState& installedState,
                       const std::string& preContent,
                       std::string& restoreError) {
    if (hooks.beforeRestore) {
        hooks.beforeRestore();
    }
    const SshRestoreOutcome restored = restoreSshConfigContentIfCurrentState(
        handler.filePath(), preContent, installedState, restoreError);
    bool stateRestored = restored.installed;
    if (stateRestored && !restored.durable) {
        stateRestored = ensureSshConfigDurableIfCurrentState(
            handler.filePath(), *restored.installedState, restoreError);
    }
    return stateRestored;
}

// Runtime reconciliation after a proven compensation restore: validates the
// restored configuration with sshd -t/-T and reloads the active service.
bool reconcileRestoredRuntime(SshConfigFileHandler& handler,
                              const SshRuntime& runtime,
                              const AtomicTargetState& installedState,
                              std::string& message) {
    std::string validationError;
    if (!runtime.validateConfiguration(validationError)) {
        message = "исходное состояние sshd_config восстановлено, но sshd его "
                  "не принимает: " + validationError;
        return false;
    }
    (void)handler;
    (void)installedState;
    const SshActivationResult restoredActivation = runtime.activateIfRunning();
    if (!restoredActivation.ok) {
        message = "исходное состояние sshd_config восстановлено на диске, но "
                  "перезагрузка не удалась: " + restoredActivation.message;
        return false;
    }
    message = "исходное состояние sshd_config восстановлено и активировано";
    return true;
}

} // namespace
SshConfigTransactionResult runSshConfigTransaction(
    SshConfigFileHandler& handler,
    const SshRuntime& runtime,
    const SshConfigTransactionHooks& hooks,
    const std::function<bool(std::string& error)>& planEdits,
    const std::function<bool(std::string& error)>& verifyPostcondition,
    const std::string& successMessage) {
    SshConfigTransactionResult result;

    // Pre-attempt content for the compensation: the exact loaded snapshot,
    // captured before any edit.
    std::string preContent;
    if (handler.loadSnapshot().has_value()) {
        preContent = handler.loadSnapshot()->content;
    }

    std::string planError;
    if (planEdits == nullptr || !planEdits(planError)) {
        result.message = "Планирование изменения sshd_config не выполнено "
                         "(файл не изменён): " + planError;
        return result;
    }

    if (hooks.beforeWrite) {
        hooks.beforeWrite();
    }

    std::string saveError;
    const FileHandler::FileSaveOutcome saveOutcome =
        handler.saveFileIfUnchanged(saveError);
    if (saveOutcome.result != FileHandler::FileSaveResult::Installed) {
        if (saveOutcome.result == FileHandler::FileSaveResult::RefusedChanged) {
            // The write was refused before anything was installed: the
            // system carries the external change and FIC replaced nothing.
            result.conflict = true;
            result.message = "sshd_config изменился во время операции; "
                             "конкурентная запись отклонена, файл не "
                             "изменён: " + saveError;
            return result;
        }
        if (saveOutcome.installed) {
            // Post-install failure (rename happened, durability did not):
            // compensate the exact installed state when it is known.
            if (!saveOutcome.installedTargetState.has_value()) {
                result.message = "Ошибка записи sshd_config (" + saveError +
                                 "); точное установленное состояние "
                                 "неизвестно, компенсация невозможна "
                                 "(fail closed)";
                return result;
            }
            std::string restoreError;
            if (compensateRestore(handler, runtime, hooks,
                                  *saveOutcome.installedTargetState,
                                  preContent, restoreError)) {
                std::string reconcileMessage;
                reconcileRestoredRuntime(handler, runtime,
                                         *saveOutcome.installedTargetState,
                                         reconcileMessage);
                result.message = "Ошибка записи sshd_config (" + saveError +
                                 "); " + reconcileMessage;
            } else {
                result.message = "Ошибка записи sshd_config (" + saveError +
                                 "); восстановить исходное состояние не "
                                 "удалось: " + restoreError;
            }
            return result;
        }
        // The write failed before anything was installed.
        result.message = "Ошибка записи sshd_config (файл не изменён): " +
                         saveError;
        return result;
    }
    if (!saveOutcome.installedTargetState.has_value()) {
        result.message = "Не удалось зафиксировать точное состояние "
                         "sshd_config после записи; компенсация невозможна "
                         "(fail closed)";
        return result;
    }
    const AtomicTargetState& installedState = *saveOutcome.installedTargetState;

    // Post-install durability: a rename without a confirmed parent directory
    // fsync is not a proven write.
    if (!saveOutcome.durabilityConfirmed) {
        std::string barrierError;
        if (!ensureSshConfigDurableIfCurrentState(
                handler.filePath(), installedState, barrierError)) {
            std::string restoreError;
            if (compensateRestore(handler, runtime, hooks, installedState,
                                  preContent, restoreError)) {
                std::string reconcileMessage;
                reconcileRestoredRuntime(handler, runtime, installedState,
                                         reconcileMessage);
                result.message =
                    "Durability записи sshd_config не подтверждена (" +
                    barrierError + "); " + reconcileMessage;
            } else {
                result.message =
                    "Durability записи sshd_config не подтверждена (" +
                    barrierError + "); восстановить исходное состояние не "
                                   "удалось: " + restoreError;
            }
            return result;
        }
    }
    // Post-install runtime validation: sshd must accept the new
    // configuration before the postcondition and activation steps run.
    std::string validationError;
    if (!runtime.validateConfiguration(validationError)) {
        std::string restoreError;
        if (compensateRestore(handler, runtime, hooks, installedState,
                              preContent, restoreError)) {
            std::string reconcileMessage;
            reconcileRestoredRuntime(handler, runtime, installedState,
                                     reconcileMessage);
            result.message = "sshd не принимает новую конфигурацию (" +
                             validationError + "); " + reconcileMessage;
        } else {
            result.message = "sshd не принимает новую конфигурацию (" +
                             validationError +
                             "); восстановить исходное состояние не удалось: " +
                             restoreError;
        }
        return result;
    }

    // Policy postcondition verification (persistent + effective state).
    std::string verifyError;
    if (verifyPostcondition == nullptr || !verifyPostcondition(verifyError)) {
        std::string restoreError;
        if (compensateRestore(handler, runtime, hooks, installedState,
                              preContent, restoreError)) {
            std::string reconcileMessage;
            reconcileRestoredRuntime(handler, runtime, installedState,
                                     reconcileMessage);
            result.message = "Проверка результата не пройдена (" + verifyError +
                             "); " + reconcileMessage;
        } else {
            result.message = "Проверка результата не пройдена (" + verifyError +
                             "); восстановить исходное состояние не удалось: " +
                             restoreError;
        }
        return result;
    }

    // Reload the active SSH service.
    const SshActivationResult activation = runtime.activateIfRunning();
    if (!activation.ok) {
        std::string restoreError;
        if (compensateRestore(handler, runtime, hooks, installedState,
                              preContent, restoreError)) {
            std::string reconcileMessage;
            reconcileRestoredRuntime(handler, runtime, installedState,
                                     reconcileMessage);
            result.message = "Перезагрузка SSH-сервиса не удалась (" +
                             activation.message + "); " + reconcileMessage;
        } else {
            result.message = "Перезагрузка SSH-сервиса не удалась (" +
                             activation.message +
                             "); восстановить исходное состояние не удалось: " +
                             restoreError;
        }
        return result;
    }

    result.ok = true;
    result.message = successMessage +
                     (activation.reloaded
                          ? "; SSH-сервис перезагружен"
                          : "; SSH-сервис неактивен, перезагрузка не требуется");
    return result;
}