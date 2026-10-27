#include "modules/net/ssh/SshConfigTransaction.h"
#include <fic/core/fs/AtomicFileWriter.h>

SshRestoreOutcome restoreSshConfigContentIfCurrentState(
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
    SshRestoreOutcome outcome;
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(
            path.string(), content, options, &error, &result)) {
        if (result.installed) {
            // The replacement itself succeeded (rename published the target);
            // only a later durability step (directory fsync) failed.
            outcome.installed = true;
            outcome.durable = false;
            outcome.installedState = result.installedTargetState;
            return outcome;
        }
        if (result.preconditionFailed) {
            outcome.preconditionFailed = true;
            error = "Файл изменился после FIC-записи; восстановление отменено, "
                    "внешнее содержимое сохранено: " + error;
        }
        return outcome;
    }
    outcome.installed = true;
    outcome.durable = result.durabilityConfirmed;
    outcome.installedState = result.installedTargetState;
    return outcome;
}

bool ensureSshConfigDurableIfCurrentState(
    const std::filesystem::path& path,
    const AtomicTargetState& installedState,
    std::string& error) {
    // Re-prove ownership before the barrier: the durability confirmation
    // applies to the exact FIC-installed state, never to whatever happens to
    // occupy the path now (an external replacement must not be fsynced into
    // legitimacy).
    if (!AtomicFileWriter::targetStateMatches(path.string(), installedState,
                                              &error)) {
        error = "Текущее состояние sshd_config не соответствует "
                "FIC-installed state; durability не подтверждается: " + error;
        return false;
    }
    if (!AtomicFileWriter::ensureTargetDurable(path.string(), &error)) {
        error = "Durability-барьер sshd_config не выполнен: " + error;
        return false;
    }
    return true;
}

namespace {
#ifdef FIC_SSH_TRANSACTION_TESTING
thread_local std::function<void(FileHandler::FileSaveOutcome&)> saveOutcomeHook;
#endif
// Keep legacy compensation/reload ordering. Record disk, durability and runtime
// facts separately: none of these imply a fully resolved failed apply.
void compensate(SshConfigFileHandler& handler, const SshRuntime& runtime,
                const SshConfigTransactionHooks& hooks, const std::string& before,
                SshConfigTransactionResult& result) {
    if (!result.installedTargetState) {
        result.message += "; точное установленное состояние неизвестно, компенсация невозможна (fail closed)";
        return;
    }
    result.compensation = SshCompensationEffect::FailedOrUnknown;
    if (hooks.beforeRestore) hooks.beforeRestore();
    std::string error;
    const auto restored = restoreSshConfigContentIfCurrentState(
        handler.filePath(), before, *result.installedTargetState, error);
    result.restoredTargetState = restored.installedState;
    if (restored.preconditionFailed) {
        result.compensation = SshCompensationEffect::RefusedByCAS;
        result.message += "; восстановить исходное состояние не удалось: " + error;
        return;
    }
    bool durable = restored.installed && restored.installedState.has_value();
    if (durable && !restored.durable)
        durable = ensureSshConfigDurableIfCurrentState(handler.filePath(), *restored.installedState, error);
    if (!durable) {
        result.message += "; восстановить исходное состояние не удалось: " + error;
        return;
    }
    if (!AtomicFileWriter::targetStateMatches(handler.filePath(), *restored.installedState, &error)) {
        result.message += "; состояние после compensation restore не подтверждено: " + error;
        return;
    }
    result.compensation = SshCompensationEffect::RestoredDurably;
    result.restoredRuntime = SshRuntimeReconciliation::FailedOrUnknown;
    if (!runtime.validateConfiguration(error)) {
        result.message += "; исходное состояние sshd_config восстановлено, но sshd его не принимает: " + error;
        return;
    }
    const auto activation = runtime.activateIfRunning();
    if (!activation.ok) {
        result.message += "; исходное состояние sshd_config восстановлено на диске, но перезагрузка не удалась: " + activation.message;
        return;
    }
    result.restoredRuntime = SshRuntimeReconciliation::LegacyAccepted;
    if (!AtomicFileWriter::targetStateMatches(handler.filePath(), *restored.installedState, &error)) {
        result.compensation = SshCompensationEffect::FailedOrUnknown;
        result.message += "; состояние после компенсации изменилось: " + error;
        return;
    }
    result.message += "; исходное состояние sshd_config восстановлено; legacy runtime reconciliation принято, verified runtime не доказан";
}
} // namespace
#ifdef FIC_SSH_TRANSACTION_TESTING
void setSshSaveOutcomeHookForTests(std::function<void(FileHandler::FileSaveOutcome&)> hook) {
    saveOutcomeHook = std::move(hook);
}
#endif

SshConfigTransactionResult runSshConfigTransaction(
    SshConfigFileHandler& handler, const SshRuntime& runtime,
    const SshConfigTransactionHooks& hooks,
    const std::function<bool(std::string&)>& planEdits,
    const std::function<bool(std::string&)>& verifyPostcondition,
    const std::string& successMessage) {
    SshConfigTransactionResult result;
    result.persistentEffect = SshPersistentEffect::NotInstalled;
    try {
        const std::string before = handler.loadSnapshot() ? handler.loadSnapshot()->content : std::string();
        std::string error;
        if (!planEdits || !planEdits(error)) {
            result.message = "Планирование изменения sshd_config не выполнено (файл не изменён): " + error;
            return result;
        }
        if (hooks.beforeWrite) hooks.beforeWrite();
        if(bool(hooks.verifiedAdmission)!=bool(hooks.verifiedActivation)) {
            result.message="incomplete verified SSH transaction contract";return result;
        }
        if(hooks.verifiedAdmission&&!hooks.verifiedAdmission(error)) {
            result.message="SSH admission refused before save: "+error;return result;
        }
        // An exception/unknown result from the writer is never no-effect.
        result.persistentEffect = SshPersistentEffect::Unknown;
        auto saved = handler.saveFileIfUnchanged(error);
#ifdef FIC_SSH_TRANSACTION_TESTING
        if (saveOutcomeHook) saveOutcomeHook(saved);
#endif
        result.installedTargetState = saved.installedTargetState;
        if (saved.installed)
            result.persistentEffect = saved.durabilityConfirmed ? SshPersistentEffect::DurableInstalled : SshPersistentEffect::Installed;
        else if (saved.result != FileHandler::FileSaveResult::Installed && !saved.installedTargetState && !saved.durabilityConfirmed)
            result.persistentEffect = SshPersistentEffect::NotInstalled;

        if (saved.result != FileHandler::FileSaveResult::Installed) {
            result.conflict = saved.preconditionFailed && !saved.installed;
            result.message = result.conflict ? "sshd_config изменился во время операции; конкурентная запись отклонена, файл не изменён: " + error
                                            : "Ошибка записи sshd_config: " + error;
            if (saved.installed && !hooks.verifiedActivation) compensate(handler, runtime, hooks, before, result);
            return result;
        }
        if (!saved.installed || !saved.installedTargetState) {
            result.message = "Не удалось зафиксировать точное состояние sshd_config после записи; компенсация невозможна (fail closed)";
            return result;
        }
        if (!saved.durabilityConfirmed) {
            if (!ensureSshConfigDurableIfCurrentState(handler.filePath(), *saved.installedTargetState, error)) {
                result.message = "Durability записи sshd_config не подтверждена: " + error;
                if(!hooks.verifiedActivation) compensate(handler, runtime, hooks, before, result);
                return result;
            }
            result.persistentEffect = SshPersistentEffect::DurableInstalled;
        }
        if (!runtime.validateConfiguration(error)) {
            result.message = "sshd не принимает новую конфигурацию: " + error;
            if(!hooks.verifiedActivation) compensate(handler, runtime, hooks, before, result);
            return result;
        }
        if (!verifyPostcondition || !verifyPostcondition(error)) {
            result.message = "Проверка результата не пройдена: " + error;
            if(!hooks.verifiedActivation) compensate(handler, runtime, hooks, before, result);
            return result;
        }
        result.activation = hooks.offlineOwnershipRelease?SshRuntimeReconciliation::NotAttempted:SshRuntimeReconciliation::FailedOrUnknown;
        if(hooks.verifiedActivation) {
            if(!hooks.verifiedActivation(*saved.installedTargetState,error)) {
                result.message=(hooks.offlineOwnershipRelease?"offline ownership release saved; stopped-state unproven; provenance retained: ":"persistent SSH configuration saved; verified activation unproven; provenance retained: ")+error;
                return result;
            }
            result.activation=hooks.offlineOwnershipRelease?SshRuntimeReconciliation::NotAttempted:SshRuntimeReconciliation::Verified;
            if(!AtomicFileWriter::targetStateMatches(handler.filePath(),*saved.installedTargetState,&error)) {
                result.message=(hooks.offlineOwnershipRelease?"offline ownership release observed; persistent main-file drift: ":"verified SSH runtime observed; persistent main-file drift: ")+error;return result;
            }
            result.message=successMessage+(hooks.offlineOwnershipRelease?"; offline ownership release; runtime NOT activated":"; verified runtime and persistent state confirmed");result.ok=true;return result;
        }
        const auto activation = runtime.activateIfRunning();
        if (!activation.ok) {
            result.message = "Перезагрузка SSH-сервиса не удалась: " + activation.message;
            if(!hooks.verifiedActivation) compensate(handler, runtime, hooks, before, result);
            return result;
        }
        result.activation = SshRuntimeReconciliation::LegacyAccepted;
        result.message = successMessage + (activation.reloaded ? "; SSH-сервис перезагружен" : "; SSH-сервис неактивен, перезагрузка не требуется");
        result.ok = true;
    } catch (const std::exception& error) {
        result.message += "; исход SSH-транзакции не разрешён: " + std::string(error.what());
    } catch (...) {
        result.message += "; исход SSH-транзакции не разрешён (unknown exception)";
    }
    return result;
}
