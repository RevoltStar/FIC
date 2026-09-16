#include "modules/net/ssh/SshRollback.h"

#include "modules/net/ssh/SshConfigFile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <fstream>
#include <sstream>
#include <utility>

namespace {

bool readSshConfigContent(const std::filesystem::path& path,
                          std::string& content) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        return false;
    }
    content = buffer.str();
    return true;
}

SshRuntime makeRuntime(const SshRollbackOptions& options) {
    SshRuntimeOptions runtimeOptions;
    runtimeOptions.configPath = options.configPath;
    runtimeOptions.includeBasePath = options.includeBasePath;
    runtimeOptions.serviceUnits = options.serviceUnits;
    return SshRuntime(runtimeOptions, *options.executables, options.runner);
}

} // namespace

bool restoreSshConfigContent(const std::filesystem::path& path,
                             const std::string& content,
                             std::string& error) {
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    return AtomicFileWriter::write(path.string(), content, options, &error);
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
        undo.appliedGlobalSectionFingerprint.empty() ||
        undo.reverseEdits.empty()) {
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

    // Conservative drift detection: rollback proceeds only when the whole
    // global section is identical to the state FIC recorded after its
    // mutation. Any unrelated global change (including comments) is a
    // Conflict; nothing is written.
    const std::string currentFingerprint = handler.globalSectionFingerprint();
    if (currentFingerprint != undo.appliedGlobalSectionFingerprint) {
        result.conflict = true;
        result.message = "Global section " + options.configPath.string() +
                         " изменился после применения FIC; откат SSH-мутации "
                         "отменён без изменения файла";
        return result;
    }

    // In-memory pre-rollback copy used for transactional compensation.
    std::string preRollbackContent;
    if (!readSshConfigContent(options.configPath, preRollbackContent)) {
        result.message = "Не удалось прочитать " + options.configPath.string() +
                         " перед откатом";
        return result;
    }

    std::string error;
    if (!handler.applyReverseEdits(undo.reverseEdits, error)) {
        result.message = "Откат SSH-мутации отменён (файл не изменён): " + error;
        return result;
    }
    if (!handler.saveFile()) {
        result.message = "Не удалось записать откат SSH-мутации в " +
                         options.configPath.string();
        return result;
    }

    SshRuntime runtime = makeRuntime(options);
    std::string validationError;
    if (!runtime.validateConfiguration(validationError)) {
        // Post-rollback validation failed: restore the pre-rollback (FIC)
        // state. Do not reload a configuration sshd does not accept.
        std::string restoreError;
        const bool stateRestored = restoreSshConfigContent(
            options.configPath, preRollbackContent, restoreError);
        if (stateRestored) {
            result.message = "Откат SSH-мутации записан, но sshd -T не принял "
                             "результат; состояние до отката восстановлено: " +
                             validationError;
        } else {
            result.message = "Откат SSH-мутации не прошёл валидацию (" +
                             validationError + "); восстановить состояние до " +
                             "отката не удалось: " + restoreError;
        }
        return result;
    }

    const SshActivationResult activation = runtime.activateIfRunning();
    if (!activation.ok) {
        std::string restoreError;
        const bool stateRestored = restoreSshConfigContent(
            options.configPath, preRollbackContent, restoreError);
        if (!stateRestored) {
            result.message = "Перезагрузка SSH-сервиса не удалась (" +
                             activation.message +
                             "); восстановить состояние до отката не удалось: " +
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