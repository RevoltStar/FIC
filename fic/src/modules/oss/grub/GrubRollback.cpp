#include "modules/oss/grub/GrubRollback.h"
#include "modules/oss/grub/GrubManagedBlock.h"
#include "modules/oss/grub/GrubManagedConfig.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace {

GrubCommandRunner effectiveRunner(GrubCommandRunner runner) {
    return runner ? runner : defaultGrubCommandRunner();
}

bool resolveRebuildExecutable(const GrubRollbackOptions& options,
                              std::filesystem::path& rebuildExecutable,
                              std::string& error) {
    if (!options.executables) {
        error = "GRUB rollback backend не настроен: нет resolver executable";
        return false;
    }
    return options.executables->resolve(
        fic::platform::ExecutableId::UpdateGrub,
        rebuildExecutable,
        error);
}

bool rebuildGrub(const GrubRollbackOptions& options,
                 const std::filesystem::path& rebuildExecutable,
                 std::string& error) {
    return runGrubRebuild(
        rebuildExecutable,
        options.platform.rebuildArguments,
        effectiveRunner(options.runner),
        error);
}

GrubRollbackResult failed(const std::string& message) {
    GrubRollbackResult result;
    result.message = message;
    return result;
}

GrubRollbackResult nothingToDoAfterRebuild(
    const GrubRollbackOptions& options,
    const std::filesystem::path& rebuildExecutable,
    const std::string& reason) {
    // Crash-after-source-rollback invariant: the managed setting is already
    // gone, but grub.cfg may still be stale — the rebuild is mandatory
    // before the mutation may be reported as NothingToDo.
    std::string rebuildError;
    if (!rebuildGrub(options, rebuildExecutable, rebuildError)) {
        return failed("Managed GRUB setting уже отсутствует, но обязательная "
                      "пересборка grub.cfg завершилась ошибкой: " +
                      rebuildError + ". " + reason);
    }
    GrubRollbackResult result;
    result.nothingToDo = true;
    result.message =
        "Managed GRUB setting отсутствует в FIC-артефакте; grub.cfg "
        "пересобран. " + reason;
    return result;
}

bool regularFileExists(const std::filesystem::path& path) {
    struct stat status {};
    return ::lstat(path.c_str(), &status) == 0 && S_ISREG(status.st_mode);
}

// Removes the FIC-owned drop-in after its last setting is gone: safe unlink
// of a regular non-symlink file plus a parent directory durability barrier.
bool removeOwnedManagedFile(const std::filesystem::path& path,
                            std::string& error) {
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        error = "Не удалось проверить managed drop-in " + path.string() +
            ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(status.st_mode) || !S_ISREG(status.st_mode)) {
        error = "Managed drop-in " + path.string() +
            " не является обычным файлом; удаление отклонено";
        return false;
    }
    if (::unlink(path.c_str()) != 0) {
        error = "Не удалось удалить managed drop-in " + path.string() +
            ": " + std::strerror(errno);
        return false;
    }
    const int descriptor = ::open(
        path.parent_path().c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        error = "Не удалось открыть каталог " + path.parent_path().string() +
            " после удаления managed drop-in: " + std::strerror(errno);
        return false;
    }
    const bool synced = ::fsync(descriptor) == 0;
    const int savedErrno = errno;
    ::close(descriptor);
    if (!synced) {
        error = "Не удалось подтвердить durability удаления " + path.string() +
            ": " + std::strerror(savedErrno);
        return false;
    }
    return true;
}


// Conditional compensation after a failed rebuild: restore the exact
// pre-rollback managed state only while the target still IS the state FIC
// installed (or is still absent after the empty-artifact removal).
void compensateOwnedDropInAfterRebuildFailure(
    const std::filesystem::path& managedPath,
    const AtomicTargetState& before,
    bool artifactRemoved,
    const std::optional<AtomicTargetState>& installedState,
    GrubRollbackResult& result) {
    if (artifactRemoved) {
        struct stat status {};
        if (::lstat(managedPath.c_str(), &status) == 0) {
            result.diagnostics.push_back(
                "Managed drop-in появился после удаления (concurrent "
                "drift): внешнее состояние сохранено, компенсация не "
                "выполнялась");
            return;
        }
        AtomicWriteOptions writeOptions;
        writeOptions.createIfMissing = true;
        writeOptions.exclusiveCreate = true;
        writeOptions.rejectSymlink = true;
        writeOptions.metadataPolicy = FileMetadataPolicy::EnforceProvided;
        writeOptions.fileMode = before.mode;
        writeOptions.fileOwner = before.owner;
        writeOptions.fileGroup = before.group;
        std::string compensationError;
        if (!AtomicFileWriter::write(
                managedPath.string(), before.content, writeOptions,
                &compensationError)) {
            result.diagnostics.push_back(
                "Не удалось компенсирующе восстановить managed drop-in: " +
                compensationError);
            return;
        }
        result.diagnostics.push_back(
            "Managed drop-in восстановлен в pre-rollback состоянии; journal "
            "остаётся активным");
        return;
    }
    if (!installedState) {
        result.diagnostics.push_back(
            "Не удалось компенсирующе восстановить managed drop-in: "
            "FIC-installed state не зафиксирован");
        return;
    }
    std::string compensationError;
    const GrubCompensationOutcome compensation =
        restoreGrubFileIfCurrentState(
            managedPath, before.content, *installedState, compensationError);
    if (compensation == GrubCompensationOutcome::Proven) {
        result.diagnostics.push_back(
            "Pre-rollback managed drop-in восстановлен; journal остаётся "
            "активным");
    } else if (compensation == GrubCompensationOutcome::ConcurrentDrift) {
        result.diagnostics.push_back(
            "Concurrent external drift после удаления: компенсация "
            "запрещена, внешнее состояние сохранено");
    } else {
        result.diagnostics.push_back(
            "Не удалось компенсирующе восстановить managed drop-in: " +
            compensationError);
    }
}

GrubRollbackResult undoOwnedDropIn(
    const GrubRollbackOptions& options,
    const fic::rollback::UndoRemoveGrubManagedSetting& undo,
    const std::filesystem::path& rebuildExecutable) {
    const std::filesystem::path managedPath =
        options.platform.managedConfigPath;

    if (!options.platform.baseDefaultsPath.empty()) {
        std::string baseError;
        if (!validateBaseGrubDefaults(
                options.platform.baseDefaultsPath, options.enforceOwnership,
                baseError)) {
            return failed("Базовые GRUB defaults небезопасны; managed drop-in "
                          "не изменялся, пересборка не запускалась: " +
                          baseError);
        }
    }

    if (!regularFileExists(managedPath)) {
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "Managed drop-in " + managedPath.string() + " отсутствует; "
            "внешние артефакты не создавались");
    }

    GrubManagedConfig configuration({managedPath, options.enforceOwnership});
    if (!configuration.loadConfig()) {
        GrubRollbackResult result;
        result.conflict = true;
        result.message = "Managed GRUB drop-in не был загружен как FIC-owned "
            "артефакт; откат отклонён, файл не изменялся: " +
            configuration.lastError();
        return result;
    }

    if (!configuration.isParameterExists(undo.key)) {
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "FIC-owned значение '" + undo.key + "' уже отсутствует");
    }
    if (configuration.getValue(undo.key) != undo.appliedValue) {
        GrubRollbackResult result;
        result.conflict = true;
        result.message = "Managed GRUB значение '" + undo.key +
            "' не соответствует записанному applied value (внешнее "
            "изменение FIC-owned артефакта); откат отклонён";
        return result;
    }

    AtomicTargetState before;
    std::string error;
    if (!AtomicFileWriter::captureTargetState(
            managedPath.string(), before, &error)) {
        return failed("Не удалось зафиксировать состояние managed drop-in: " +
                      error);
    }

    if (!configuration.removeValue(undo.key)) {
        return failed(configuration.lastError());
    }
    bool installed = false;
    if (!configuration.saveConfig(error, installed)) {
        return failed("Не удалось записать managed drop-in: " + error);
    }

    // Post-write proof of the removal state.
    if (configuration.installedState() &&
        !AtomicFileWriter::targetStateMatches(
            managedPath.string(), *configuration.installedState(), &error)) {
        return failed("Managed drop-in изменился сразу после записи: " + error);
    }

    const bool emptyNow = configuration.entries().empty();
    if (emptyNow) {
        // Do not leave a meaningless header-only artifact behind.
        std::string removeError;
        if (!removeOwnedManagedFile(managedPath, removeError)) {
            return failed("Managed drop-in стал пустым, но не был удалён: " +
                          removeError);
        }
    }

    if (!rebuildGrub(options, rebuildExecutable, error)) {
        GrubRollbackResult result;
        result.message = "FIC-owned значение удалено, но обязательная "
            "пересборка grub.cfg завершилась ошибкой: " + error;
        compensateOwnedDropInAfterRebuildFailure(
            managedPath, before, emptyNow,
            configuration.installedState(), result);
        std::string compensationRebuildError;
        if (!rebuildGrub(options, rebuildExecutable, compensationRebuildError)) {
            result.diagnostics.push_back(
                "Компенсирующая пересборка grub.cfg завершилась ошибкой: " +
                compensationRebuildError);
        }
        return result;
    }

    GrubRollbackResult result;
    result.ok = true;
    result.message = "FIC-owned GRUB значение '" + undo.key +
        "' удалено из managed drop-in; grub.cfg пересобран";
    return result;
}

GrubRollbackResult undoSharedBlock(
    const GrubRollbackOptions& options,
    const fic::rollback::UndoRemoveGrubManagedSetting& undo,
    const std::filesystem::path& rebuildExecutable) {
    const std::filesystem::path sharedPath =
        options.platform.sharedDefaultsPath;

    if (!regularFileExists(sharedPath)) {
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "Shared GRUB defaults " + sharedPath.string() +
                " отсутствуют; FIC block не восстанавливался");
    }

    GrubConfiguration configuration({sharedPath, {}, {},
                                     options.enforceOwnership});
    std::string error;
    if (!configuration.load(error)) {
        return failed("Не удалось загрузить shared GRUB defaults: " + error);
    }

    AtomicTargetState before;
    if (!AtomicFileWriter::captureTargetState(
            sharedPath.string(), before, &error)) {
        return failed("Не удалось зафиксировать состояние shared GRUB "
                      "defaults: " + error);
    }

    // Strict ownership proof: a malformed or ambiguous FIC block is a
    // fail-closed conflict, the file is never touched.
    const GrubBlockParseResult parse =
        parseGrubManagedBlock(configuration.content());
    if (!parse.ok) {
        GrubRollbackResult result;
        result.conflict = true;
        result.message = "FIC managed block в " + sharedPath.string() +
            " не является валидным FIC-owned артефактом; откат отклонён, "
            "файл не изменялся: " + parse.error;
        return result;
    }
    if (!parse.view.present) {
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "FIC managed block уже отсутствует");
    }
    std::string currentValue;
    bool keyFound = false;
    for (const GrubBlockEntries::value_type& entry : parse.view.entries) {
        if (entry.first == undo.key) {
            keyFound = true;
            currentValue = entry.second;
        }
    }
    if (!keyFound) {
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "FIC-owned значение '" + undo.key + "' уже отсутствует в block");
    }
    if (currentValue != undo.appliedValue) {
        GrubRollbackResult result;
        result.conflict = true;
        result.message = "Managed GRUB значение '" + undo.key +
            "' в FIC block не соответствует записанному applied value "
            "(внешнее изменение FIC-owned артефакта); откат отклонён";
        return result;
    }

    const GrubBlockMutationResult removal = removeGrubManagedBlockValue(
        configuration.content(), undo.key);
    if (!removal.ok) {
        return failed(removal.error);
    }

    AtomicWriteOptions writeOptions;
    writeOptions.createIfMissing = false;
    writeOptions.rejectSymlink = true;
    writeOptions.expectedTargetState = before;
    AtomicWriteResult writeResult;
    if (!AtomicFileWriter::writeWithResult(
            sharedPath.string(), removal.content, writeOptions,
            &error, &writeResult)) {
        GrubRollbackResult result;
        result.message = "Не удалось записать shared GRUB defaults: " + error;
        if (writeResult.installed) {
            result.diagnostics.push_back(
                "Запись опубликована, но durability не подтверждена: "
                "источник может содержать выполненный откат; journal "
                "остаётся активным");
        }
        return result;
    }
    if (!writeResult.installedTargetState ||
        !AtomicFileWriter::targetStateMatches(
            sharedPath.string(), *writeResult.installedTargetState,
            &error)) {
        return failed("Shared GRUB defaults изменились сразу после записи "
                      "отката: " + error);
    }
    const AtomicTargetState installed = *writeResult.installedTargetState;

    if (!rebuildGrub(options, rebuildExecutable, error)) {
        GrubRollbackResult result;
        result.message = "FIC-owned значение удалено из managed block, но "
            "обязательная пересборка grub.cfg завершилась ошибкой: " + error;
        std::string compensationError;
        const GrubCompensationOutcome compensation =
            restoreGrubFileIfCurrentState(
                sharedPath, before.content, installed, compensationError);
        if (compensation == GrubCompensationOutcome::Proven) {
            result.diagnostics.push_back(
                "Pre-rollback FIC block восстановлен; journal остаётся "
                "активным");
        } else if (compensation == GrubCompensationOutcome::ConcurrentDrift) {
            result.diagnostics.push_back(
                "Concurrent external drift после удаления: компенсация "
                "запрещена, внешнее состояние сохранено");
        } else {
            result.diagnostics.push_back(
                "Не удалось компенсирующе восстановить shared GRUB "
                "defaults: " + compensationError);
        }
        std::string compensationRebuildError;
        if (!rebuildGrub(options, rebuildExecutable, compensationRebuildError)) {
            result.diagnostics.push_back(
                "Компенсирующая пересборка grub.cfg завершилась ошибкой: " +
                compensationRebuildError);
        }
        return result;
    }

    GrubRollbackResult result;
    result.ok = true;
    result.message = "FIC-owned GRUB значение '" + undo.key +
        "' удалено из managed block; grub.cfg пересобран";
    return result;
}

} // namespace

GrubRollbackResult undoGrubManagedSetting(
    const GrubRollbackOptions& options,
    const fic::rollback::UndoRemoveGrubManagedSetting& undo) {
    if (!isGrubManagedKey(undo.key)) {
        return failed("Недопустимый ключ FIC GRUB managed setting: " +
                      undo.key);
    }
    if (undo.appliedValue.empty() ||
        undo.appliedValue.find_first_of("\r\n") != std::string::npos ||
        undo.appliedValue.find('\0') != std::string::npos) {
        return failed("Undo payload содержит недопустимое applied value");
    }

    std::filesystem::path rebuildExecutable;
    std::string resolveError;
    if (!resolveRebuildExecutable(options, rebuildExecutable, resolveError)) {
        return failed(resolveError);
    }

    switch (options.platform.topology) {
    case fic::platform::GrubConfigTopology::OwnedDefaultsDropIn:
        return undoOwnedDropIn(options, undo, rebuildExecutable);
    case fic::platform::GrubConfigTopology::SharedDefaultsFile:
        return undoSharedBlock(options, undo, rebuildExecutable);
    default:
        return failed("Неизвестная топология GRUB-конфигурации");
    }
}
