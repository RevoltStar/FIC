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
    // P0 invariant: EVERY rollback rebuild runs only on currently validated
    // inputs — the base/shared defaults are re-proven immediately before the
    // rebuild command is spawned, for the mandatory rebuild, the
    // NothingToDo rebuild, the post-removal rebuild and the compensating
    // rebuild alike. A failed validation never runs the rebuild and never
    // resolves the journal record.
    GrubManagedConfigurationOptions managed;
    managed.managedPath = options.platform.managedConfigPath;
    managed.baseDefaultsPath = options.platform.baseDefaultsPath;
    managed.sharedDefaultsPath = options.platform.sharedDefaultsPath;
    managed.enforceOwnership = options.enforceOwnership;
    if (!validateGrubRebuildInputs(managed, error)) {
        error = "Входные данные пересборки GRUB не прошли проверку "
                "безопасности, пересборка не запускалась: " + error;
        return false;
    }
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


// Conditional compensation after a failed rebuild: restore the exact
// pre-rollback managed state only while the target still IS the state FIC
// installed (the canonical header-only empty drop-in is never unlinked, so
// there is no artifact-removal case to compensate). When the installed state
// is not proven (unwritten artifact), compensation is impossible.
void compensateOwnedDropInAfterRebuildFailure(
    const std::filesystem::path& managedPath,
    const AtomicTargetState& before,
    const std::optional<AtomicTargetState>& installedState,
    GrubRollbackResult& result) {
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

    // Typed probe: Missing (ENOENT) is a legitimate released state, but an
    // unsafe artifact occupying the path (symlink, directory, FIFO, ...) is
    // NEVER "already released" — it is a fail-closed conflict without any
    // rebuild, and a non-ENOENT lstat error fails closed as well.
    const GrubTargetProbe probe = probeGrubTargetFile(managedPath);
    if (probe.kind == GrubTargetKind::Missing) {
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "Managed drop-in " + managedPath.string() + " отсутствует; "
            "внешние артефакты не создавались");
    }
    if (probe.kind == GrubTargetKind::Unsafe) {
        GrubRollbackResult result;
        result.conflict = true;
        result.message = "Managed drop-in " + managedPath.string() +
            " не является обычным несимлинковым файлом; откат отклонён, "
            "файл не изменялся, пересборка не запускалась: " + probe.error;
        return result;
    }
    if (probe.kind == GrubTargetKind::Error) {
        return failed("Не удалось классифицировать managed drop-in: " +
                      probe.error);
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

    // SINGLE-SNAPSHOT: the pre-rollback state is the exact snapshot captured
    // by loadConfig() — the same state the CAS write below is proven
    // against. A fresh re-read must never substitute for it.
    AtomicTargetState before;
    if (!configuration.originalStateAtLoad(before)) {
        // The artifact vanished between the probe and the load: ownership is
        // already released.
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "Managed drop-in " + managedPath.string() +
            " отсутствует; внешние артефакты не создавались");
    }
    std::string error;

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

    // The canonical empty drop-in (header-only zzzz-fic.cfg) is intentionally
    // RETAINED: a last-key removal never unlinks the FIC-owned artifact.
    // Keeping a stable canonical file removes the unlink/recreate race and
    // the concurrent-drift compensation corner cases; the header-only file
    // is inert for update-grub and stays FIC-owned for future applies.

    if (!rebuildGrub(options, rebuildExecutable, error)) {
        GrubRollbackResult result;
        result.message = "FIC-owned значение удалено, но обязательная "
            "пересборка grub.cfg завершилась ошибкой: " + error;
        compensateOwnedDropInAfterRebuildFailure(
            managedPath, before, configuration.installedState(), result);
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

    // Typed probe: Missing (ENOENT) is a legitimate released state; an
    // unsafe artifact occupying the path is a fail-closed conflict without
    // any rebuild; other lstat errors fail closed as well.
    const GrubTargetProbe probe = probeGrubTargetFile(sharedPath);
    if (probe.kind == GrubTargetKind::Missing) {
        return nothingToDoAfterRebuild(
            options, rebuildExecutable,
            "Shared GRUB defaults " + sharedPath.string() +
                " отсутствуют; FIC block не восстанавливался");
    }
    if (probe.kind == GrubTargetKind::Unsafe) {
        GrubRollbackResult result;
        result.conflict = true;
        result.message = "Shared GRUB defaults " + sharedPath.string() +
            " не являются обычным несимлинковым файлом; откат отклонён, "
            "файл не изменялся, пересборка не запускалась: " + probe.error;
        return result;
    }
    if (probe.kind == GrubTargetKind::Error) {
        return failed("Не удалось классифицировать shared GRUB defaults: " +
                      probe.error);
    }

    GrubConfiguration configuration({sharedPath, {}, {},
                                     options.enforceOwnership});
    std::string error;
    if (!configuration.load(error)) {
        return failed("Не удалось загрузить shared GRUB defaults: " + error);
    }

    // SINGLE-SNAPSHOT: the pre-rollback state is the exact snapshot captured
    // by load() — the same snapshot the FIC block was parsed from and the
    // same state the CAS write below is proven against.
    const AtomicTargetState& before = configuration.loadedState();

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
    // Deterministic test seam: an external writer racing between the FIC
    // snapshot and this CAS write (production never sets the hook).
    fireGrubSharedPreWriteHookForTests();
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
