#include "modules/oss/grub/GrubConfiguration.h"
#include "modules/oss/grub/GrubManagedBlock.h"
#include "modules/oss/grub/GrubManagedConfig.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr std::uintmax_t kMaximumGrubDefaultsSize = 1024U * 1024U;

bool readFile(const std::filesystem::path& path,
              std::string& content,
              std::string& error) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        error = "Не удалось открыть файл GRUB: " + path.string();
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        error = "Не удалось прочитать файл GRUB: " + path.string();
        return false;
    }
    content = buffer.str();
    return true;
}

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "команда пересборки GRUB превысила таймаут";
    }
    if (!result.standardError.empty()) {
        return result.standardError;
    }
    if (!result.standardOutput.empty()) {
        return result.standardOutput;
    }
    if (result.exitCode != 0) {
        return "команда пересборки GRUB завершилась с кодом " +
            std::to_string(result.exitCode);
    }
    if (!result.started) {
        return "команда пересборки GRUB не была запущена";
    }
    return "неизвестная ошибка пересборки GRUB";
}

} // namespace

std::mutex& grubBackendMutex() {
    static std::mutex mutex;
    return mutex;
}

GrubCommandRunner defaultGrubCommandRunner() {
    return [](const std::string& executable,
              const std::vector<std::string>& arguments,
              const ProcessOptions& processOptions) {
        return VerifiedProcessExecutor::execute(
            executable, arguments, processOptions);
    };
}

bool runGrubRebuild(const std::filesystem::path& executable,
                    const std::vector<std::string>& arguments,
                    const GrubCommandRunner& runner,
                    std::string& error) {
    if (executable.empty() || !executable.is_absolute()) {
        error = "Профиль платформы не задаёт команду пересборки GRUB";
        return false;
    }
    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    processOptions.timeout = std::chrono::seconds(60);
    const ProcessResult result = runner(executable.string(), arguments, processOptions);
    if (!result.success()) {
        error = "Не удалось пересобрать конфигурацию GRUB: " +
            processFailure(result);
        return false;
    }
    error.clear();
    return true;
}

GrubCompensationOutcome restoreGrubFileIfCurrentState(
    const std::filesystem::path& path,
    const std::string& content,
    const AtomicTargetState& expectedInstalledState,
    std::string& error) {
    std::string matchError;
    if (!AtomicFileWriter::targetStateMatches(
            path.string(), expectedInstalledState, &matchError)) {
        error = "файл GRUB больше не находится в состоянии, установленном "
                "FIC (concurrent external modification); компенсация "
                "отклонена: " + matchError;
        return GrubCompensationOutcome::ConcurrentDrift;
    }
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.expectedTargetState = expectedInstalledState;
    if (!AtomicFileWriter::write(path.string(), content, options, &error)) {
        return GrubCompensationOutcome::Failed;
    }
    return GrubCompensationOutcome::Proven;
}

GrubConfiguration::GrubConfiguration(GrubConfigurationOptions options,
                                     GrubCommandRunner runner)
    : options_(std::move(options)),
      runner_(runner ? std::move(runner) : defaultGrubCommandRunner()) {}

bool GrubConfiguration::checkFileSafety(std::string& error) const {
    struct stat status {};
    if (::lstat(options_.defaultsPath.c_str(), &status) != 0) {
        error = "Не удалось проверить файл GRUB-конфигурации: " +
            options_.defaultsPath.string() + ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(status.st_mode) || !S_ISREG(status.st_mode)) {
        error = "GRUB-конфигурация не является обычным файлом: " +
            options_.defaultsPath.string();
        return false;
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        kMaximumGrubDefaultsSize) {
        error = "GRUB-конфигурация превышает допустимый размер";
        return false;
    }
    if (!options_.enforceOwnership) {
        return true;
    }
    if (status.st_uid != 0 || (status.st_mode & 0022) != 0) {
        error = "Небезопасные владелец или права GRUB-файла: " +
            options_.defaultsPath.string();
        return false;
    }

    std::filesystem::path current = options_.defaultsPath.parent_path();
    while (!current.empty()) {
        struct stat directoryStatus {};
        if (::lstat(current.c_str(), &directoryStatus) != 0 ||
            S_ISLNK(directoryStatus.st_mode) ||
            !S_ISDIR(directoryStatus.st_mode) ||
            directoryStatus.st_uid != 0 ||
            (directoryStatus.st_mode & 0022) != 0) {
            error = "GRUB-файл находится в небезопасном каталоге: " +
                current.string();
            return false;
        }
        if (current == current.root_path()) {
            break;
        }
        current = current.parent_path();
    }
    return true;
}

bool GrubConfiguration::readDocument(std::string& error) {
    if (!options_.defaultsPath.is_absolute() ||
        options_.defaultsPath != options_.defaultsPath.lexically_normal()) {
        error = "Путь GRUB-конфигурации должен быть абсолютным и нормализованным";
        return false;
    }
    if (!checkFileSafety(error)) {
        return false;
    }
    return readFile(options_.defaultsPath, document_, error);
}

bool GrubConfiguration::load(std::string& error) {
    document_.clear();
    if (!readDocument(error)) {
        document_.clear();
        return false;
    }
    return true;
}

bool GrubConfiguration::rebuild(std::string& error) const {
    return runGrubRebuild(
        options_.rebuildExecutable, options_.rebuildArguments,
        runner_, error);
}

namespace {

// Conditional compensation after a failed rebuild: restore the exact
// pre-apply state only while the target still IS the FIC-installed state.
GrubOperationResult compensateAfterRebuildFailure(
    const std::filesystem::path& path,
    const AtomicTargetState& before,
    const AtomicTargetState& installed,
    const std::function<bool(std::string&)>& rebuildFn,
    GrubOperationResult result) {
    std::string compensationError;
    const GrubCompensationOutcome compensation =
        restoreGrubFileIfCurrentState(path, before.content, installed,
                                      compensationError);
    if (compensation == GrubCompensationOutcome::Proven) {
        std::string verifyError;
        AtomicTargetState restored;
        if (!AtomicFileWriter::captureTargetState(
                path.string(), restored, &verifyError) ||
            restored.content != before.content ||
            restored.mode != before.mode ||
            restored.owner != before.owner ||
            restored.group != before.group) {
            result.sourceState = GrubSourceMutationState::Indeterminate;
            result.diagnostics.push_back(
                "Исходное состояние " + path.string() +
                " не подтвердилось после компенсации: " + verifyError);
            return result;
        }
        result.sourceState = GrubSourceMutationState::Compensated;
        result.diagnostics.push_back(
            "Исходное состояние " + path.string() +
            " восстановлено после ошибки пересборки");
        std::string compensationRebuildError;
        if (!rebuildFn(compensationRebuildError)) {
            result.diagnostics.push_back(
                "Компенсирующая пересборка завершилась ошибкой: " +
                compensationRebuildError);
        }
        return result;
    }
    result.sourceState = GrubSourceMutationState::Indeterminate;
    if (compensation == GrubCompensationOutcome::ConcurrentDrift) {
        result.diagnostics.push_back(
            "Обнаружено внешнее изменение файла после записи FIC "
            "(concurrent drift): внешнее состояние сохранено, исходное не "
            "восстанавливалось, компенсирующая пересборка не запускалась");
        return result;
    }
    result.diagnostics.push_back(
        "Не удалось восстановить исходное состояние: " + compensationError);
    return result;
}

} // namespace

GrubOperationResult GrubConfiguration::ensureManagedValue(
    const std::string& key,
    const std::string& value) {
    GrubOperationResult result;
    if (!isGrubManagedKey(key)) {
        result.message = "Недопустимый ключ FIC GRUB managed block: " + key;
        return result;
    }
    if (value.find_first_of("\r\n") != std::string::npos ||
        value.find('\0') != std::string::npos) {
        result.message = "Значение GRUB-параметра содержит запрещённые символы";
        return result;
    }

    // Ownership proof first: a malformed FIC block is a fail-closed conflict,
    // the file is never touched in that case.
    const GrubBlockParseResult parse = parseGrubManagedBlock(document_);
    if (!parse.ok) {
        result.message = "FIC managed block в " + options_.defaultsPath.string() +
            ": " + parse.error;
        return result;
    }
    bool alreadySet = false;
    for (const GrubBlockEntries::value_type& entry : parse.view.entries) {
        if (entry.first == key && entry.second == value) {
            alreadySet = true;
        }
    }

    // Transaction snapshot for the CAS write and the conditional
    // compensation. The snapshot is captured BEFORE anything is computed as
    // "installed"; it is never re-derived after a failure.
    AtomicTargetState before;
    std::string error;
    if (!AtomicFileWriter::captureTargetState(
            options_.defaultsPath.string(), before, &error)) {
        result.message = "Не удалось зафиксировать состояние " +
            options_.defaultsPath.string() + ": " + error;
        return result;
    }

    if (alreadySet) {
        // Idempotent path: no source mutation, but the rebuild is still
        // mandatory because grub.cfg is a derived artifact.
        if (!rebuild(error)) {
            result.message = error;
            result.sourceState = GrubSourceMutationState::Unchanged;
            return result;
        }
        result.ok = true;
        result.changed = false;
        result.sourceState = GrubSourceMutationState::Unchanged;
        result.message =
            "FIC managed block уже содержит значение " + key +
            "; grub.cfg пересобран";
        return result;
    }

    const GrubBlockMutationResult mutation =
        setGrubManagedBlockValue(document_, key, value);
    if (!mutation.ok) {
        result.message = mutation.error;
        return result;
    }

    AtomicWriteOptions writeOptions;
    writeOptions.createIfMissing = false;
    writeOptions.rejectSymlink = true;
    writeOptions.expectedTargetState = before;
    AtomicWriteResult writeResult;
    if (!AtomicFileWriter::writeWithResult(
            options_.defaultsPath.string(), mutation.content, writeOptions,
            &error, &writeResult)) {
        if (writeResult.installed) {
            // Rename published the new state but durability is unproven:
            // the source may still carry the FIC mutation.
            result.sourceState = GrubSourceMutationState::Indeterminate;
            result.message = "Не удалось подтвердить durability записи " +
                options_.defaultsPath.string() + ": " + error;
            return result;
        }
        result.message = "Не удалось записать GRUB-конфигурацию: " + error;
        result.sourceState = GrubSourceMutationState::Unchanged;
        return result;
    }
    if (!writeResult.installedTargetState) {
        result.message = "Запись GRUB-конфигурации не вернула установленное "
                         "состояние";
        result.sourceState = GrubSourceMutationState::Indeterminate;
        return result;
    }
    const AtomicTargetState installed = *writeResult.installedTargetState;
    result.sourceState = GrubSourceMutationState::Installed;

    // Post-write proof: the installed state must still occupy the path.
    if (!AtomicFileWriter::targetStateMatches(
            options_.defaultsPath.string(), installed, &error)) {
        result.message = "Файл GRUB изменился сразу после записи: " + error;
        result.sourceState = GrubSourceMutationState::Indeterminate;
        return result;
    }

    if (!rebuild(error)) {
        return compensateAfterRebuildFailure(
            options_.defaultsPath, before, installed,
            [this](std::string& rebuildError) {
                return rebuild(rebuildError);
            },
            result);
    }

    result.ok = true;
    result.changed = true;
    result.sourceState = GrubSourceMutationState::Installed;
    result.message = "FIC managed block обновлён и grub.cfg пересобран";
    result.diagnostics.push_back(
        parse.view.present
            ? "Предыдущее managed-значение " + key + " обновлено в FIC block"
            : "Параметр " + key + " добавлен в FIC managed block");
    return result;
}

bool validateBaseGrubDefaults(const std::filesystem::path& path,
                              bool enforceOwnership,
                              std::string& error) {
    if (!path.is_absolute() || path != path.lexically_normal()) {
        error = "Базовые GRUB defaults должны задаваться абсолютным "
            "нормализованным путём: " + path.string();
        return false;
    }
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        if (errno == ENOENT) {
            // A missing base defaults file is the safe state: nothing is
            // sourced by update-grub.
            return true;
        }
        error = "Не удалось проверить базовые GRUB defaults " +
            path.string() + ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(status.st_mode)) {
        error = "Базовые GRUB defaults не должны быть symbolic link: " +
            path.string();
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        error = "Базовые GRUB defaults не являются обычным файлом: " +
            path.string();
        return false;
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        kMaximumGrubDefaultsSize) {
        error = "Базовые GRUB defaults превышают допустимый размер";
        return false;
    }
    if ((status.st_mode & 0022) != 0) {
        error = "Базовые GRUB defaults доступны на запись группе или всем: " +
            path.string();
        return false;
    }
    if (enforceOwnership &&
        (status.st_uid != 0 || status.st_gid != 0)) {
        error = "Базовые GRUB defaults должны принадлежать root: " +
            path.string();
        return false;
    }
    for (std::filesystem::path current = path.parent_path(); !current.empty();
         current = current.parent_path()) {
        struct stat directoryStatus {};
        if (::lstat(current.c_str(), &directoryStatus) != 0 ||
            S_ISLNK(directoryStatus.st_mode) ||
            !S_ISDIR(directoryStatus.st_mode)) {
            error = "Каталог базовых GRUB defaults отсутствует или "
                "небезопасен: " + current.string();
            return false;
        }
        // A group-writable directory in the chain is always unsafe. A
        // world-writable directory is acceptable only with the sticky bit
        // (shared-tmp semantics): sticky prevents other users from
        // replacing or removing entries they do not own, so the validated
        // base defaults file itself cannot be swapped underneath the check.
        const bool worldWritable = (directoryStatus.st_mode & 0002) != 0;
        if ((directoryStatus.st_mode & 0022) != 0 &&
            !(worldWritable && (directoryStatus.st_mode & S_ISVTX) != 0)) {
            error = "Каталог базовых GRUB defaults доступен на запись "
                "группе или всем: " + current.string();
            return false;
        }
        if (enforceOwnership &&
            (directoryStatus.st_uid != 0 || directoryStatus.st_gid != 0)) {
            error = "Небезопасные владелец или права каталога базовых "
                "GRUB defaults: " + current.string();
            return false;
        }
        if (current == current.root_path()) break;
    }
    return true;
}

GrubValueObservation inspectGrubManagedValue(
    const GrubManagedConfigurationOptions& options,
    const std::string& key) {
    GrubValueObservation observation;
    if (!isGrubManagedKey(key)) {
        observation.valid = false;
        observation.error = "Недопустимый ключ FIC GRUB managed block: " + key;
        return observation;
    }
    if (!options.managedPath.empty()) {
        // Debian/Ubuntu owned drop-in.
        observation.source = options.managedPath;
        struct stat status {};
        if (::lstat(options.managedPath.c_str(), &status) != 0) {
            if (errno == ENOENT) {
                return observation; // missing artifact: valid, not found
            }
            observation.valid = false;
            observation.error = "Не удалось проверить managed drop-in: " +
                options.managedPath.string() + ": " + std::strerror(errno);
            return observation;
        }
        GrubManagedConfig configuration({options.managedPath,
                                         options.enforceOwnership});
        if (!configuration.loadConfig()) {
            observation.valid = false;
            observation.error = configuration.lastError();
            return observation;
        }
        if (!configuration.isParameterExists(key)) {
            return observation;
        }
        observation.found = true;
        observation.value = configuration.getValue(key);
        return observation;
    }
    if (!options.sharedDefaultsPath.empty()) {
        // ALT shared defaults with the FIC EOF managed block.
        observation.source = options.sharedDefaultsPath;
        struct stat status {};
        if (::lstat(options.sharedDefaultsPath.c_str(), &status) != 0) {
            if (errno == ENOENT) {
                return observation;
            }
            observation.valid = false;
            observation.error = "Не удалось проверить shared GRUB defaults: " +
                options.sharedDefaultsPath.string() + ": " +
                std::strerror(errno);
            return observation;
        }
        GrubConfiguration configuration({options.sharedDefaultsPath,
                                         {}, {}, options.enforceOwnership});
        std::string error;
        if (!configuration.load(error)) {
            observation.valid = false;
            observation.error = error;
            return observation;
        }
        const GrubBlockParseResult parse =
            parseGrubManagedBlock(configuration.content());
        if (!parse.ok) {
            observation.valid = false;
            observation.error = parse.error;
            return observation;
        }
        for (const GrubBlockEntries::value_type& entry : parse.view.entries) {
            if (entry.first == key) {
                observation.found = true;
                observation.value = entry.second;
                return observation;
            }
        }
        return observation;
    }
    observation.valid = false;
    observation.error = "Топология GRUB-конфигурации не задана";
    return observation;
}

GrubOperationResult ensureManagedGrubDropInValue(
    const GrubManagedConfigurationOptions& options,
    const std::string& key,
    const std::string& value,
    GrubCommandRunner runner) {
    GrubOperationResult result;
    // Base defaults are proven safe BEFORE the managed drop-in is loaded,
    // mutated, or rebuilt — including on the idempotent path, because
    // update-grub sources /etc/default/grub on every rebuild.
    if (!options.baseDefaultsPath.empty()) {
        std::string baseError;
        if (!validateBaseGrubDefaults(
                options.baseDefaultsPath, options.enforceOwnership,
                baseError)) {
            result.message = "Базовые GRUB defaults небезопасны; managed "
                "drop-in не изменялся, пересборка не запускалась: " +
                baseError;
            return result;
        }
    }
    runner = runner ? runner : defaultGrubCommandRunner();
    GrubManagedConfig configuration({
        options.managedPath, options.enforceOwnership});
    if (!configuration.loadConfig()) {
        result.message = "Не удалось загрузить managed GRUB-конфигурацию: " +
            configuration.lastError();
        return result;
    }

    const bool found = configuration.isParameterExists(key);
    const std::string previousValue = found
        ? configuration.getValue(key)
        : std::string{};
    if (found && previousValue == value) {
        std::string rebuildError;
        if (!configuration.snapshotUnchanged(rebuildError)) {
            result.message = "Managed GRUB-конфигурация изменилась перед "
                "пересборкой: " + rebuildError;
            return result;
        }
        if (!runGrubRebuild(
                options.rebuildExecutable, options.rebuildArguments,
                runner, rebuildError)) {
            result.message = rebuildError;
            return result;
        }
        result.ok = true;
        result.message =
            "Persistent-значение GRUB соответствует политике; grub.cfg пересобран";
        return result;
    }

    if (!configuration.setValue(key, value)) {
        result.message = configuration.lastError();
        return result;
    }

    auto restore = [&](const std::string& context) {
        std::string restoreError;
        bool concurrentDrift = false;
        if (!configuration.restoreOriginal(restoreError, concurrentDrift) ||
            !configuration.verifyOriginal(restoreError)) {
            result.sourceState = GrubSourceMutationState::Indeterminate;
            result.diagnostics.push_back(
                context + ": не удалось восстановить исходный managed GRUB-файл: " +
                restoreError);
            if (concurrentDrift) {
                result.diagnostics.push_back(
                    "Обнаружено внешнее изменение managed GRUB-файла после "
                    "записи FIC (concurrent drift): внешнее состояние "
                    "сохранено, исходное значение НЕ восстанавливалось, "
                    "файл не удалялся, компенсирующая пересборка не "
                    "запускалась");
            }
            return false;
        }
        result.sourceState = GrubSourceMutationState::Compensated;
        return true;
    };

    std::string error;
    bool installed = false;
    if (!configuration.saveConfig(error, installed)) {
        result.message = "Не удалось записать managed GRUB-конфигурацию: " + error;
        if (installed) {
            result.sourceState = GrubSourceMutationState::Indeterminate;
            restore("Ошибка записи после atomic replace");
        }
        return result;
    }
    result.sourceState = GrubSourceMutationState::Installed;

    GrubManagedConfig verification({
        options.managedPath, options.enforceOwnership});
    if (!verification.loadConfig() ||
        verification.entries() != configuration.entries()) {
        const std::string verificationError = verification.lastError().empty()
            ? "managed GRUB-файл не соответствует записанному состоянию"
            : verification.lastError();
        result.message = "Не удалось проверить managed GRUB-файл после записи: " +
            verificationError;
        restore("Ошибка post-write verification");
        return result;
    }

    if (!runGrubRebuild(
            options.rebuildExecutable, options.rebuildArguments,
            runner, error)) {
        result.message = "Новая GRUB-конфигурация не активирована: " + error;
        if (restore("Ошибка пересборки GRUB") &&
            result.sourceState == GrubSourceMutationState::Compensated) {
            std::string compensationError;
            if (!runGrubRebuild(
                    options.rebuildExecutable, options.rebuildArguments,
                    runner, compensationError)) {
                result.diagnostics.push_back(
                    "Исходный managed GRUB-файл восстановлен, но "
                    "компенсирующая пересборка завершилась ошибкой: " +
                    compensationError);
            }
        }
        return result;
    }

    result.ok = true;
    result.changed = true;
    result.sourceState = GrubSourceMutationState::Installed;
    result.message = "Отклонение GRUB исправлено и grub.cfg пересобран";
    result.diagnostics.push_back(
        found
            ? "Предыдущее managed-значение " + key + " = " + previousValue
            : "Параметр " + key + " отсутствовал в managed GRUB-конфигурации");
    return result;
}
