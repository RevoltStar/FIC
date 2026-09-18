#include "modules/oss/grub/GrubConfiguration.h"
#include "modules/oss/grub/GrubManagedBlock.h"
#include "modules/oss/grub/GrubManagedConfig.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr std::uintmax_t kMaximumGrubDefaultsSize = 1024U * 1024U;

// Test-only deterministic seam (see GrubConfiguration.h). Never set in
// production.
std::function<void()>& grubSharedPreWriteHook() {
    static std::function<void()> hook;
    return hook;
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

void setGrubSharedPreWriteHookForTests(std::function<void()> hook) {
    grubSharedPreWriteHook() = std::move(hook);
}

void fireGrubSharedPreWriteHookForTests() {
    std::function<void()> hook;
    std::swap(hook, grubSharedPreWriteHook());
    if (hook) {
        hook();
    }
}

// Deterministic TOCTOU seam for tests: the hook receives the currently
// loaded snapshot path and replaces the file on disk. Cleared after firing,
// production never installs it.
static std::function<void(const std::string&)>& grubPostLoadMutationHook() {
    static std::function<void(const std::string&)> hook;
    return hook;
}

void setGrubPostLoadMutationHookForTests(
    std::function<void(const std::string&)> hook) {
    grubPostLoadMutationHook() = std::move(hook);
}

void fireGrubPostLoadMutationHookForTests(const std::string& path) {
    std::function<void(const std::string&)> hook;
    std::swap(hook, grubPostLoadMutationHook());
    if (hook) {
        hook(path);
    }
}

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

bool GrubConfiguration::readSnapshot(std::string& error) {
    if (!options_.defaultsPath.is_absolute() ||
        options_.defaultsPath != options_.defaultsPath.lexically_normal()) {
        error = "Путь GRUB-конфигурации должен быть абсолютным и нормализованным";
        return false;
    }
    if (!checkFileSafety(error)) {
        return false;
    }
    // Single authoritative snapshot: safe open (no symlink traversal, no
    // FIFO blocking), bounded read, then an identity/metadata re-proof of
    // BOTH the open descriptor and the path before the snapshot is accepted.
    const int descriptor = ::open(
        options_.defaultsPath.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        error = "Не удалось открыть файл GRUB: " +
            options_.defaultsPath.string() + ": " + std::strerror(errno);
        return false;
    }
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode)) {
        const int savedErrno = errno;
        ::close(descriptor);
        error = "Файл GRUB не является читаемым обычным файлом: " +
            options_.defaultsPath.string();
        if (savedErrno != 0) {
            error += ": " + std::string(std::strerror(savedErrno));
        }
        return false;
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        kMaximumGrubDefaultsSize) {
        ::close(descriptor);
        error = "GRUB-конфигурация превышает допустимый размер";
        return false;
    }
    std::string content;
    char buffer[8192];
    while (true) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            const int savedErrno = errno;
            ::close(descriptor);
            error = "Не удалось прочитать файл GRUB: " +
                options_.defaultsPath.string() + ": " +
                std::strerror(savedErrno);
            return false;
        }
        content.append(buffer, static_cast<std::size_t>(count));
        if (content.size() > kMaximumGrubDefaultsSize) {
            ::close(descriptor);
            error = "GRUB-конфигурация превышает допустимый размер";
            return false;
        }
    }
    struct stat finalStatus {};
    struct stat pathStatus {};
    const bool finalStatOk = ::fstat(descriptor, &finalStatus) == 0;
    const bool pathStatOk = ::lstat(options_.defaultsPath.c_str(), &pathStatus) == 0;
    if (!finalStatOk || !pathStatOk ||
        finalStatus.st_dev != status.st_dev ||
        finalStatus.st_ino != status.st_ino ||
        finalStatus.st_size != static_cast<off_t>(content.size()) ||
        pathStatus.st_dev != status.st_dev ||
        pathStatus.st_ino != status.st_ino ||
        (pathStatus.st_mode & S_IFMT) != S_IFREG) {
        ::close(descriptor);
        error = "Файл GRUB изменился, пока он читался: " +
            options_.defaultsPath.string();
        return false;
    }
    if (::close(descriptor) != 0) {
        error = "Не удалось закрыть файл GRUB: " +
            options_.defaultsPath.string();
        return false;
    }
    loadedState_ = AtomicTargetState{
        {status.st_dev, status.st_ino},
        std::move(content),
        static_cast<mode_t>(status.st_mode & 07777),
        status.st_uid,
        status.st_gid};
    return true;
}

bool GrubConfiguration::load(std::string& error) {
    loaded_ = false;
    loadedState_ = AtomicTargetState{};
    if (!readSnapshot(error)) {
        loadedState_ = AtomicTargetState{};
        return false;
    }
    loaded_ = true;
    return true;
}

bool GrubConfiguration::rebuild(std::string& error) {
    // The rebuild sources the CURRENT on-disk inputs as root: they must be
    // re-proven immediately before every rebuild, never inherited from an
    // earlier validation.
    if (!validateGrubSourceFile(
            options_.defaultsPath, options_.enforceOwnership, error)) {
        error = "Входные данные пересборки GRUB не прошли проверку "
                "безопасности, пересборка не запускалась: " + error;
        return false;
    }
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
    if (!loaded_) {
        result.message = "GRUB-конфигурация не была загружена";
        return result;
    }
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
    // the file is never touched in that case. Parsing reads the SAME
    // authoritative snapshot that the CAS precondition below is built from.
    const GrubBlockParseResult parse =
        parseGrubManagedBlock(loadedState_.content);
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

    // SINGLE-SNAPSHOT transaction: the authoritative CAS precondition and the
    // compensation source are the SAME snapshot the block was parsed from
    // (captured by load()). It is never re-derived after a failure, and an
    // external writer racing after the load can only fail the CAS below.
    const AtomicTargetState& before = loadedState_;
    std::string error;

    if (alreadySet) {
        // Idempotent path: no source mutation, but the rebuild is still
        // mandatory because grub.cfg is a derived artifact.
        //
        // Re-prove FIC ownership of the shared file against the SAME snapshot
        // the block was parsed from before publishing anything derived from
        // it: if an external writer replaced the file after load(), the
        // snapshot is stale and the rebuild must not consume FIC-owned data
        // (fail closed, external bytes preserved).
        std::string proofError;
        // Deterministic test seam: simulates an external writer racing
        // between load() and this re-proof (production never sets the hook).
        fireGrubPostLoadMutationHookForTests(
            options_.defaultsPath.string());
        if (!AtomicFileWriter::targetStateMatches(
                options_.defaultsPath.string(), loadedState_, &proofError)) {
            result.message =
                "FIC managed block в " + options_.defaultsPath.string() +
                " изменился внешне после загрузки: " + proofError;
            return result;
        }
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
        setGrubManagedBlockValue(loadedState_.content, key, value);
    if (!mutation.ok) {
        result.message = mutation.error;
        return result;
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

namespace {

// Shared directory-chain proof for GRUB defaults files: every ancestor must
// exist as a real directory without symlink components, must not be
// group/world-writable (a world-writable directory is acceptable only with
// the sticky bit — shared-tmp semantics), and under enforceOwnership must be
// owned by root:root.
bool validateGrubDefaultsDirectoryChain(const std::filesystem::path& path,
                                        bool enforceOwnership,
                                        std::string& error) {
    for (std::filesystem::path current = path.parent_path(); !current.empty();
         current = current.parent_path()) {
        struct stat directoryStatus {};
        if (::lstat(current.c_str(), &directoryStatus) != 0 ||
            S_ISLNK(directoryStatus.st_mode) ||
            !S_ISDIR(directoryStatus.st_mode)) {
            error = "Каталог GRUB defaults отсутствует или небезопасен: " +
                current.string();
            return false;
        }
        const bool worldWritable = (directoryStatus.st_mode & 0002) != 0;
        if ((directoryStatus.st_mode & 0022) != 0 &&
            !(worldWritable && (directoryStatus.st_mode & S_ISVTX) != 0)) {
            error = "Каталог GRUB defaults доступен на записи группе или "
                    "всем: " + current.string();
            return false;
        }
        if (enforceOwnership &&
            (directoryStatus.st_uid != 0 || directoryStatus.st_gid != 0)) {
            error = "Небезопасные владелец или права каталога GRUB defaults: " +
                current.string();
            return false;
        }
        if (current == current.root_path()) break;
    }
    return true;
}

} // namespace

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
    return validateGrubDefaultsDirectoryChain(path, enforceOwnership, error);
}

GrubTargetProbe probeGrubTargetFile(const std::filesystem::path& path) {
    GrubTargetProbe probe;
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        if (errno == ENOENT) {
            probe.kind = GrubTargetKind::Missing;
            return probe;
        }
        probe.kind = GrubTargetKind::Error;
        probe.error = "Не удалось проверить " + path.string() + ": " +
            std::strerror(errno);
        return probe;
    }
    if (S_ISLNK(status.st_mode) || !S_ISREG(status.st_mode)) {
        probe.kind = GrubTargetKind::Unsafe;
        probe.error = path.string() +
            " занимает путь, но не является обычным несимлинковым файлом";
        return probe;
    }
    probe.kind = GrubTargetKind::Regular;
    return probe;
}

GrubManagedJournalState classifyGrubManagedJournalState(
    const GrubManagedConfigurationOptions& options,
    const std::string& key,
    const std::string& appliedValue,
    GrubValueObservation* observation) {
    const GrubValueObservation inspected =
        inspectGrubManagedValue(options, key);
    if (observation) {
        *observation = inspected;
    }
    if (!inspected.valid) {
        return GrubManagedJournalState::Invalid;
    }
    if (!inspected.found) {
        return GrubManagedJournalState::Before;
    }
    return inspected.value == appliedValue
        ? GrubManagedJournalState::After
        : GrubManagedJournalState::Drift;
}

bool validateGrubSourceFile(const std::filesystem::path& path,
                            bool enforceOwnership,
                            std::string& error) {
    if (!path.is_absolute() || path != path.lexically_normal()) {
        error = "Путь shared GRUB defaults должен быть абсолютным и "
            "нормализованным: " + path.string();
        return false;
    }
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        if (errno == ENOENT) {
            // A missing shared defaults file sources nothing unsafe.
            return true;
        }
        error = "Не удалось проверить shared GRUB defaults " +
            path.string() + ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(status.st_mode)) {
        error = "Shared GRUB defaults не должны быть symbolic link: " +
            path.string();
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        error = "Shared GRUB defaults не являются обычным файлом: " +
            path.string();
        return false;
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        kMaximumGrubDefaultsSize) {
        error = "Shared GRUB defaults превышают допустимый размер";
        return false;
    }
    if ((status.st_mode & 0022) != 0) {
        error = "Shared GRUB defaults доступны на запись группе или всем: " +
            path.string();
        return false;
    }
    if (enforceOwnership && status.st_uid != 0) {
        error = "Shared GRUB defaults должны принадлежать root: " +
            path.string();
        return false;
    }
    return validateGrubDefaultsDirectoryChain(path, enforceOwnership, error);
}

bool validateGrubDropInTopology(
    const GrubManagedConfigurationOptions& options, std::string& error) {
    if (options.managedPath.empty()) {
        error = "Managed GRUB drop-in путь не задан";
        return false;
    }
    // Delegates to GrubManagedConfig::validateTopology: safe directory chain,
    // every foreign *.cfg a regular non-symlink safe file, none sorted after
    // zzzz-fic.cfg (update-grub sources drop-ins in lexicographic order).
    // The FIC-managed zzzz-fic.cfg itself MAY be absent: a missing managed
    // artifact is a legitimate released state.
    return GrubManagedConfig::validateTopology(
        {options.managedPath, options.enforceOwnership}, error);
}

bool validateGrubRebuildInputs(const GrubManagedConfigurationOptions& options,
                               std::string& error) {
    // Topology-aware: every platform input the rebuild command reads or
    // sources is proven safe right before the rebuild. Debian/Ubuntu
    // validates the base defaults AND the whole /etc/default/grub.d/*.cfg
    // topology the rebuild sources; ALT validates the shared defaults file.
    if (!options.baseDefaultsPath.empty()) {
        if (!validateBaseGrubDefaults(
                options.baseDefaultsPath, options.enforceOwnership, error)) {
            return false;
        }
        if (!options.managedPath.empty() &&
            !validateGrubDropInTopology(options, error)) {
            return false;
        }
    }
    if (!options.sharedDefaultsPath.empty() &&
        !validateGrubSourceFile(
            options.sharedDefaultsPath, options.enforceOwnership, error)) {
        return false;
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
        // P0 invariant: rebuild inputs are re-proven immediately before EVERY
        // rebuild, never inherited from the entry validation above.
        if (!validateGrubRebuildInputs(options, rebuildError)) {
            result.message = "Входные данные пересборки GRUB не прошли "
                "проверку безопасности, пересборка не запускалась: " +
                rebuildError;
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

    // P0 invariant: rebuild inputs are re-proven immediately before EVERY
    // rebuild, including the post-write rebuild and the compensating rebuild
    // after a failed one.
    if (!validateGrubRebuildInputs(options, error)) {
        result.message = "Входные данные пересборки GRUB не прошли проверку "
            "безопасности, пересборка не запускалась: " + error;
        if (restore("Ошибка проверки входных данных пересборки GRUB") &&
            result.sourceState == GrubSourceMutationState::Compensated) {
            std::string compensationError;
            if (!validateGrubRebuildInputs(options, compensationError) ||
                !runGrubRebuild(
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

    if (!runGrubRebuild(
            options.rebuildExecutable, options.rebuildArguments,
            runner, error)) {
        result.message = "Новая GRUB-конфигурация не активирована: " + error;
        if (restore("Ошибка пересборки GRUB") &&
            result.sourceState == GrubSourceMutationState::Compensated) {
            std::string compensationError;
            if (!validateGrubRebuildInputs(options, compensationError) ||
                !runGrubRebuild(
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
