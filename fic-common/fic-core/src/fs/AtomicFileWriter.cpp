#include <fic/core/fs/AtomicFileWriter.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <system_error>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

void setError(std::string* target, const std::string& message) {
    if (target != nullptr) {
        *target = message;
    }
}

// Test-only seam storage (see setDirectoryFsyncHookForTests()).
std::function<bool(const std::string&)>& testDirectoryFsyncHook() {
    static std::function<bool(const std::string&)> hook;
    return hook;
}

// Test-only seam storage (see setRemovePreunlinkHookForTests()).
std::function<void(const std::string&)>& testRemovePreunlinkHook() {
    static std::function<void(const std::string&)> hook;
    return hook;
}

std::function<void(const std::string&)>& testPreInstallHook() {
    static std::function<void(const std::string&)> hook;
    return hook;
}

std::string errnoMessage() {
    return std::strerror(errno);
}

bool writeAll(int fd, const char* data, size_t size) {
    while (size > 0) {
        const ssize_t written = ::write(fd, data, size);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            errno = EIO;
            return false;
        }
        data += written;
        size -= static_cast<size_t>(written);
    }
    return true;
}

bool closeFd(int& fd) {
    if (fd < 0) {
        return true;
    }
    const int descriptor = fd;
    fd = -1;
    // On Linux close(2) releases the descriptor even when it reports EINTR.
    // Retrying could close an unrelated descriptor reused by another thread.
    return ::close(descriptor) == 0;
}

bool installTempFile(const std::filesystem::path& tempPath,
                     const std::filesystem::path& targetPath,
                     bool exclusiveCreate) {
    if (!exclusiveCreate) {
        return ::rename(tempPath.c_str(), targetPath.c_str()) == 0;
    }
#ifdef SYS_renameat2
    if (::syscall(SYS_renameat2, AT_FDCWD, tempPath.c_str(),
                  AT_FDCWD, targetPath.c_str(), RENAME_NOREPLACE) == 0) {
        return true;
    }
    if (errno != ENOSYS && errno != EINVAL) {
        return false;
    }
#endif
    if (::link(tempPath.c_str(), targetPath.c_str()) != 0) {
        return false;
    }
    if (::unlink(tempPath.c_str()) != 0) {
        return false;
    }
    return true;
}

bool matchesExpectedIdentity(const std::filesystem::path& path,
                             const AtomicWriteOptions& options) {
    if (!options.expectedTargetIdentity.has_value()) {
        return true;
    }
    struct stat current {};
    return ::lstat(path.c_str(), &current) == 0 && S_ISREG(current.st_mode) &&
        current.st_dev == options.expectedTargetIdentity->device &&
        current.st_ino == options.expectedTargetIdentity->inode;
}

bool matchesExpectedState(const std::filesystem::path& path,
                          const AtomicWriteOptions& options) {
    if (!options.expectedTargetState.has_value()) {
        return true;
    }
    const auto& expected = *options.expectedTargetState;
    int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return false;
    }
    struct stat current {};
    if (::fstat(descriptor, &current) != 0 || !S_ISREG(current.st_mode) ||
        current.st_dev != expected.identity.device ||
        current.st_ino != expected.identity.inode ||
        (current.st_mode & 07777) != expected.mode ||
        current.st_uid != expected.owner || current.st_gid != expected.group) {
        closeFd(descriptor);
        return false;
    }
    std::size_t offset = 0;
    char buffer[8192];
    while (true) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            closeFd(descriptor);
            return false;
        }
        const std::size_t size = static_cast<std::size_t>(count);
        if (offset + size > expected.content.size() ||
            expected.content.compare(offset, size, buffer, size) != 0) {
            closeFd(descriptor);
            return false;
        }
        offset += size;
    }
    const bool matches = offset == expected.content.size();
    return closeFd(descriptor) && matches;
}

bool matchesExpectedTarget(const std::filesystem::path& path,
                           const AtomicWriteOptions& options) {
    return matchesExpectedIdentity(path, options) &&
        matchesExpectedState(path, options);
}

void cleanup(int& fd, const std::filesystem::path& path) {
    closeFd(fd);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

// Durability barrier for a target directory: open the parent directory and
// fsync it (close errors after a successful fsync do not un-confirm the
// durability). Used both by the post-rename step of writeWithResult() and by
// the recovery barrier ensureTargetDurable().
bool fsyncParentDirectory(const std::filesystem::path& targetDir,
                          std::string* errorMessage) {
    int dirFd = ::open(targetDir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dirFd < 0) {
        setError(errorMessage, "could not open directory " + targetDir.string() + ": " + errnoMessage());
        return false;
    }
    if (::fsync(dirFd) < 0) {
        setError(errorMessage, "could not fsync directory " + targetDir.string() + ": " + errnoMessage());
        closeFd(dirFd);
        return false;
    }
    if (!closeFd(dirFd)) {
        // The fsync itself succeeded: durability is confirmed even when the
        // descriptor close reports an error afterwards.
        setError(errorMessage, "could not close directory " + targetDir.string() + ": " + errnoMessage());
    }
    return true;
}

void markPreconditionFailure(AtomicWriteResult* result) {
    if (result != nullptr) {
        result->preconditionFailed = true;
    }
}

} // namespace

bool AtomicFileWriter::write(const std::string& path,
                             const std::string& content,
                             const AtomicWriteOptions& options,
                             std::string* errorMessage) {
    return writeWithResult(path, content, options, errorMessage, nullptr);
}

bool AtomicFileWriter::writeWithResult(
    const std::string& path,
    const std::string& content,
    const AtomicWriteOptions& options,
    std::string* errorMessage,
    AtomicWriteResult* result) {
    if (result != nullptr) {
        *result = AtomicWriteResult{};
    }
    std::error_code error;
    const std::filesystem::path requestedPath(path);

    struct stat linkStat {};
    const bool targetExists = ::lstat(requestedPath.c_str(), &linkStat) == 0;
    if (!targetExists && errno != ENOENT) {
        setError(errorMessage, "could not stat file " + path + ": " + errnoMessage());
        return false;
    }
    if (!targetExists && !options.createIfMissing) {
        setError(errorMessage, "refusing to create missing file: " + path);
        return false;
    }
    if (targetExists && options.exclusiveCreate) {
        setError(errorMessage, "refusing to replace existing file: " + path);
        return false;
    }
    if (targetExists && options.rejectSymlink && S_ISLNK(linkStat.st_mode)) {
        setError(errorMessage, "refusing to replace symbolic link: " + path);
        return false;
    }
    if (!matchesExpectedTarget(requestedPath, options)) {
        markPreconditionFailure(result);
        setError(errorMessage,
                 "target state changed before atomic write: " + path);
        return false;
    }

    const std::filesystem::path targetPath = targetExists && !options.rejectSymlink
        ? std::filesystem::canonical(requestedPath, error)
        : std::filesystem::absolute(requestedPath, error);
    if (error) {
        setError(errorMessage, "could not resolve file path " + path + ": " + error.message());
        return false;
    }

    const std::filesystem::path targetDir = targetPath.parent_path();
    if (targetDir.empty()) {
        setError(errorMessage, "could not determine parent directory: " + path);
        return false;
    }

    struct stat targetStat {};
    const bool hasTargetStat = ::stat(targetPath.c_str(), &targetStat) == 0;
    if (!hasTargetStat && errno != ENOENT) {
        setError(errorMessage, "could not stat target " + targetPath.string() + ": " + errnoMessage());
        return false;
    }
    if (!hasTargetStat && !options.createIfMissing) {
        setError(errorMessage, "target disappeared before write: " + targetPath.string());
        return false;
    }
    if (hasTargetStat && !S_ISREG(targetStat.st_mode)) {
        setError(errorMessage, "refusing to replace non-regular file: " + targetPath.string());
        return false;
    }

    std::string tempTemplate =
        (targetDir / ("." + targetPath.filename().string() + ".tmp.XXXXXX")).string();
    int tempFd = ::mkstemp(tempTemplate.data());
    if (tempFd < 0) {
        setError(errorMessage, "could not create temporary file for " + targetPath.string() + ": " + errnoMessage());
        return false;
    }
    const std::filesystem::path tempPath(tempTemplate);

    const bool preserveExisting = hasTargetStat &&
        options.metadataPolicy == FileMetadataPolicy::PreserveExisting;
    const uid_t owner = preserveExisting
        ? targetStat.st_uid
        : options.fileOwner.value_or(hasTargetStat ? targetStat.st_uid : ::geteuid());
    const gid_t group = preserveExisting
        ? targetStat.st_gid
        : options.fileGroup.value_or(hasTargetStat ? targetStat.st_gid : ::getegid());
    const mode_t mode = preserveExisting
        ? (targetStat.st_mode & 07777)
        : options.fileMode.value_or(hasTargetStat ? (targetStat.st_mode & 07777) : 0600);

    struct stat tempStat {};
    if (::fstat(tempFd, &tempStat) < 0) {
        setError(errorMessage, "could not stat temporary file " + tempPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    if ((tempStat.st_uid != owner || tempStat.st_gid != group) &&
        ::fchown(tempFd, owner, group) < 0) {
        setError(errorMessage, "could not set owner on " + tempPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (::fchmod(tempFd, mode) < 0) {
        setError(errorMessage, "could not set metadata on " + tempPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }

    if (!writeAll(tempFd, content.data(), content.size())) {
        setError(errorMessage, "could not write " + tempPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (::fsync(tempFd) < 0) {
        setError(errorMessage, "could not fsync " + tempPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    // Capture the final temp file metadata (after fchown/fchmod) so the
    // installed state below describes exactly what rename() will publish.
    // Must happen before the descriptor is closed.
    struct stat installedStat {};
    if (::fstat(tempFd, &installedStat) < 0) {
        setError(errorMessage,
                 "could not stat prepared temporary file " + tempPath.string() +
                     ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (!closeFd(tempFd)) {
        setError(errorMessage, "could not close " + tempPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (!matchesExpectedTarget(targetPath, options)) {
        markPreconditionFailure(result);
        setError(errorMessage,
                 "target state changed before atomic replacement: " +
                     targetPath.string());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (testPreInstallHook()) {
        testPreInstallHook()(targetPath.string());
    }
    if (!matchesExpectedTarget(targetPath, options)) {
        markPreconditionFailure(result);
        setError(errorMessage,
                 "target state changed before atomic replacement: " +
                     targetPath.string());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (!installTempFile(tempPath, targetPath, options.exclusiveCreate)) {
        const int installError = errno;
        if (options.exclusiveCreate && installError == EEXIST) {
            markPreconditionFailure(result);
        }
        setError(errorMessage, "could not replace " + targetPath.string() + ": " +
            std::strerror(installError));
        cleanup(tempFd, tempPath);
        return false;
    }
    if (result != nullptr) {
        result->installed = true;
        // Built from the temp descriptor that rename() just published: never
        // from a fresh post-rename capture of the target path (an external
        // writer could replace the target in between).
        result->installedTargetState = AtomicTargetState{};
        result->installedTargetState->identity.device = installedStat.st_dev;
        result->installedTargetState->identity.inode = installedStat.st_ino;
        result->installedTargetState->mode = installedStat.st_mode & 07777;
        result->installedTargetState->owner = installedStat.st_uid;
        result->installedTargetState->group = installedStat.st_gid;
        result->installedTargetState->content = content;
    }

    // A test seam may simulate a durability failure after the rename. The
    // target is already installed here: result->installed stays true and
    // installedTargetState describes the published state (the invariant
    // "post-rename error != pre-install failure").
    if (testDirectoryFsyncHook() &&
        !testDirectoryFsyncHook()(targetPath.string())) {
        setError(errorMessage,
                 "simulated directory fsync failure after install (test seam)");
        return false;
    }

    if (!fsyncParentDirectory(targetDir, errorMessage)) {
        return false;
    }
    if (result != nullptr) {
        result->durabilityConfirmed = true;
    }
    return true;
}

bool AtomicFileWriter::ensureTargetDurable(const std::string& path,
                                           std::string* errorMessage) {
    // The test seam also replaces the barrier fsync, so recovery durability
    // failures stay deterministic in tests (same target-path argument as the
    // post-rename fsync of writeWithResult).
    if (testDirectoryFsyncHook() && !testDirectoryFsyncHook()(path)) {
        setError(errorMessage,
                 "simulated directory fsync failure (test seam): " + path);
        return false;
    }
    const std::filesystem::path requestedPath(path);
    // The target itself must stay a regular file: the barrier only confirms
    // the directory entry of an already observed regular file.
    struct stat info {};
    if (::lstat(requestedPath.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
        setError(errorMessage, "could not stat regular file " + path + ": " +
                                   errnoMessage());
        return false;
    }
    std::error_code canonicalError;
    const std::filesystem::path resolvedPath =
        std::filesystem::canonical(requestedPath, canonicalError);
    if (canonicalError) {
        setError(errorMessage,
                 "could not resolve file path " + path + ": " +
                     canonicalError.message());
        return false;
    }
    return fsyncParentDirectory(resolvedPath.parent_path(), errorMessage);
}

bool AtomicFileWriter::fsyncParentDirectoryForPath(
    const std::string& path, std::string* errorMessage) {
    if (testDirectoryFsyncHook() && !testDirectoryFsyncHook()(path)) {
        setError(errorMessage,
                 "simulated directory fsync failure (test seam): " + path);
        return false;
    }
    return fsyncParentDirectory(
        std::filesystem::path(path).parent_path(), errorMessage);
}

bool AtomicFileWriter::ensureTargetDurableIfCurrentState(
    const std::string& path,
    const AtomicTargetState& expected,
    std::string* errorMessage) {
    // Re-prove ownership before the barrier: the durability confirmation
    // applies to the exact captured state, never to whatever happens to
    // occupy the path now. An external replacement between the original
    // capture and this point must fail closed instead of being fsynced into
    // legitimacy.
    std::string matchError;
    if (!targetStateMatches(path, expected, &matchError)) {
        setError(errorMessage,
                 "state changed before durability confirmation: " + matchError);
        return false;
    }
    // The state still matches: the remaining failure mode is the directory
    // fsync itself and its error is reported as-is.
    return ensureTargetDurable(path, errorMessage);
}

bool AtomicFileWriter::targetStateMatches(const std::string& path,
                                          const AtomicTargetState& expected,
                                          std::string* errorMessage) {
    AtomicWriteOptions options;
    options.expectedTargetState = expected;
    if (!matchesExpectedTarget(std::filesystem::path(path), options)) {
        setError(errorMessage,
                 "target state does not match the expected FIC-installed "
                 "state: " +
                     path);
        return false;
    }
    return true;
}

void AtomicFileWriter::setDirectoryFsyncHookForTests(
    std::function<bool(const std::string& targetPath)> hook) {
    testDirectoryFsyncHook() = std::move(hook);
}

void AtomicFileWriter::setRemovePreunlinkHookForTests(
    std::function<void(const std::string& targetPath)> hook) {
    testRemovePreunlinkHook() = std::move(hook);
}

void AtomicFileWriter::setPreInstallHookForTests(
    std::function<void(const std::string& targetPath)> hook) {
    testPreInstallHook() = std::move(hook);
}

bool AtomicFileWriter::captureTargetState(const std::string& path,
                                          AtomicTargetState& state,
                                          std::string* errorMessage) {
    int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        setError(errorMessage, "could not open " + path + ": " + errnoMessage());
        return false;
    }
    struct stat info {};
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
        setError(errorMessage, "refusing non-regular file: " + path);
        closeFd(descriptor);
        return false;
    }
    std::string content;
    char buffer[8192];
    while (true) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            setError(errorMessage, "could not read " + path + ": " + errnoMessage());
            closeFd(descriptor);
            return false;
        }
        content.append(buffer, static_cast<std::size_t>(count));
    }
    if (!closeFd(descriptor)) {
        setError(errorMessage, "could not close " + path + ": " + errnoMessage());
        return false;
    }
    state.identity.device = info.st_dev;
    state.identity.inode = info.st_ino;
    state.mode = info.st_mode & 07777;
    state.owner = info.st_uid;
    state.group = info.st_gid;
    state.content = std::move(content);
    return true;
    state.identity.device = info.st_dev;
    state.identity.inode = info.st_ino;
    state.mode = info.st_mode & 07777;
    state.owner = info.st_uid;
    state.group = info.st_gid;
    state.content = std::move(content);
    return true;
}

bool AtomicFileWriter::removeIfCurrentState(
    const std::string& path,
    const AtomicTargetState& expected,
    std::string* errorMessage,
    AtomicRemoveResult* result) {
    if (result != nullptr) {
        *result = AtomicRemoveResult{};
    }
    const std::filesystem::path requestedPath(path);
    const std::filesystem::path parentDir = requestedPath.parent_path();
    const std::string name = requestedPath.filename().string();
    if (parentDir.empty() || name.empty() || name == "." || name == "..") {
        setError(errorMessage, "invalid removal target path: " + path);
        return false;
    }

    // Open the parent directory once: the proof AND the unlink are performed
    // relative to this directory handle, so a concurrently renamed directory
    // breaks the proof instead of silently redirecting the delete.
    int dirFd = ::open(parentDir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirFd < 0) {
        setError(errorMessage, "could not open directory " +
                                   parentDir.string() + ": " + errnoMessage());
        return false;
    }

    struct stat info {};
    if (::fstatat(dirFd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0) {
        const int statErrno = errno;
        closeFd(dirFd);
        if (statErrno == ENOENT) {
            // Nothing occupies the path: the expected state can never be
            // proven. That is a precondition mismatch (the caller captured a
            // state that is already gone), not an unexpected I/O failure.
            setError(errorMessage, "removal target does not exist: " + path);
            if (result != nullptr) {
                result->preconditionFailed = true;
            }
            return true;
        }
        setError(errorMessage, "could not stat removal target " + path +
                                   ": " + std::strerror(statErrno));
        return false;
    }
    // Symlinks and non-regular objects are never deleted through this
    // primitive, whatever their content looks like.
    if (S_ISLNK(info.st_mode) || !S_ISREG(info.st_mode)) {
        closeFd(dirFd);
        setError(errorMessage,
                 "refusing to remove a symlink or non-regular target: " + path);
        if (result != nullptr) {
            result->preconditionFailed = true;
        }
        return true;
    }
    if (info.st_dev != expected.identity.device ||
        info.st_ino != expected.identity.inode) {
        closeFd(dirFd);
        setError(errorMessage,
                 "removal target identity changed before the delete (same "
                 "content under a different inode is still a replacement): " +
                     path);
        if (result != nullptr) {
            result->preconditionFailed = true;
        }
        return true;
    }
    if ((info.st_mode & 07777) != expected.mode ||
        info.st_uid != expected.owner || info.st_gid != expected.group) {
        closeFd(dirFd);
        setError(errorMessage,
                 "removal target metadata changed before the delete: " + path);
        if (result != nullptr) {
            result->preconditionFailed = true;
        }
        return true;
    }

    // Content re-proof through the same directory handle. The fd proves the
    // object that is READ; every identity/metadata comparison below anchors
    // that fd to the expected state.
    int fileFd =
        ::openat(dirFd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fileFd < 0) {
        const int openErrno = errno;
        closeFd(dirFd);
        setError(errorMessage, "could not open removal target " + path + ": " +
                                   std::strerror(openErrno));
        return false;
    }
    struct stat openedInfo {};
    if (::fstat(fileFd, &openedInfo) != 0) {
        const int statErrno = errno;
        closeFd(fileFd);
        closeFd(dirFd);
        setError(errorMessage, "could not stat the opened removal target " +
                                   path + ": " + std::strerror(statErrno));
        return false;
    }
    if (!S_ISREG(openedInfo.st_mode) ||
        openedInfo.st_dev != expected.identity.device ||
        openedInfo.st_ino != expected.identity.inode ||
        (openedInfo.st_mode & 07777) != expected.mode ||
        openedInfo.st_uid != expected.owner ||
        openedInfo.st_gid != expected.group) {
        // The pathname was replaced between the initial proof and the open:
        // the opened object is a replacement, never deleted through this
        // primitive (Step 7F follow-up hardening).
        closeFd(fileFd);
        closeFd(dirFd);
        setError(errorMessage,
                 "removal target identity changed before the delete (the "
                 "opened object does not match the captured state; a "
                 "replacement is never deleted): " + path);
        if (result != nullptr) {
            result->preconditionFailed = true;
        }
        return true;
    }
    std::string content;
    char buffer[8192];
    bool readFailed = false;
    while (true) {
        const ssize_t count = ::read(fileFd, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            readFailed = true;
            break;
        }
        content.append(buffer, static_cast<std::size_t>(count));
    }
    if (readFailed) {
        closeFd(fileFd);
        closeFd(dirFd);
        setError(errorMessage, "could not read removal target " + path);
        return false;
    }
    if (content != expected.content) {
        closeFd(fileFd);
        closeFd(dirFd);
        setError(errorMessage,
                 "removal target content changed before the delete: " + path);
        if (result != nullptr) {
            result->preconditionFailed = true;
        }
        return true;
    }

    // Test-only seam: runs AFTER the initial proof and BEFORE the final
    // unlink proof, simulating a concurrent pathname replacement inside the
    // race window. Production code must never set the hook.
    if (testRemovePreunlinkHook()) {
        testRemovePreunlinkHook()(path);
    }

    // Final unlink proof (Step 7F follow-up hardening): re-stat the PATH and
    // compare it against the PROVEN open fd AND the captured expectation.
    // This narrows the pathname/inode race to the tiny window between this
    // fstatat and the unlinkat — a plain unlinkat cannot be made
    // inode-conditional on Linux, so a replacement landing exactly in that
    // window is a documented residual race (fail safe: the subsequent unlink
    // of a just-replaced path is only possible after the identity re-proof
    // below passed; every detected replacement is reported, never deleted).
    struct stat finalInfo {};
    if (::fstatat(dirFd, name.c_str(), &finalInfo, AT_SYMLINK_NOFOLLOW) != 0) {
        const int statErrno = errno;
        closeFd(fileFd);
        closeFd(dirFd);
        if (statErrno == ENOENT) {
            setError(errorMessage, "removal target does not exist: " + path);
        } else {
            setError(errorMessage, "could not re-stat removal target " + path +
                                       ": " + std::strerror(statErrno));
        }
        if (result != nullptr) {
            result->preconditionFailed = true;
        }
        return true;
    }
    if (S_ISLNK(finalInfo.st_mode) || !S_ISREG(finalInfo.st_mode) ||
        finalInfo.st_dev != openedInfo.st_dev ||
        finalInfo.st_ino != openedInfo.st_ino ||
        (finalInfo.st_mode & 07777) != (openedInfo.st_mode & 07777) ||
        finalInfo.st_uid != openedInfo.st_uid ||
        finalInfo.st_gid != openedInfo.st_gid) {
        // The pathname now denotes a different object (or a symlink): keep
        // both the replacement and the proven fd object untouched.
        closeFd(fileFd);
        closeFd(dirFd);
        setError(errorMessage,
                 "removal target identity changed before the delete (same "
                 "content under a different inode is still a replacement): " +
                     path);
        if (result != nullptr) {
            result->preconditionFailed = true;
        }
        return true;
    }

    // The exact captured state is proven to still occupy the path: remove
    // it relative to the same directory handle.
    if (::unlinkat(dirFd, name.c_str(), 0) != 0) {
        const int unlinkErrno = errno;
        closeFd(fileFd);
        closeFd(dirFd);
        setError(errorMessage, "could not unlink " + path + ": " +
                                   std::strerror(unlinkErrno));
        return false;
    }
    closeFd(fileFd);
    closeFd(dirFd);
    if (result != nullptr) {
        result->removed = true;
    }

    // Durability barrier for the removal. The unlink succeeded, so the
    // system state HAS changed even if this fsync fails — the caller must
    // treat removed=true as installed-but-not-durable exactly like an
    // installed-but-not-durable rename.
    std::string fsyncError;
    if (!fsyncParentDirectoryForPath(path, &fsyncError)) {
        setError(errorMessage, "directory fsync after removal failed (" +
                                   fsyncError + "); the removal is NOT "
                                   "confirmed durable");
        return false;
    }
    if (result != nullptr) {
        result->durabilityConfirmed = true;
    }
    return true;
}

bool AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
    const std::string& path, std::string* errorMessage) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) == 0) {
        setError(errorMessage, "target is still present: " + path);
        return false;
    }
    if (errno != ENOENT) {
        setError(errorMessage, "could not stat target " + path + ": " +
                                   errnoMessage());
        return false;
    }
    // The absence is observed. It proves nothing about power-loss durability
    // until the parent directory entry state is fsynced (honoring the test
    // seam, same as every other durability barrier).
    std::string fsyncError;
    if (!fsyncParentDirectoryForPath(path, &fsyncError)) {
        setError(errorMessage, "absence durability barrier failed (" +
                                   fsyncError + ")");
        return false;
    }
    // Fail closed when an object appeared while the barrier ran: the new
    // object is never touched and the caller must not resolve any state.
    if (::lstat(path.c_str(), &info) == 0) {
        setError(errorMessage,
                 "an object appeared during the absence durability barrier: " +
                     path);
        return false;
    }
    if (errno != ENOENT) {
        setError(errorMessage, "could not re-prove absence of " + path + ": " +
                                   errnoMessage());
        return false;
    }
    return true;
}
