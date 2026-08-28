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
    if (!closeFd(tempFd)) {
        setError(errorMessage, "could not close " + tempPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (!matchesExpectedTarget(targetPath, options)) {
        setError(errorMessage,
                 "target state changed before atomic replacement: " +
                     targetPath.string());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (!installTempFile(tempPath, targetPath, options.exclusiveCreate)) {
        setError(errorMessage, "could not replace " + targetPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
    }
    if (result != nullptr) {
        result->installed = true;
    }

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
        setError(errorMessage, "could not close directory " + targetDir.string() + ": " + errnoMessage());
        return false;
    }
    return true;
}
