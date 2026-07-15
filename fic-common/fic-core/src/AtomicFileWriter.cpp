#include <fic/core/AtomicFileWriter.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
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
    if (targetExists && options.rejectSymlink && S_ISLNK(linkStat.st_mode)) {
        setError(errorMessage, "refusing to replace symbolic link: " + path);
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
    if (::rename(tempPath.c_str(), targetPath.c_str()) < 0) {
        setError(errorMessage, "could not replace " + targetPath.string() + ": " + errnoMessage());
        cleanup(tempFd, tempPath);
        return false;
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
