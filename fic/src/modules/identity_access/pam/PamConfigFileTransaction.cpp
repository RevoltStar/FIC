#include "modules/identity_access/pam/PamConfigFileTransaction.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

bool readRegularFile(const std::filesystem::path& path,
                     std::string& content,
                     struct stat& info,
                     std::string& error)
{
    struct stat linkInfo {};
    if (::lstat(path.c_str(), &linkInfo) != 0) {
        error = "could not inspect PAM config " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    if (S_ISLNK(linkInfo.st_mode)) {
        error = "refusing PAM config symlink: " + path.string();
        return false;
    }
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        error = "could not open PAM config " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "refusing non-regular PAM config: " + path.string();
        ::close(descriptor);
        return false;
    }
    content.clear();
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
            error = "could not read PAM config " + path.string() + ": " +
                std::strerror(errno);
            ::close(descriptor);
            return false;
        }
        content.append(buffer, static_cast<std::size_t>(count));
    }
    if (::close(descriptor) != 0) {
        error = "could not close PAM config " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    return true;
}

bool fsyncParent(const std::filesystem::path& path, std::string& error)
{
    const int directory = ::open(
        path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) {
        error = "could not open PAM config directory: " +
            std::string(std::strerror(errno));
        return false;
    }
    const bool synced = ::fsync(directory) == 0;
    const int saved = errno;
    ::close(directory);
    if (!synced) {
        error = "could not fsync PAM config directory: " +
            std::string(std::strerror(saved));
    }
    return synced;
}

} // namespace

bool PamConfigFileTransaction::capture(
    const std::filesystem::path& path,
    PamConfigFileSnapshot& snapshot,
    std::string& error)
{
    snapshot = PamConfigFileSnapshot{};
    snapshot.path = path;
    struct stat linkInfo {};
    if (::lstat(path.c_str(), &linkInfo) != 0) {
        if (errno == ENOENT) {
            snapshot.existed = false;
            error.clear();
            return true;
        }
        error = "could not inspect PAM config " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    struct stat info {};
    if (!readRegularFile(path, snapshot.content, info, error)) {
        return false;
    }
    snapshot.existed = true;
    snapshot.mode = info.st_mode & 07777;
    snapshot.owner = info.st_uid;
    snapshot.group = info.st_gid;
    error.clear();
    return true;
}

bool PamConfigFileTransaction::recordMutation(
    PamConfigFileSnapshot& snapshot,
    std::string& error)
{
    struct stat current {};
    std::string content;
    if (!readRegularFile(snapshot.path, content, current, error)) {
        return false;
    }
    snapshot.mutationRecorded = true;
    snapshot.mutatedContent = std::move(content);
    snapshot.mutatedDevice = current.st_dev;
    snapshot.mutatedInode = current.st_ino;
    snapshot.mutatedMode = current.st_mode & 07777;
    snapshot.mutatedOwner = current.st_uid;
    snapshot.mutatedGroup = current.st_gid;
    error.clear();
    return true;
}

bool PamConfigFileTransaction::rollback(
    const PamConfigFileSnapshot& snapshot,
    std::string& error)
{
    struct stat current {};
    if (::lstat(snapshot.path.c_str(), &current) != 0) {
        if (!snapshot.existed && errno == ENOENT) {
            error.clear();
            return true;
        }
        error = "PAM config target disappeared before rollback: " +
            snapshot.path.string();
        return false;
    }
    if (S_ISLNK(current.st_mode) || !S_ISREG(current.st_mode)) {
        error = "PAM config target became unsafe before rollback: " +
            snapshot.path.string();
        return false;
    }
    if (snapshot.mutationRecorded) {
        struct stat observed {};
        std::string content;
        if (!readRegularFile(snapshot.path, content, observed, error)) {
            return false;
        }
        if (observed.st_dev != snapshot.mutatedDevice ||
            observed.st_ino != snapshot.mutatedInode ||
            content != snapshot.mutatedContent ||
            (observed.st_mode & 07777) != snapshot.mutatedMode ||
            observed.st_uid != snapshot.mutatedOwner ||
            observed.st_gid != snapshot.mutatedGroup) {
            error = "PAM config target changed after mutation: " +
                snapshot.path.string();
            return false;
        }
        current = observed;
    }

    if (!snapshot.existed) {
        if (::unlink(snapshot.path.c_str()) != 0) {
            error = "could not remove newly created PAM config during rollback: " +
                std::string(std::strerror(errno));
            return false;
        }
        if (!fsyncParent(snapshot.path, error)) {
            return false;
        }
        struct stat absent {};
        if (::lstat(snapshot.path.c_str(), &absent) == 0 || errno != ENOENT) {
            error = "new PAM config still exists after rollback";
            return false;
        }
        error.clear();
        return true;
    }

    AtomicWriteOptions options;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = snapshot.mode;
    options.fileOwner = snapshot.owner;
    options.fileGroup = snapshot.group;
    options.expectedTargetIdentity =
        AtomicTargetIdentity{current.st_dev, current.st_ino};
    if (!AtomicFileWriter::write(
            snapshot.path.string(), snapshot.content, options, &error)) {
        return false;
    }

    struct stat restored {};
    std::string content;
    if (!readRegularFile(snapshot.path, content, restored, error)) {
        return false;
    }
    if (content != snapshot.content ||
        (restored.st_mode & 07777) != snapshot.mode ||
        restored.st_uid != snapshot.owner || restored.st_gid != snapshot.group) {
        error = "PAM config rollback verification failed";
        return false;
    }
    error.clear();
    return true;
}

} // namespace fic::identity::pam
