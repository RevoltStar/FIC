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
            snapshot.state = PamConfigFileTransactionState::Captured;
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
    snapshot.device = info.st_dev;
    snapshot.inode = info.st_ino;
    snapshot.state = PamConfigFileTransactionState::Captured;
    error.clear();
    return true;
}

bool PamConfigFileTransaction::mutate(
    PamConfigFileSnapshot& snapshot,
    const Mutation& mutation,
    std::string& error)
{
    if (snapshot.state != PamConfigFileTransactionState::Captured) {
        error = "PAM config transaction is not in captured state";
        return false;
    }
    bool writerInvoked = false;
    const Writer conditionalWriter =
        [&](const std::string& target,
            const std::string& content,
            const AtomicWriteOptions& requestedOptions,
            std::string* writerError) {
            if (writerInvoked) {
                if (writerError != nullptr) {
                    *writerError =
                        "PAM config transaction writer may be called once";
                }
                return false;
            }
            writerInvoked = true;
            if (std::filesystem::path(target) != snapshot.path) {
                if (writerError != nullptr) {
                    *writerError =
                        "PAM config transaction target does not match snapshot";
                }
                return false;
            }

            AtomicWriteOptions options = requestedOptions;
            options.rejectSymlink = true;
            if (snapshot.existed) {
                options.createIfMissing = false;
                options.exclusiveCreate = false;
                options.expectedTargetIdentity = AtomicTargetIdentity{
                    snapshot.device, snapshot.inode};
                options.expectedTargetState = AtomicTargetState{
                    {snapshot.device, snapshot.inode}, snapshot.content,
                    snapshot.mode, snapshot.owner, snapshot.group};
            } else {
                options.createIfMissing = true;
                options.exclusiveCreate = true;
                options.expectedTargetIdentity.reset();
                options.expectedTargetState.reset();
            }

            std::string atomicError;
            AtomicWriteResult writeResult;
            const bool written = AtomicFileWriter::writeWithResult(
                target, content, options, &atomicError, &writeResult);

            // This second-stage observation narrows the remaining rename race
            // and prevents rollback ownership from being claimed for output
            // that an external writer replaced immediately after installation.
            struct stat current {};
            std::string observedContent;
            std::string observationError;
            const bool observed = readRegularFile(
                snapshot.path, observedContent, current, observationError);
            mode_t expectedMode = 0600;
            uid_t expectedOwner = ::geteuid();
            gid_t expectedGroup = ::getegid();
            if (snapshot.existed) {
                expectedMode = snapshot.mode;
                expectedOwner = snapshot.owner;
                expectedGroup = snapshot.group;
            }
            if (options.metadataPolicy == FileMetadataPolicy::EnforceProvided) {
                expectedMode = options.fileMode.value_or(expectedMode);
                expectedOwner = options.fileOwner.value_or(expectedOwner);
                expectedGroup = options.fileGroup.value_or(expectedGroup);
            } else if (!snapshot.existed) {
                expectedMode = options.fileMode.value_or(expectedMode);
                expectedOwner = options.fileOwner.value_or(expectedOwner);
                expectedGroup = options.fileGroup.value_or(expectedGroup);
            }
            const bool owned = observed && observedContent == content &&
                (current.st_mode & 07777) == expectedMode &&
                current.st_uid == expectedOwner &&
                current.st_gid == expectedGroup;
            if (writeResult.installed && owned) {
                snapshot.state =
                    PamConfigFileTransactionState::MutationCommitted;
                snapshot.mutatedContent = std::move(observedContent);
                snapshot.mutatedDevice = current.st_dev;
                snapshot.mutatedInode = current.st_ino;
                snapshot.mutatedMode = current.st_mode & 07777;
                snapshot.mutatedOwner = current.st_uid;
                snapshot.mutatedGroup = current.st_gid;
            }
            if (!written) {
                if (writerError != nullptr) {
                    *writerError = atomicError;
                }
                return false;
            }
            if (!owned) {
                if (writerError != nullptr) {
                    *writerError =
                        "PAM config changed before mutation ownership could "
                        "be recorded: " + observationError;
                }
                return false;
            }
            return true;
        };

    const bool result = mutation(conditionalWriter, error);
    if (result && !writerInvoked) {
        error = "PAM config mutation did not invoke transaction writer";
        return false;
    }
    return result;
}

bool PamConfigFileTransaction::rollback(
    const PamConfigFileSnapshot& snapshot,
    std::string& error)
{
    if (snapshot.state !=
        PamConfigFileTransactionState::MutationCommitted) {
        error.clear();
        return true;
    }
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
    options.expectedTargetState = AtomicTargetState{
        {current.st_dev, current.st_ino}, snapshot.mutatedContent,
        snapshot.mutatedMode, snapshot.mutatedOwner, snapshot.mutatedGroup};
    if (!AtomicFileWriter::write(
            snapshot.path.string(), snapshot.content, options, &error)) {
        return false;
    }

    struct stat restored {};
    std::string restoredContent;
    if (!readRegularFile(
            snapshot.path, restoredContent, restored, error)) {
        return false;
    }
    if (restoredContent != snapshot.content ||
        (restored.st_mode & 07777) != snapshot.mode ||
        restored.st_uid != snapshot.owner || restored.st_gid != snapshot.group) {
        error = "PAM config rollback verification failed";
        return false;
    }
    error.clear();
    return true;
}

} // namespace fic::identity::pam
