#include <fic/core/fs/SecureStateFile.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <optional>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::core {
namespace {

std::string errnoMessage() {
    return std::strerror(errno);
}

} // namespace
bool proveSafeParentDirectory(
    const std::filesystem::path& parent,
    const SecureStateFileExpectation& expectation,
    std::string& detail) {
    if (parent.empty()) {
        detail = "parent path is empty";
        return false;
    }
    // O_NOFOLLOW on the parent itself: a symlinked state directory would
    // redirect the whole state directory. O_DIRECTORY rejects non-directories
    // without a separate stat and without a second pathname resolution.
    const int directory = ::open(
        parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        detail = "unsafe parent directory " + parent.string() + ": " +
            errnoMessage();
        return false;
    }
    struct stat info {};
    const bool inspected = ::fstat(directory, &info) == 0;
    if (!inspected) {
        detail = "could not inspect parent directory " + parent.string() +
            ": " + errnoMessage();
    } else if (expectation.parentOwner.has_value() &&
               info.st_uid != *expectation.parentOwner) {
        detail = "parent directory has unsafe ownership: " + parent.string();
    } else if (expectation.exactParentMode != 0 &&
               (info.st_mode & 07777) != expectation.exactParentMode) {
        detail = "parent directory has unsafe mode: " + parent.string();
    }
    ::close(directory);
    if (!detail.empty()) {
        return false;
    }
    detail.clear();
    return true;
}
SecureStateReadResult readSecureStateFile(
    const std::filesystem::path& path,
    const SecureStateFileExpectation& expectation) {
    SecureStateReadResult result;

    if (!proveSafeParentDirectory(
            path.parent_path(), expectation, result.detail)) {
        return result;
    }

    const std::uintmax_t acceptedSize = expectation.maxSize != 0
        ? std::min<std::uintmax_t>(
              expectation.maxSize, SECURE_STATE_READ_HARD_MAX_BYTES)
        : SECURE_STATE_READ_HARD_MAX_BYTES;

    const int descriptor =
        ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        if (errno == ENOENT) {
            // Absence proven through the very same secure open call. This is a
            // distinct, honest outcome - not a failed read.
            result.status = SecureStateReadStatus::Missing;
            result.detail.clear();
            return result;
        }
        result.detail = errno == ELOOP
            ? "state file is a symbolic link: " + path.string()
            : "could not securely open state file " + path.string() + ": " +
                errnoMessage();
        return result;
    }

    struct stat before {};
    if (::fstat(descriptor, &before) != 0) {
        result.detail = "could not inspect opened state file " + path.string() +
            ": " + errnoMessage();
        ::close(descriptor);
        return result;
    }
    if (!S_ISREG(before.st_mode)) {
        result.detail = "state file is not a regular file: " + path.string();
        ::close(descriptor);
        return result;
    }
    if (expectation.owner.has_value() && before.st_uid != *expectation.owner) {
        result.detail = "state file has unsafe ownership: " + path.string();
        ::close(descriptor);
        return result;
    }
    if (expectation.group.has_value() && before.st_gid != *expectation.group) {
        result.detail = "state file has unsafe group: " + path.string();
        ::close(descriptor);
        return result;
    }
    if (expectation.exactMode != 0 &&
        (before.st_mode & 07777) != expectation.exactMode) {
        result.detail = "state file has unexpected mode: " + path.string();
        ::close(descriptor);
        return result;
    }
    if (expectation.forbiddenMode != 0 &&
        (before.st_mode & expectation.forbiddenMode) != 0) {
        result.detail = "state file has unsafe mode bits: " + path.string();
        ::close(descriptor);
        return result;
    }
    if (expectation.requireSingleLink && before.st_nlink != 1) {
        result.detail = "state file has multiple hard links: " + path.string();
        ::close(descriptor);
        return result;
    }
    if (static_cast<std::uintmax_t>(before.st_size) > acceptedSize) {
        result.detail = "state file exceeds the accepted size: " +
            path.string();
        ::close(descriptor);
        return result;
    }

    // Bounded read through the SAME descriptor proven above.
    std::string content;
    char buffer[256];
    while (content.size() <= acceptedSize) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            result.detail = "could not completely read state file " +
                path.string() + ": " + errnoMessage();
            ::close(descriptor);
            return result;
        }
        content.append(buffer, static_cast<std::size_t>(count));
    }
    if (content.size() > acceptedSize) {
        result.detail = std::string(
            "state file grew beyond the accepted size while reading: ") +
            path.string();
        ::close(descriptor);
        return result;
    }

    // Re-fstat the SAME descriptor: identity and size must be unchanged from
    // the pre-read proof. A concurrent in-place rewrite is reported as a race
    // instead of being silently parsed.
    struct stat after {};
    if (::fstat(descriptor, &after) != 0) {
        result.detail = "could not re-inspect state file " + path.string() +
            ": " + errnoMessage();
        ::close(descriptor);
        return result;
    }
    if (after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_size != before.st_size) {
        result.detail = "state file changed during the proof: " + path.string();
        ::close(descriptor);
        return result;
    }
    ::close(descriptor);

    result.status = SecureStateReadStatus::Proven;
    result.detail.clear();
    result.content = std::move(content);
    result.targetState.identity.device = before.st_dev;
    result.targetState.identity.inode = before.st_ino;
    result.targetState.mode = before.st_mode & 07777;
    result.targetState.owner = before.st_uid;
    result.targetState.group = before.st_gid;
    result.targetState.content = result.content;
    return result;
}

} // namespace fic::core