#include <fic/ipc/FicAdminSocket.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <grp.h>
#include <optional>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace fic::ipc {
namespace {
std::string octalMode(mode_t mode) {
    std::ostringstream output;
    output << '0' << std::oct << (mode & 07777);
    return output.str();
}

bool verifyPath(const std::filesystem::path& path,
                mode_t expectedType,
                mode_t expectedMode,
                uid_t expectedUid,
                std::optional<gid_t> expectedGid,
                std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        error = "lstat(" + path.string() + ") failed: " + std::strerror(errno);
        return false;
    }
    if ((info.st_mode & S_IFMT) != expectedType) {
        error = "invalid filesystem object type: " + path.string();
        return false;
    }
    if (info.st_uid != expectedUid) {
        error = "invalid owner for " + path.string();
        return false;
    }
    if (expectedGid.has_value() && info.st_gid != expectedGid.value()) {
        error = "invalid group for " + path.string();
        return false;
    }
    const mode_t actualMode = info.st_mode & 07777;
    if (actualMode != expectedMode) {
        error = "invalid permissions for " + path.string() +
            ": expected " + octalMode(expectedMode) +
            ", actual " + octalMode(actualMode);
        return false;
    }
    return true;
}

bool probeSocket(const std::string& socketPath,
                 std::optional<pid_t>& peerPid,
                 int& connectError,
                 std::string& error) {
    connectError = 0;
    int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        error = "socket() failed: " + std::string(std::strerror(errno));
        return false;
    }

    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(address.sun_path)) {
        error = "socket path is too long: " + socketPath;
        ::close(fd);
        return false;
    }
    std::strncpy(address.sun_path, socketPath.c_str(), sizeof(address.sun_path) - 1);
    const socklen_t addressLength = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + socketPath.size() + 1U);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), addressLength) != 0) {
        connectError = errno;
        if (connectError == EINPROGRESS || connectError == EAGAIN) {
            // A nonblocking Unix connect can report EAGAIN when the live
            // listener's backlog is full. It is still an active socket and
            // must never be unlinked as stale.
            ::close(fd);
            return true;
        }
        error = std::strerror(errno);
        ::close(fd);
        return false;
    }

#ifdef SO_PEERCRED
    struct ucred credentials {};
    socklen_t credentialsLength = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
                     &credentials, &credentialsLength) == 0) {
        peerPid = credentials.pid;
    }
#endif

    ::close(fd);
    return true;
}

void closeAndRemove(int fd, const std::filesystem::path& socketPath) {
    if (fd >= 0) {
        ::close(fd);
    }
    ::unlink(socketPath.c_str());
}
} // namespace

AdminSocketResult create_admin_server_socket(const AdminSocketOptions& options) {
    AdminSocketResult result;
    if (options.socketPath.empty() || !options.socketPath.is_absolute() ||
        options.socketPath.lexically_normal() != options.socketPath) {
        result.error = "administrative socket path must be absolute and normalized";
        return result;
    }
    if (options.backlog <= 0) {
        result.error = "administrative socket backlog must be positive";
        return result;
    }

    const std::filesystem::path runtimeDir = options.socketPath.parent_path();
    const bool runtimeDirExisted = std::filesystem::exists(runtimeDir);
    std::error_code filesystemError;
    if (!runtimeDirExisted) {
        std::filesystem::create_directories(runtimeDir, filesystemError);
        if (filesystemError) {
            result.error = "could not create runtime directory " + runtimeDir.string() +
                ": " + filesystemError.message();
            return result;
        }
    }

    struct stat runtimeInfo {};
    if (::lstat(runtimeDir.c_str(), &runtimeInfo) != 0 || !S_ISDIR(runtimeInfo.st_mode)) {
        result.error = "runtime parent is not a real directory: " + runtimeDir.string();
        return result;
    }

    group* ficGroup = nullptr;
    std::optional<gid_t> expectedGroup;
    mode_t socketMode = 0600;
    if (options.security == AdminSocketSecurityProfile::ProductionAdmin) {
        ficGroup = ::getgrnam("fic");
        if (ficGroup == nullptr) {
            result.error = "group 'fic' does not exist; refusing to expose production administrative socket";
            return result;
        }
        expectedGroup = ficGroup->gr_gid;
        if (::chown(runtimeDir.c_str(), 0, ficGroup->gr_gid) != 0 ||
            ::chmod(runtimeDir.c_str(), 0770) != 0) {
            result.error = "failed to enforce production runtime directory metadata: " +
                std::string(std::strerror(errno));
            return result;
        }
        if (!verifyPath(runtimeDir, S_IFDIR, 0770, 0, expectedGroup, result.error)) {
            return result;
        }
        socketMode = 0660;
    } else if (!runtimeDirExisted && ::chmod(runtimeDir.c_str(), 0700) != 0) {
        result.error = "failed to secure development runtime directory: " +
            std::string(std::strerror(errno));
        return result;
    }

    struct stat existingInfo {};
    if (::lstat(options.socketPath.c_str(), &existingInfo) == 0) {
        if (!S_ISSOCK(existingInfo.st_mode)) {
            result.error = "refusing to replace non-socket object: " + options.socketPath.string();
            return result;
        }
        if (existingInfo.st_uid != geteuid()) {
            result.error = "refusing to replace socket owned by another user: " +
                options.socketPath.string();
            return result;
        }

        int connectError = 0;
        std::string probeError;
        if (probeSocket(options.socketPath.string(), result.existingPeerPid,
                        connectError, probeError)) {
            result.error = options.label + " is already active";
            return result;
        }
        if (connectError != ECONNREFUSED && connectError != ENOENT) {
            result.error = "could not verify stale socket " + options.socketPath.string() +
                ": " + probeError;
            return result;
        }
        if (::unlink(options.socketPath.c_str()) != 0 && errno != ENOENT) {
            result.error = "could not remove stale socket " + options.socketPath.string() +
                ": " + std::strerror(errno);
            return result;
        }
    } else if (errno != ENOENT) {
        result.error = "lstat(" + options.socketPath.string() + ") failed: " +
            std::strerror(errno);
        return result;
    }

    int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        result.error = "socket() failed: " + std::string(std::strerror(errno));
        return result;
    }

    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    const std::string socketPath = options.socketPath.string();
    if (socketPath.size() >= sizeof(address.sun_path)) {
        result.error = "socket path is too long: " + socketPath;
        ::close(fd);
        return result;
    }
    std::strncpy(address.sun_path, socketPath.c_str(), sizeof(address.sun_path) - 1);
    const socklen_t addressLength = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + socketPath.size() + 1U);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), addressLength) != 0) {
        result.error = "bind(" + socketPath + ") failed: " + std::strerror(errno);
        ::close(fd);
        return result;
    }

    if (expectedGroup.has_value() &&
        ::chown(options.socketPath.c_str(), static_cast<uid_t>(-1), expectedGroup.value()) != 0) {
        result.error = "failed to set administrative socket group: " +
            std::string(std::strerror(errno));
        closeAndRemove(fd, options.socketPath);
        return result;
    }
    if (::chmod(options.socketPath.c_str(), socketMode) != 0) {
        result.error = "failed to set administrative socket permissions: " +
            std::string(std::strerror(errno));
        closeAndRemove(fd, options.socketPath);
        return result;
    }
    if (!verifyPath(options.socketPath, S_IFSOCK, socketMode, geteuid(),
                    expectedGroup, result.error)) {
        closeAndRemove(fd, options.socketPath);
        return result;
    }
    if (::listen(fd, options.backlog) != 0) {
        result.error = "listen(" + socketPath + ") failed: " + std::strerror(errno);
        closeAndRemove(fd, options.socketPath);
        return result;
    }

    result.fileDescriptor = fd;
    return result;
}

} // namespace fic::ipc
