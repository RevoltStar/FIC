#include "daemon/DaemonInstanceLock.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::daemon {
namespace {
class Descriptor {
public:
    explicit Descriptor(int fd = -1) : fd_(fd) {}
    ~Descriptor() { if (fd_ >= 0) ::close(fd_); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int get() const { return fd_; }
    int release() { const int fd = fd_; fd_ = -1; return fd; }
    void reset(int fd) { if (fd_ >= 0) ::close(fd_); fd_ = fd; }
private:
    int fd_;
};
bool trustedDirectory(int fd) {
    struct stat st{};
    return ::fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == 0 && (st.st_mode & 0022) == 0;
}
bool trustedFile(const struct stat& st) {
    return S_ISREG(st.st_mode) && st.st_uid == 0 &&
           (st.st_mode & 07777) == 0600 && st.st_nlink == 1;
}
bool fail(std::string& error, const std::string& reason) {
    error = "daemon singleton lock: " + reason;
    return false;
}
} // namespace

DaemonInstanceLock::~DaemonInstanceLock() {
    // close, rather than LOCK_UN, also avoids unlocking the parent's shared
    // open-file description if an inherited object is destroyed after fork.
    if (descriptor_ >= 0) ::close(descriptor_);
}

bool DaemonInstanceLock::tryAcquire(const std::filesystem::path& directory,
                                    std::string& error) {
    error.clear();
    if (descriptor_ >= 0) return fail(error, "already acquired by this object");
    if (::geteuid() != 0) return fail(error, "root is required");
    if (!directory.is_absolute() || directory == directory.root_path() ||
        directory.lexically_normal() != directory)
        return fail(error, "runtime directory must be normalized and absolute");
    for (const auto& component : directory)
        if (component == "..") return fail(error, "parent traversal refused");

    Descriptor parent(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (!trustedDirectory(parent.get())) return fail(error, "untrusted root directory");
    const auto relative = directory.relative_path();
    for (auto it = relative.begin(); it != relative.end(); ++it) {
        const bool last = std::next(it) == relative.end();
        int next = ::openat(parent.get(), it->c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT && last) {
            if (::mkdirat(parent.get(), it->c_str(), 0755) != 0 && errno != EEXIST)
                return fail(error, "cannot create runtime directory: " + std::string(std::strerror(errno)));
            next = ::openat(parent.get(), it->c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        Descriptor child(next);
        if (!trustedDirectory(child.get()))
            return fail(error, "runtime path is not a root-controlled real directory");
        parent.reset(child.release());
    }

    constexpr const char* name = "daemon.lock";
    int fd = ::openat(parent.get(), name,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0 && errno == EEXIST)
        fd = ::openat(parent.get(), name, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    Descriptor file(fd);
    struct stat before{};
    if (fd < 0 || ::fstat(fd, &before) != 0 || !trustedFile(before))
        return fail(error, "lockfile must be a root-owned single-link regular file with mode 0600");
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0)
        return fail(error, errno == EWOULDBLOCK || errno == EAGAIN
            ? "another daemon instance holds the lock"
            : "flock failed: " + std::string(std::strerror(errno)));
    struct stat pinned{}, named{};
    if (::fstat(fd, &pinned) != 0 || !trustedFile(pinned) ||
        ::fstatat(parent.get(), name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !trustedFile(named) || pinned.st_dev != named.st_dev || pinned.st_ino != named.st_ino ||
        pinned.st_dev != before.st_dev || pinned.st_ino != before.st_ino)
        return fail(error, "lockfile identity changed during acquisition");
    descriptor_ = file.release();
    return true;
}
} // namespace fic::daemon
