#include <fic/core/FileStats.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#else
struct open_how {
    std::uint64_t flags;
    std::uint64_t mode;
    std::uint64_t resolve;
};
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_IN_ROOT 0x10
#endif
#include <limits.h>
#include <sstream>
#include <sys/syscall.h>
#include <utility>
#include <vector>

namespace {
constexpr mode_t PERMISSION_MASK = 07777;
constexpr std::size_t MAX_LOOKUP_BUFFER = 1024U * 1024U;
constexpr std::size_t MAX_SYMLINK_LENGTH = PATH_MAX;

FileStatsOperationResult successResult() {
    return {true, {}, {}};
}

FileStatsOperationResult failureResult(const std::string& operation,
                                       const std::string& subject,
                                       int errorNumber) {
    const std::error_code error(errorNumber, std::generic_category());
    return {
        false,
        error,
        operation + " " + subject + " failed: " + error.message() +
            " (errno=" + std::to_string(errorNumber) + ")"
    };
}

std::size_t lookupBufferSize(long configured) {
    constexpr std::size_t fallback = 16384;
    if (configured <= 0) {
        return fallback;
    }
    return std::min(static_cast<std::size_t>(configured), MAX_LOOKUP_BUFFER);
}

FileStatsOperationResult resolveUser(const std::string& name, uid_t& id) {
    std::vector<char> buffer(lookupBufferSize(::sysconf(_SC_GETPW_R_SIZE_MAX)));
    struct passwd entry {};
    struct passwd* result = nullptr;
    int lookupError = 0;
    while ((lookupError = ::getpwnam_r(
                name.c_str(), &entry, buffer.data(), buffer.size(), &result)) ==
           ERANGE && buffer.size() < MAX_LOOKUP_BUFFER) {
        buffer.resize(std::min(buffer.size() * 2, MAX_LOOKUP_BUFFER));
    }
    if (lookupError != 0) {
        return failureResult("user lookup for", name, lookupError);
    }
    if (result == nullptr) {
        return {false, {}, "expected owner does not exist: " + name};
    }
    id = result->pw_uid;
    return successResult();
}

FileStatsOperationResult resolveGroup(const std::string& name, gid_t& id) {
    std::vector<char> buffer(lookupBufferSize(::sysconf(_SC_GETGR_R_SIZE_MAX)));
    struct group entry {};
    struct group* result = nullptr;
    int lookupError = 0;
    while ((lookupError = ::getgrnam_r(
                name.c_str(), &entry, buffer.data(), buffer.size(), &result)) ==
           ERANGE && buffer.size() < MAX_LOOKUP_BUFFER) {
        buffer.resize(std::min(buffer.size() * 2, MAX_LOOKUP_BUFFER));
    }
    if (lookupError != 0) {
        return failureResult("group lookup for", name, lookupError);
    }
    if (result == nullptr) {
        return {false, {}, "expected group does not exist: " + name};
    }
    id = result->gr_gid;
    return successResult();
}

std::string ownerName(uid_t id) {
    std::vector<char> buffer(lookupBufferSize(::sysconf(_SC_GETPW_R_SIZE_MAX)));
    struct passwd entry {};
    struct passwd* result = nullptr;
    if (::getpwuid_r(id, &entry, buffer.data(), buffer.size(), &result) == 0 &&
        result != nullptr) {
        return result->pw_name;
    }
    return std::to_string(id);
}

std::string groupName(gid_t id) {
    std::vector<char> buffer(lookupBufferSize(::sysconf(_SC_GETGR_R_SIZE_MAX)));
    struct group entry {};
    struct group* result = nullptr;
    if (::getgrgid_r(id, &entry, buffer.data(), buffer.size(), &result) == 0 &&
        result != nullptr) {
        return result->gr_name;
    }
    return std::to_string(id);
}

int openAt2(int directoryDescriptor,
            const char* path,
            int flags,
            std::uint64_t resolveFlags) {
#ifdef SYS_openat2
    struct open_how how {};
    how.flags = static_cast<std::uint64_t>(flags);
    how.resolve = resolveFlags;
    return static_cast<int>(::syscall(
        SYS_openat2, directoryDescriptor, path, &how, sizeof(how)));
#else
    (void) directoryDescriptor;
    (void) path;
    (void) flags;
    (void) resolveFlags;
    errno = ENOSYS;
    return -1;
#endif
}

class ScopedDescriptor {
public:
    explicit ScopedDescriptor(int descriptor = -1) : descriptor_(descriptor) {}
    ~ScopedDescriptor() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }
    ScopedDescriptor(const ScopedDescriptor&) = delete;
    ScopedDescriptor& operator=(const ScopedDescriptor&) = delete;
    int get() const { return descriptor_; }
    int release() {
        const int result = descriptor_;
        descriptor_ = -1;
        return result;
    }

private:
    int descriptor_;
};

FileStatsOperationResult readSymlinkDescriptor(
    int descriptor,
    const std::filesystem::path& policyPath,
    std::filesystem::path& target) {
    std::vector<char> buffer(256);
    for (;;) {
        const ssize_t length = ::readlinkat(
            descriptor, "", buffer.data(), buffer.size());
        if (length < 0) {
            return failureResult(
                "readlinkat", policyPath.string(), errno);
        }
        if (static_cast<std::size_t>(length) < buffer.size()) {
            if (length == 0) {
                return {false, {},
                        "readlinkat returned an empty target for " +
                            policyPath.string()};
            }
            target = std::string(buffer.data(), static_cast<std::size_t>(length));
            return successResult();
        }
        if (buffer.size() >= MAX_SYMLINK_LENGTH) {
            return {false, {},
                    "symlink target is too long for " + policyPath.string()};
        }
        buffer.resize(std::min(buffer.size() * 2, MAX_SYMLINK_LENGTH));
    }
}
} // namespace

FileStats::FileStats(const std::string& path)
    : FileStats(path, DeferredOpenTag{}) {
    openRegularPath();
}

FileStats::FileStats(const std::string& path, DeferredOpenTag)
    : path_(path) {
}

void FileStats::openRegularPath() {
    descriptor_ = ::open(
        path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor_ < 0) {
        set_open_error("open", errno);
        return;
    }

    const FileStatsOperationResult result = update_from_descriptor();
    if (!result) {
        state_ = FileStatsState::Error;
        systemError_ = result.systemError;
        errorMessage_ = result.message;
        close_descriptor();
    }
}

void FileStats::set_open_error(const std::string& operation, int errorNumber) {
    exists = false;
    if (errorNumber == ENOENT) {
        state_ = FileStatsState::Missing;
        systemError_.clear();
        errorMessage_.clear();
        return;
    }
    state_ = FileStatsState::Error;
    const FileStatsOperationResult result =
        failureResult(operation, path_, errorNumber);
    systemError_ = result.systemError;
    errorMessage_ = result.message;
}

FileStats FileStats::openPolicyPath(
    const std::filesystem::path& path,
    const std::vector<std::filesystem::path>& allowedFinalSymlinkTargets) {
    FileStats result(path.string(), DeferredOpenTag{});
    result.openRegularPath();
    if (!result.has_error() || result.error_code().value() != ELOOP ||
        allowedFinalSymlinkTargets.empty()) {
        return result;
    }

    result.close_descriptor();
    result.systemError_.clear();
    result.errorMessage_.clear();

    if (!path.is_absolute() || path.filename().empty()) {
        result.state_ = FileStatsState::Error;
        result.errorMessage_ =
            "policy symlink path must be absolute and name an object: " +
            path.string();
        return result;
    }

    ScopedDescriptor rootDescriptor(
        ::open("/", O_PATH | O_DIRECTORY | O_CLOEXEC));
    if (rootDescriptor.get() < 0) {
        result.set_open_error("open root directory for", errno);
        return result;
    }

    const std::filesystem::path normalizedPath = path.lexically_normal();
    const std::filesystem::path parentPath = normalizedPath.parent_path();
    const std::string relativeParent = parentPath == "/"
        ? "."
        : parentPath.relative_path().string();
    ScopedDescriptor parentDescriptor(openAt2(
        rootDescriptor.get(),
        relativeParent.c_str(),
        O_PATH | O_DIRECTORY | O_CLOEXEC,
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS));
    if (parentDescriptor.get() < 0) {
        result.set_open_error(
            "openat2 policy symlink parent for", errno);
        return result;
    }

    ScopedDescriptor linkDescriptor(::openat(
        parentDescriptor.get(),
        normalizedPath.filename().c_str(),
        O_PATH | O_NOFOLLOW | O_CLOEXEC));
    if (linkDescriptor.get() < 0) {
        result.set_open_error("openat policy symlink for", errno);
        return result;
    }
    struct stat linkStat {};
    if (::fstat(linkDescriptor.get(), &linkStat) != 0) {
        result.set_open_error("fstat policy symlink for", errno);
        return result;
    }
    if (!S_ISLNK(linkStat.st_mode)) {
        result.state_ = FileStatsState::Error;
        result.errorMessage_ =
            "policy path changed while opening final symlink: " + path.string();
        return result;
    }

    std::filesystem::path rawTarget;
    const FileStatsOperationResult readResult = readSymlinkDescriptor(
        linkDescriptor.get(), normalizedPath, rawTarget);
    if (!readResult) {
        result.state_ = FileStatsState::Error;
        result.systemError_ = readResult.systemError;
        result.errorMessage_ = readResult.message;
        return result;
    }
    const std::filesystem::path normalizedTarget = rawTarget.is_absolute()
        ? rawTarget.lexically_normal()
        : (parentPath / rawTarget).lexically_normal();
    if (std::find(
            allowedFinalSymlinkTargets.begin(),
            allowedFinalSymlinkTargets.end(),
            normalizedTarget) == allowedFinalSymlinkTargets.end()) {
        result.state_ = FileStatsState::Error;
        result.errorMessage_ =
            "final symlink target is not allowed for " + path.string() +
            ": " + normalizedTarget.string();
        return result;
    }

    const std::string relativeTarget = normalizedTarget.relative_path().string();
    ScopedDescriptor targetDescriptor(openAt2(
        rootDescriptor.get(),
        relativeTarget.c_str(),
        O_RDONLY | O_CLOEXEC | O_NONBLOCK,
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS));
    if (targetDescriptor.get() < 0) {
        result.set_open_error("openat2 allowed symlink target for", errno);
        return result;
    }

    struct stat currentLinkStat {};
    if (::fstatat(parentDescriptor.get(),
                  normalizedPath.filename().c_str(),
                  &currentLinkStat,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        result.set_open_error("fstatat policy symlink verification for", errno);
        return result;
    }
    if (!S_ISLNK(currentLinkStat.st_mode) ||
        currentLinkStat.st_dev != linkStat.st_dev ||
        currentLinkStat.st_ino != linkStat.st_ino) {
        result.state_ = FileStatsState::Error;
        result.errorMessage_ =
            "policy symlink changed during validation: " + path.string();
        return result;
    }

    result.descriptor_ = targetDescriptor.release();
    const FileStatsOperationResult statResult = result.update_from_descriptor();
    if (!statResult) {
        result.state_ = FileStatsState::Error;
        result.systemError_ = statResult.systemError;
        result.errorMessage_ = statResult.message;
        result.close_descriptor();
    }
    return result;
}

FileStats FileStats::fromBorrowedDescriptor(
    int descriptor,
    const std::string& diagnosticPath) {
    FileStats result(diagnosticPath, DeferredOpenTag{});
    result.descriptor_ = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
    if (result.descriptor_ < 0) {
        result.set_open_error("fcntl(F_DUPFD_CLOEXEC) for", errno);
        return result;
    }
    const FileStatsOperationResult statResult = result.update_from_descriptor();
    if (!statResult) {
        result.state_ = FileStatsState::Error;
        result.systemError_ = statResult.systemError;
        result.errorMessage_ = statResult.message;
        result.close_descriptor();
    }
    return result;
}

FileStats::FileStats(const std::string& owner,
                     const std::string& group,
                     const mode_t& permissions)
    : _owner(owner),
      _group(group),
      _permissions(permissions & PERMISSION_MASK),
      exists(true),
      state_(FileStatsState::Available) {
}

FileStats::~FileStats() {
    close_descriptor();
}

FileStats::FileStats(FileStats&& other) noexcept {
    move_from(std::move(other));
}

FileStats& FileStats::operator=(FileStats&& other) noexcept {
    if (this != &other) {
        close_descriptor();
        move_from(std::move(other));
    }
    return *this;
}

void FileStats::close_descriptor() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
        descriptor_ = -1;
    }
}

void FileStats::move_from(FileStats&& other) noexcept {
    _owner = std::move(other._owner);
    _group = std::move(other._group);
    _permissions = other._permissions;
    exists = other.exists;
    descriptor_ = other.descriptor_;
    path_ = std::move(other.path_);
    state_ = other.state_;
    ownerId_ = other.ownerId_;
    groupId_ = other.groupId_;
    systemError_ = other.systemError_;
    errorMessage_ = std::move(other.errorMessage_);
    other.descriptor_ = -1;
    other.exists = false;
}

FileStatsOperationResult FileStats::update_from_descriptor() {
    if (descriptor_ < 0) {
        return {false, {}, "file object is not open: " + path_};
    }
    struct stat fileStat {};
    if (::fstat(descriptor_, &fileStat) != 0) {
        return failureResult("fstat", path_, errno);
    }
    ownerId_ = fileStat.st_uid;
    groupId_ = fileStat.st_gid;
    _owner = ownerName(ownerId_);
    _group = groupName(groupId_);
    _permissions = fileStat.st_mode & PERMISSION_MASK;
    exists = true;
    state_ = FileStatsState::Available;
    systemError_.clear();
    errorMessage_.clear();
    return successResult();
}

FileStatsOperationResult FileStats::refresh() {
    const FileStatsOperationResult result = update_from_descriptor();
    if (!result) {
        state_ = FileStatsState::Error;
        systemError_ = result.systemError;
        errorMessage_ = result.message;
    }
    return result;
}

FileStatsOperationResult FileStats::resolve_owner_group(
    const std::string& owner,
    const std::string& group,
    uid_t& ownerId,
    gid_t& groupId) {
    FileStatsOperationResult result = resolveUser(owner, ownerId);
    if (!result) {
        return result;
    }
    return resolveGroup(group, groupId);
}

FileStatsOperationResult FileStats::change_owner_group(
    const std::string& owner,
    const std::string& group) {
    uid_t ownerId = 0;
    gid_t groupId = 0;
    FileStatsOperationResult result =
        resolve_owner_group(owner, group, ownerId, groupId);
    if (!result) {
        return result;
    }
    return change_owner_group(ownerId, groupId);
}

FileStatsOperationResult FileStats::change_owner_group(uid_t ownerId,
                                                       gid_t groupId) {
    if (descriptor_ < 0) {
        return {false, {}, "file object is not open: " + path_};
    }
    if (::fchown(descriptor_, ownerId, groupId) != 0) {
        return failureResult("fchown", path_, errno);
    }
    return successResult();
}

FileStatsOperationResult FileStats::change_permissions(mode_t permissions) {
    if (descriptor_ < 0) {
        return {false, {}, "file object is not open: " + path_};
    }
    if (::fchmod(descriptor_, permissions & PERMISSION_MASK) != 0) {
        return failureResult("fchmod", path_, errno);
    }
    return successResult();
}

bool FileStats::group_exists(const std::string& group) {
    gid_t id = 0;
    return static_cast<bool>(resolveGroup(group, id));
}

bool FileStats::check_owner_group(const FileStats& fs) const {
    return _owner == fs._owner && _group == fs._group;
}

bool FileStats::check_permission(const FileStats& fs) const {
    return _permissions == fs._permissions;
}

std::string FileStats::permToString() const {
    std::ostringstream output;
    output << std::setfill('0') << std::setw(4) << std::oct
           << static_cast<unsigned int>(_permissions);
    return output.str();
}
