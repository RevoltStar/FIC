#include <fic/core/FileStats.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

namespace {
constexpr mode_t PERMISSION_MASK = 07777;
constexpr std::size_t MAX_LOOKUP_BUFFER = 1024U * 1024U;

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
} // namespace

FileStats::FileStats(const std::string& path)
    : path_(path) {
    descriptor_ = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor_ < 0) {
        exists = false;
        if (errno == ENOENT) {
            state_ = FileStatsState::Missing;
            return;
        }
        state_ = FileStatsState::Error;
        const FileStatsOperationResult result = failureResult("open", path, errno);
        systemError_ = result.systemError;
        errorMessage_ = result.message;
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
