#ifndef FILESTATS_H
#define FILESTATS_H

#include <grp.h>
#include <filesystem>
#include <pwd.h>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

enum class FileStatsState {
    Available,
    Missing,
    Error
};

struct FileStatsOperationResult {
    bool success = false;
    std::error_code systemError;
    std::string message;

    explicit operator bool() const { return success; }
};

class FileStats
{
public:
    std::string _owner;
    std::string _group;
    mode_t _permissions = 0;
    bool exists = false;

    explicit FileStats(const std::string& path);
    FileStats(const std::string& owner,
              const std::string& group,
              const mode_t& permissions);
    ~FileStats();

    FileStats(const FileStats&) = delete;
    FileStats& operator=(const FileStats&) = delete;
    FileStats(FileStats&& other) noexcept;
    FileStats& operator=(FileStats&& other) noexcept;

    static FileStats openPolicyPath(
        const std::filesystem::path& path,
        const std::vector<std::filesystem::path>& allowedFinalSymlinkTargets);
    // The returned object owns a close-on-exec duplicate. The caller retains
    // ownership of descriptor and both descriptors refer to the same inode.
    static FileStats fromBorrowedDescriptor(
        int descriptor,
        const std::string& diagnosticPath);

    FileStatsOperationResult change_owner_group(
        const std::string& owner,
        const std::string& group);
    FileStatsOperationResult change_owner_group(uid_t ownerId, gid_t groupId);
    FileStatsOperationResult change_permissions(mode_t permissions);
    FileStatsOperationResult refresh();

    static FileStatsOperationResult resolve_owner_group(
        const std::string& owner,
        const std::string& group,
        uid_t& ownerId,
        gid_t& groupId);
    static bool group_exists(const std::string& group);

    bool check_owner_group(const FileStats& fs) const;
    bool check_permission(const FileStats& fs) const;
    std::string permToString() const;

    FileStatsState state() const { return state_; }
    bool is_missing() const { return state_ == FileStatsState::Missing; }
    bool has_error() const { return state_ == FileStatsState::Error; }
    const std::string& error_message() const { return errorMessage_; }
    const std::error_code& error_code() const { return systemError_; }
    uid_t owner_id() const { return ownerId_; }
    gid_t group_id() const { return groupId_; }

private:
    struct DeferredOpenTag {};

    FileStats(const std::string& path, DeferredOpenTag);

    int descriptor_ = -1;
    std::string path_;
    FileStatsState state_ = FileStatsState::Available;
    uid_t ownerId_ = 0;
    gid_t groupId_ = 0;
    std::error_code systemError_;
    std::string errorMessage_;

    void close_descriptor();
    void move_from(FileStats&& other) noexcept;
    void openRegularPath();
    void set_open_error(const std::string& operation, int errorNumber);
    FileStatsOperationResult update_from_descriptor();
};

#endif // FILESTATS_H
