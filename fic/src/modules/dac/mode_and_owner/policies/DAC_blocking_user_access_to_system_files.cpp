#include "modules/dac/mode_and_owner/policies/DAC_blocking_user_access_to_system_files.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) : fd_(fd) {}
    ~UniqueFd() { if (fd_ >= 0) ::close(fd_); }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) ::close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    int get() const { return fd_; }
private:
    int fd_;
};

struct CollectedTcbRule {
    std::string path;
    FileStats expected;
    FileStats current;
    mode_t requiredPermissions = 0;
    UniqueFd parent;
    std::string name;
    dev_t device = 0;
    ino_t inode = 0;
    nlink_t linkCount = 0;
};

struct DirectoryListingSnapshot {
    UniqueFd descriptor;
    std::string path;
    std::vector<std::string> names;
};

bool validEntryName(const std::string& name) {
    return !name.empty() && name != "." && name != ".." &&
        name.find('/') == std::string::npos;
}

bool localAccountExists(const std::string& name) {
    long size = ::sysconf(_SC_GETPW_R_SIZE_MAX);
    if (size < 1024) {
        size = 16384;
    }
    std::vector<char> buffer(static_cast<std::size_t>(size));
    struct passwd entry {};
    struct passwd* result = nullptr;
    return ::getpwnam_r(name.c_str(), &entry, buffer.data(), buffer.size(),
                        &result) == 0 && result != nullptr;
}

bool collectDirectoryNames(int descriptor,
                           std::vector<std::string>& names,
                           std::string& error) {
    const int duplicate = ::openat(
        descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (duplicate < 0) {
        error = "openat(.) for directory scan: " +
            std::string(std::strerror(errno));
        return false;
    }
    DIR* directory = ::fdopendir(duplicate);
    if (directory == nullptr) {
        const int savedError = errno;
        ::close(duplicate);
        error = "fdopendir: " + std::string(std::strerror(savedError));
        return false;
    }
    errno = 0;
    while (dirent* item = ::readdir(directory)) {
        const std::string name(item->d_name);
        if (name != "." && name != "..") {
            names.push_back(name);
        }
        errno = 0;
    }
    const int readError = errno;
    ::closedir(directory);
    if (readError != 0) {
        error = "readdir: " + std::string(std::strerror(readError));
        return false;
    }
    std::sort(names.begin(), names.end());
    return true;
}

UniqueFd duplicateDescriptor(int descriptor) {
    return UniqueFd(::fcntl(descriptor, F_DUPFD_CLOEXEC, 0));
}
} // namespace

DAC_blocking_user_access_to_system_files::DAC_blocking_user_access_to_system_files(
    const fic::platform::DacPlatformConfig& platformConfig)
    : ModeAndOwner(
          MissingFilePolicy::Ignore,
          PolicyPathResolution::Standard,
          ModeEnforcement::MaximumAllowed),
      tcbCredentialStorage_(platformConfig.tcbCredentialStorage)
{
    for (const fic::platform::FileAccessRule& rule :
         platformConfig.protectedSystemFiles) {
        this->ModeAndOwner::addExpectedRule(
            rule.path,
            rule.owner,
            rule.group,
            static_cast<mode_t>(rule.permissions),
            rule.allowedFinalSymlinkTargets,
            rule.providerManagedFinalSymlinkTargets);
    }
    this->policyName = "blocking_user_access_to_system_files";
    this->policyTypeValue = std::make_unique<FileAccessRulesPolicyTypeValue>(
        platformConfig.protectedSystemFiles,
        platformConfig.tcbCredentialStorage);
}

bool DAC_blocking_user_access_to_system_files::apply(){
    return this->ModeAndOwner::apply();
}

void DAC_blocking_user_access_to_system_files::applyAdditionalRules(
    ApplyCounters& counters) {
    if (!tcbCredentialStorage_) {
        return;
    }
    const auto& config = *tcbCredentialStorage_;
    const auto failCollection = [&](const std::string& message) {
        ++counters.total;
        ++counters.failed;
        this->log("Не удалось безопасно проверить TCB: " + message,
                  logLevel::ERROR);
    };

    UniqueFd root(::open(config.rootPath.c_str(),
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (root.get() < 0) {
        failCollection(config.rootPath.string() + ": " +
                       std::string(std::strerror(errno)));
        return;
    }

    std::vector<CollectedTcbRule> rules;
    std::vector<DirectoryListingSnapshot> directorySnapshots;
    struct stat rootInfo {};
    if (::fstat(root.get(), &rootInfo) != 0) {
        failCollection(config.rootPath.string() + ": " +
                       std::string(std::strerror(errno)));
        return;
    }
    UniqueFd rootParent(::open(config.rootPath.parent_path().c_str(),
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC));
    if (rootParent.get() < 0) {
        failCollection(config.rootPath.parent_path().string() + ": " +
                       std::string(std::strerror(errno)));
        return;
    }
    FileStats rootStats = FileStats::fromBorrowedDescriptor(
        root.get(), config.rootPath.string());
    if (rootStats.has_error()) {
        failCollection(rootStats.error_message());
        return;
    }
    rules.push_back({config.rootPath.string(),
                     FileStats(config.rootOwner, config.rootGroup,
                               static_cast<mode_t>(config.rootPermissions)),
                     std::move(rootStats), 0,
                     duplicateDescriptor(rootParent.get()),
                     config.rootPath.filename().string(),
                     rootInfo.st_dev, rootInfo.st_ino, rootInfo.st_nlink});

    std::vector<std::string> accountNames;
    std::string scanError;
    if (!collectDirectoryNames(root.get(), accountNames, scanError)) {
        failCollection(config.rootPath.string() + ": " + scanError);
        return;
    }
    directorySnapshots.push_back({duplicateDescriptor(root.get()),
                                  config.rootPath.string(), accountNames});
    for (const std::string& account : accountNames) {
        if (!validEntryName(account) || !localAccountExists(account)) {
            failCollection("неизвестный объект в " + config.rootPath.string() +
                           ": " + account);
            return;
        }
        UniqueFd accountFd(::openat(
            root.get(), account.c_str(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
        if (accountFd.get() < 0) {
            failCollection(config.rootPath.string() + "/" + account + ": " +
                           std::string(std::strerror(errno)));
            return;
        }
        struct stat directoryInfo {};
        if (::fstat(accountFd.get(), &directoryInfo) != 0 ||
            !S_ISDIR(directoryInfo.st_mode)) {
            failCollection("TCB account object is not a directory: " + account);
            return;
        }
        const std::string accountPath =
            (config.rootPath / account).string();
        FileStats accountStats = FileStats::fromBorrowedDescriptor(
            accountFd.get(), accountPath);
        if (accountStats.has_error()) {
            failCollection(accountStats.error_message());
            return;
        }
        rules.push_back({accountPath,
                         FileStats(account, config.entryGroup,
                                   static_cast<mode_t>(
                                       config.entryDirectoryPermissions)),
                         std::move(accountStats), 02000,
                         duplicateDescriptor(root.get()), account,
                         directoryInfo.st_dev, directoryInfo.st_ino,
                         directoryInfo.st_nlink});

        std::vector<std::string> fileNames;
        if (!collectDirectoryNames(accountFd.get(), fileNames, scanError)) {
            failCollection(accountPath + ": " + scanError);
            return;
        }
        directorySnapshots.push_back({duplicateDescriptor(accountFd.get()),
                                      accountPath, fileNames});
        std::set<std::string> present;
        for (const std::string& fileName : fileNames) {
            const auto expectedFile = std::find_if(
                config.files.begin(), config.files.end(),
                [&](const auto& candidate) { return candidate.name == fileName; });
            if (expectedFile == config.files.end()) {
                failCollection("неизвестный объект в " + accountPath + ": " +
                               fileName);
                return;
            }
            UniqueFd fileFd(::openat(accountFd.get(), fileName.c_str(),
                                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                                         O_NONBLOCK));
            if (fileFd.get() < 0) {
                failCollection(accountPath + "/" + fileName + ": " +
                               std::string(std::strerror(errno)));
                return;
            }
            struct stat fileInfo {};
            if (::fstat(fileFd.get(), &fileInfo) != 0 ||
                !S_ISREG(fileInfo.st_mode) || fileInfo.st_nlink != 1) {
                failCollection("TCB credential object must be a regular file "
                               "with one link: " + accountPath + "/" + fileName);
                return;
            }
            FileStats fileStats = FileStats::fromBorrowedDescriptor(
                fileFd.get(), accountPath + "/" + fileName);
            if (fileStats.has_error()) {
                failCollection(fileStats.error_message());
                return;
            }
            rules.push_back({accountPath + "/" + fileName,
                             FileStats(account, config.entryGroup,
                                       static_cast<mode_t>(
                                           expectedFile->permissions)),
                             std::move(fileStats), 0,
                             duplicateDescriptor(accountFd.get()), fileName,
                             fileInfo.st_dev, fileInfo.st_ino,
                             fileInfo.st_nlink});
            present.insert(fileName);
        }
        for (const auto& expectedFile : config.files) {
            if (expectedFile.required &&
                present.find(expectedFile.name) == present.end()) {
                failCollection("обязательный TCB-файл отсутствует: " +
                               accountPath + "/" + expectedFile.name);
                return;
            }
        }
    }

    const auto topologyUnchanged = [&]() {
        for (const DirectoryListingSnapshot& snapshot : directorySnapshots) {
            std::vector<std::string> currentNames;
            if (!collectDirectoryNames(snapshot.descriptor.get(), currentNames,
                                       scanError) ||
                currentNames != snapshot.names) {
                scanError = "TCB topology changed during inspection: " +
                    snapshot.path;
                return false;
            }
        }
        for (const CollectedTcbRule& rule : rules) {
            struct stat currentInfo {};
            if (rule.parent.get() < 0 ||
                ::fstatat(rule.parent.get(), rule.name.c_str(), &currentInfo,
                          AT_SYMLINK_NOFOLLOW) != 0 ||
                currentInfo.st_dev != rule.device ||
                currentInfo.st_ino != rule.inode ||
                currentInfo.st_nlink != rule.linkCount) {
                scanError = "TCB object changed during inspection: " + rule.path;
                return false;
            }
        }
        return true;
    };
    if (!topologyUnchanged()) {
        failCollection(scanError);
        return;
    }

    for (const CollectedTcbRule& rule : rules) {
        uid_t ownerId = 0;
        gid_t groupId = 0;
        const FileStatsOperationResult identityResult =
            FileStats::resolve_owner_group(
                rule.expected._owner, rule.expected._group, ownerId, groupId);
        if (!identityResult) {
            failCollection(identityResult.message);
            return;
        }
    }

    for (CollectedTcbRule& rule : rules) {
        ++counters.total;
        applyOpenedRule(rule.path, rule.expected, std::move(rule.current), false,
                        counters, rule.requiredPermissions);
    }
    if (!topologyUnchanged()) {
        failCollection(scanError);
    }
}
