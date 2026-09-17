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
    FileStats expected;   // enforced metadata from the profile
    FileStats baseline;   // platform baseline metadata from the profile
    FileStats current;    // object state captured at collection time
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

// Safe TCB tree collection shared by the apply path (enforced metadata) and
// the platform-baseline rollback backend. Fails closed on any unknown or
// unsafe object; the returned rules pin their parent descriptors so that a
// later mutation can re-open and re-verify the exact same inode.
bool collectTcbTree(
    const fic::platform::TcbCredentialStorageConfig& config,
    std::vector<CollectedTcbRule>& rules,
    std::vector<DirectoryListingSnapshot>& directorySnapshots,
    std::string& error);

// Topology stability proof shared by the apply path and rollback: the TCB
// tree must not change between collection and the mutations based on it.
bool tcbTopologyUnchanged(
    const std::vector<DirectoryListingSnapshot>& directorySnapshots,
    const std::vector<CollectedTcbRule>& rules,
    std::string& error);

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

bool collectTcbTree(
    const fic::platform::TcbCredentialStorageConfig& config,
    std::vector<CollectedTcbRule>& rules,
    std::vector<DirectoryListingSnapshot>& directorySnapshots,
    std::string& error) {
    UniqueFd root(::open(config.rootPath.c_str(),
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (root.get() < 0) {
        error = config.rootPath.string() + ": " +
                std::string(std::strerror(errno));
        return false;
    }

    std::vector<std::string> accountNames;
    std::string scanError;
    if (!collectDirectoryNames(root.get(), accountNames, scanError)) {
        error = config.rootPath.string() + ": " + scanError;
        return false;
    }
    struct stat rootInfo {};
    if (::fstat(root.get(), &rootInfo) != 0) {
        error = config.rootPath.string() + ": " +
                std::string(std::strerror(errno));
        return false;
    }
    UniqueFd rootParent(::open(config.rootPath.parent_path().c_str(),
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                   O_CLOEXEC));
    if (rootParent.get() < 0) {
        error = config.rootPath.parent_path().string() + ": " +
                std::string(std::strerror(errno));
        return false;
    }
    FileStats rootStats = FileStats::fromBorrowedDescriptor(
        root.get(), config.rootPath.string());
    if (rootStats.has_error()) {
        error = rootStats.error_message();
        return false;
    }
    rules.push_back({config.rootPath.string(),
                     FileStats(config.rootOwner, config.rootGroup,
                               static_cast<mode_t>(config.rootPermissions)),
                     FileStats(config.rootOwner, config.rootGroup,
                               static_cast<mode_t>(
                                   config.rootBaselinePermissions)),
                     std::move(rootStats), 0,
                     duplicateDescriptor(rootParent.get()),
                     config.rootPath.filename().string(),
                     rootInfo.st_dev, rootInfo.st_ino, rootInfo.st_nlink});

    directorySnapshots.push_back({duplicateDescriptor(root.get()),
                                  config.rootPath.string(), accountNames});
    for (const std::string& account : accountNames) {
        if (!validEntryName(account) || !localAccountExists(account)) {
            error = "неизвестный объект в " + config.rootPath.string() +
                    ": " + account;
            return false;
        }
        UniqueFd accountFd(::openat(
            root.get(), account.c_str(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
        if (accountFd.get() < 0) {
            error = config.rootPath.string() + "/" + account + ": " +
                    std::string(std::strerror(errno));
            return false;
        }
        struct stat directoryInfo {};
        if (::fstat(accountFd.get(), &directoryInfo) != 0 ||
            !S_ISDIR(directoryInfo.st_mode)) {
            error = "TCB account object is not a directory: " + account;
            return false;
        }
        const std::string accountPath =
            (config.rootPath / account).string();
        FileStats accountStats = FileStats::fromBorrowedDescriptor(
            accountFd.get(), accountPath);
        if (accountStats.has_error()) {
            error = accountStats.error_message();
            return false;
        }
        rules.push_back({accountPath,
                         FileStats(account, config.entryGroup,
                                   static_cast<mode_t>(
                                       config.entryDirectoryPermissions)),
                         FileStats(account, config.entryGroup,
                                   static_cast<mode_t>(config.
                                       entryDirectoryBaselinePermissions)),
                         std::move(accountStats), 02000,
                         duplicateDescriptor(root.get()), account,
                         directoryInfo.st_dev, directoryInfo.st_ino,
                         directoryInfo.st_nlink});

        std::vector<std::string> fileNames;
        if (!collectDirectoryNames(accountFd.get(), fileNames, scanError)) {
            error = accountPath + ": " + scanError;
            return false;
        }
        directorySnapshots.push_back({duplicateDescriptor(accountFd.get()),
                                      accountPath, fileNames});
        std::set<std::string> present;
        for (const std::string& fileName : fileNames) {
            const auto expectedFile = std::find_if(
                config.files.begin(), config.files.end(),
                [&](const auto& candidate) { return candidate.name == fileName; });
            if (expectedFile == config.files.end()) {
                error = "неизвестный объект в " + accountPath + ": " +
                        fileName;
                return false;
            }
            UniqueFd fileFd(::openat(accountFd.get(), fileName.c_str(),
                                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                                         O_NONBLOCK));
            if (fileFd.get() < 0) {
                error = accountPath + "/" + fileName + ": " +
                        std::string(std::strerror(errno));
                return false;
            }
            struct stat fileInfo {};
            if (::fstat(fileFd.get(), &fileInfo) != 0 ||
                !S_ISREG(fileInfo.st_mode) || fileInfo.st_nlink != 1) {
                error = "TCB credential object must be a regular file "
                        "with one link: " + accountPath + "/" + fileName;
                return false;
            }
            FileStats fileStats = FileStats::fromBorrowedDescriptor(
                fileFd.get(), accountPath + "/" + fileName);
            if (fileStats.has_error()) {
                error = fileStats.error_message();
                return false;
            }
            rules.push_back({accountPath + "/" + fileName,
                             FileStats(account, config.entryGroup,
                                       static_cast<mode_t>(
                                           expectedFile->permissions)),
                             FileStats(account, config.entryGroup,
                                       static_cast<mode_t>(
                                           expectedFile->baselinePermissions)),
                             std::move(fileStats), 0,
                             duplicateDescriptor(accountFd.get()), fileName,
                             fileInfo.st_dev, fileInfo.st_ino,
                             fileInfo.st_nlink});
            present.insert(fileName);
        }
        for (const auto& expectedFile : config.files) {
            if (expectedFile.required &&
                present.find(expectedFile.name) == present.end()) {
                error = "обязательный TCB-файл отсутствует: " +
                        accountPath + "/" + expectedFile.name;
                return false;
            }
        }
    }
    return true;
}

bool tcbTopologyUnchanged(
    const std::vector<DirectoryListingSnapshot>& directorySnapshots,
    const std::vector<CollectedTcbRule>& rules,
    std::string& error) {
    for (const DirectoryListingSnapshot& snapshot : directorySnapshots) {
        std::vector<std::string> currentNames;
        if (!collectDirectoryNames(snapshot.descriptor.get(), currentNames,
                                   error) ||
            currentNames != snapshot.names) {
            error = "TCB topology changed during inspection: " +
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
            error = "TCB object changed during inspection: " + rule.path;
            return false;
        }
    }
    return true;
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
        this->ModeAndOwner::addExpectedRule(rule);
    }
    this->policyName = "blocking_user_access_to_system_files";
    this->policyTypeValue = std::make_unique<FileAccessRulesPolicyTypeValue>(
        platformConfig.protectedSystemFiles,
        platformConfig.tcbCredentialStorage);
}

bool DAC_blocking_user_access_to_system_files::apply(){
    // ENABLE applies the enforced hardening state only; disable-time
    // rollback transitions to the platform profile baseline (never to the
    // pre-FIC state) and is driven by the recorded journal provenance.
    return this->ModeAndOwner::applyWithBaselineJournalProvenance();
}

void DAC_blocking_user_access_to_system_files::applyAdditionalRules(
    ApplyCounters& counters) {
    if (!tcbCredentialStorage_) {
        return;
    }
    const auto& config = *tcbCredentialStorage_;

    std::vector<CollectedTcbRule> rules;
    std::vector<DirectoryListingSnapshot> directorySnapshots;
    std::string error;
    if (!collectTcbTree(config, rules, directorySnapshots, error) ||
        !tcbTopologyUnchanged(directorySnapshots, rules, error)) {
        ++counters.total;
        ++counters.failed;
        this->log("Не удалось безопасно проверить TCB: " + error,
                  logLevel::ERROR);
        return;
    }

    for (const CollectedTcbRule& rule : rules) {
        uid_t ownerId = 0;
        gid_t groupId = 0;
        const FileStatsOperationResult identityResult =
            FileStats::resolve_owner_group(
                rule.expected._owner, rule.expected._group, ownerId, groupId);
        if (!identityResult) {
            ++counters.total;
            ++counters.failed;
            this->log("Не удалось безопасно проверить TCB: " +
                          identityResult.message,
                      logLevel::ERROR);
            return;
        }
    }

    for (CollectedTcbRule& rule : rules) {
        ++counters.total;
        applyOpenedRule(rule.path, rule.expected, std::move(rule.current), false,
                        counters, rule.requiredPermissions);
    }
    if (!tcbTopologyUnchanged(directorySnapshots, rules, error)) {
        ++counters.total;
        ++counters.failed;
        this->log("Не удалось безопасно проверить TCB: " + error,
                  logLevel::ERROR);
    }
}

TcbBaselineRollbackReport rollbackTcbTreeToBaseline(
    const fic::platform::TcbCredentialStorageConfig& config) {
    TcbBaselineRollbackReport report;
    std::vector<CollectedTcbRule> rules;
    std::vector<DirectoryListingSnapshot> directorySnapshots;
    std::string error;
    // Rollback works with the actually existing TCB tree at rollback time;
    // missing accounts are never reconstructed and unknown/unsafe objects
    // fail closed the same way as during apply.
    if (!collectTcbTree(config, rules, directorySnapshots, error) ||
        !tcbTopologyUnchanged(directorySnapshots, rules, error)) {
        report.failed = 1;
        report.firstError = error;
        return report;
    }

    for (CollectedTcbRule& rule : rules) {
        uid_t ownerId = 0;
        gid_t groupId = 0;
        const FileStatsOperationResult identityResult =
            FileStats::resolve_owner_group(
                rule.baseline._owner, rule.baseline._group, ownerId, groupId);
        if (!identityResult) {
            ++report.failed;
            if (report.firstError.empty()) {
                report.firstError = identityResult.message;
            }
            continue;
        }
        // Re-open the exact collected object through its pinned parent
        // descriptor (nofollow) and re-verify it is still the same object
        // type and inode before mutating.
        const int objectFd = ::openat(rule.parent.get(), rule.name.c_str(),
                                      O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (objectFd < 0) {
            ++report.failed;
            if (report.firstError.empty()) {
                report.firstError = rule.path + ": " +
                    std::string(std::strerror(errno));
            }
            continue;
        }
        FileStats current =
            FileStats::fromBorrowedDescriptor(objectFd, rule.path);
        if (current.has_error() ||
            S_ISDIR(current.file_type()) !=
                S_ISDIR(rule.current.file_type())) {
            ++report.failed;
            if (report.firstError.empty()) {
                report.firstError = current.has_error()
                    ? current.error_message()
                    : "TCB object type mismatch: " + rule.path;
            }
            continue;
        }

        bool compliant = true;
        if (current.owner_id() != ownerId || current.group_id() != groupId) {
            compliant = false;
            const FileStatsOperationResult change =
                current.change_owner_group(ownerId, groupId);
            if (!change) {
                ++report.failed;
                if (report.firstError.empty()) {
                    report.firstError = change.message;
                }
                continue;
            }
        }
        if ((current._permissions & 07777) !=
            (rule.baseline._permissions & 07777)) {
            compliant = false;
            const FileStatsOperationResult change =
                current.change_permissions(rule.baseline._permissions);
            if (!change) {
                ++report.failed;
                if (report.firstError.empty()) {
                    report.firstError = change.message;
                }
                continue;
            }
        }
        // Postcondition: fstat-based verification against the baseline.
        const FileStatsOperationResult refreshed = current.refresh();
        if (!refreshed ||
            current.owner_id() != ownerId ||
            current.group_id() != groupId ||
            (current._permissions & 07777) !=
                (rule.baseline._permissions & 07777)) {
            ++report.failed;
            if (report.firstError.empty()) {
                report.firstError = refreshed
                    ? "TCB baseline postcondition failed: " + rule.path
                    : refreshed.message;
            }
            continue;
        }
        if (compliant) {
            ++report.compliant;
        } else {
            ++report.applied;
        }
    }
    return report;
}
