#include <fic/core/UpgradeManager.h>

#include <fic/core/AtomicFileWriter.h>
#include <fic/version/ProductVersion.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <fcntl.h>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fic::core {
namespace {
constexpr const char* JOURNAL_NAME = "upgrade.journal";
constexpr const char* LOCK_NAME = "upgrade.lock";
constexpr const char* MANIFEST_NAME = "manifest";
constexpr std::size_t MAX_CONFIG_BYTES = 1024U * 1024U;
constexpr std::array<const char*, 9> CONFIG_FILES = {
    "AUDIT.conf", "DAC.conf", "DC.conf", "GLOBAL.conf", "IDENTITY_ACCESS.conf",
    "FIREWALL.conf", "NET.conf", "OSS.conf", "SYSCTL.conf"
};

struct SemanticVersion {
    std::array<std::string, 3> core;
    std::vector<std::string> prerelease;
};

class UpgradeFileLock {
public:
    ~UpgradeFileLock() {
        if (descriptor_ >= 0) {
            ::flock(descriptor_, LOCK_UN);
            ::close(descriptor_);
        }
    }

    bool acquire(const std::filesystem::path& stateDirectory,
                 std::string& error) {
        const std::filesystem::path lockPath = stateDirectory / LOCK_NAME;
        descriptor_ = ::open(lockPath.c_str(),
                             O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                             0640);
        if (descriptor_ < 0) {
            error = "could not open upgrade lock: " +
                std::string(std::strerror(errno));
            return false;
        }
        struct stat info {};
        if (::fstat(descriptor_, &info) != 0 || !S_ISREG(info.st_mode) ||
            ::fchmod(descriptor_, 0640) != 0) {
            error = "upgrade lock is not a regular 0640 file";
            return false;
        }
        if (::flock(descriptor_, LOCK_EX) != 0) {
            error = "could not acquire upgrade lock: " +
                std::string(std::strerror(errno));
            return false;
        }
        return true;
    }

private:
    int descriptor_ = -1;
};

bool validAbsoluteNormalized(const std::filesystem::path& path) {
    return !path.empty() && path.is_absolute() && path.lexically_normal() == path;
}

bool validDatabaseBackupPath(const std::filesystem::path& stateDirectory,
                             const std::filesystem::path& backupPath,
                             std::string& error) {
    if (backupPath.empty() || !validAbsoluteNormalized(backupPath) ||
        backupPath.parent_path() != stateDirectory / "db-backups") {
        error = "database backup must be inside the product backup directory";
        return false;
    }
    return true;
}

bool ensureRealDirectory(const std::filesystem::path& path, std::string& error) {
    if (!validAbsoluteNormalized(path)) {
        error = "upgrade path must be absolute and normalized: " + path.string();
        return false;
    }
    std::error_code filesystemError;
    std::filesystem::create_directories(path, filesystemError);
    if (filesystemError) {
        error = "could not create directory " + path.string() + ": " +
            filesystemError.message();
        return false;
    }
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        error = "upgrade path is not a real directory: " + path.string();
        return false;
    }
    if (::chmod(path.c_str(), 02750) != 0) {
        error = "could not set directory permissions for " + path.string() +
            ": " + std::strerror(errno);
        return false;
    }
    return true;
}

bool readRegularFile(const std::filesystem::path& path,
                     std::string& content,
                     std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "configuration is missing or not a regular file: " + path.string();
        return false;
    }
    if (static_cast<std::uintmax_t>(info.st_size) > MAX_CONFIG_BYTES) {
        error = "configuration exceeds the 1 MiB migration limit: " + path.string();
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        error = "could not open configuration: " + path.string();
        return false;
    }
    std::ostringstream output;
    output << input.rdbuf();
    content = output.str();
    return input.good() || input.eof();
}

bool readDefaultConfig(const std::filesystem::path& path,
                       std::string& content,
                       std::string& error) {
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        error = "default configuration is missing or cannot be opened safely: " +
            path.string() + ": " + std::strerror(errno);
        return false;
    }
    struct stat info {};
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "default configuration is not a regular file: " + path.string();
        ::close(descriptor);
        return false;
    }
    if (static_cast<std::uintmax_t>(info.st_size) > MAX_CONFIG_BYTES) {
        error = "default configuration exceeds the 1 MiB limit: " + path.string();
        ::close(descriptor);
        return false;
    }

    content.clear();
    std::array<char, 8192> buffer {};
    while (true) {
        const ssize_t bytesRead = ::read(descriptor, buffer.data(), buffer.size());
        if (bytesRead > 0) {
            content.append(buffer.data(), static_cast<std::size_t>(bytesRead));
            if (content.size() > MAX_CONFIG_BYTES) {
                error = "default configuration exceeds the 1 MiB limit: " +
                    path.string();
                ::close(descriptor);
                return false;
            }
            continue;
        }
        if (bytesRead == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        error = "could not read default configuration " + path.string() + ": " +
            std::strerror(errno);
        ::close(descriptor);
        return false;
    }
    if (::close(descriptor) != 0) {
        error = "could not close default configuration " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    return true;
}

bool setManagedFileMetadata(const std::filesystem::path& directory,
                            AtomicWriteOptions& options,
                            std::string& error) {
    struct stat info {};
    if (::lstat(directory.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        error = "could not determine managed file directory metadata: " +
            directory.string();
        return false;
    }
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0640;
    options.fileOwner = ::geteuid();
    options.fileGroup = info.st_gid;
    return true;
}

bool parseSchemaVersion(const std::string& content, int& version, std::string& error) {
    constexpr const char* prefix = "_schema_version=";
    version = 0;
    std::istringstream input(content);
    std::string line;
    bool found = false;
    while (std::getline(input, line)) {
        if (line.rfind(prefix, 0) != 0) {
            continue;
        }
        if (found) {
            error = "configuration contains duplicate _schema_version";
            return false;
        }
        found = true;
        try {
            std::size_t consumed = 0;
            version = std::stoi(line.substr(std::strlen(prefix)), &consumed);
            if (consumed != line.size() - std::strlen(prefix) || version < 0) {
                error = "configuration has an invalid _schema_version";
                return false;
            }
        } catch (const std::exception&) {
            error = "configuration has an invalid _schema_version";
            return false;
        }
    }
    return true;
}

std::filesystem::path journalPath(const std::filesystem::path& stateDirectory) {
    return stateDirectory / JOURNAL_NAME;
}

bool writeState(const std::filesystem::path& stateDirectory,
                const UpgradeState& state,
                std::string& error) {
    const std::string content =
        "format=1\n"
        "target_version=" + state.targetVersion + "\n"
        "phase=" + state.phase + "\n"
        "transaction_directory=" + state.transactionDirectory.string() + "\n"
        "database_backup=" + state.databaseBackup.string() + "\n";
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    if (!setManagedFileMetadata(stateDirectory, options, error)) {
        return false;
    }
    if (!AtomicFileWriter::write(
            journalPath(stateDirectory).string(), content, options, &error)) {
        return false;
    }
    return AtomicFileWriter::write(
        (state.transactionDirectory / MANIFEST_NAME).string(),
        content, options, &error);
}

bool parseSemanticVersion(const std::string& version, SemanticVersion& parsed) {
    parsed = {};
    const std::size_t buildSeparator = version.find('+');
    const std::string withoutBuild = version.substr(0, buildSeparator);
    const std::size_t prereleaseSeparator = withoutBuild.find('-');
    const std::string core = withoutBuild.substr(0, prereleaseSeparator);
    if (core.empty() || core.front() == '.' || core.back() == '.') {
        return false;
    }
    std::istringstream coreInput(core);
    std::string identifier;
    std::size_t index = 0;
    while (std::getline(coreInput, identifier, '.')) {
        if (index >= parsed.core.size() || identifier.empty() ||
            !std::all_of(identifier.begin(), identifier.end(), [](unsigned char ch) {
                return std::isdigit(ch);
            }) || (identifier.size() > 1 && identifier.front() == '0')) {
            return false;
        }
        parsed.core[index++] = identifier;
    }
    if (index != parsed.core.size()) {
        return false;
    }

    if (prereleaseSeparator != std::string::npos) {
        const std::string prerelease = withoutBuild.substr(prereleaseSeparator + 1);
        if (prerelease.empty() || prerelease.front() == '.' ||
            prerelease.back() == '.') {
            return false;
        }
        std::istringstream prereleaseInput(prerelease);
        while (std::getline(prereleaseInput, identifier, '.')) {
            if (identifier.empty() ||
                !std::all_of(identifier.begin(), identifier.end(), [](unsigned char ch) {
                    return std::isalnum(ch) || ch == '-';
                })) {
                return false;
            }
            const bool numeric = std::all_of(
                identifier.begin(), identifier.end(), [](unsigned char ch) {
                    return std::isdigit(ch);
                });
            if (numeric && identifier.size() > 1 && identifier.front() == '0') {
                return false;
            }
            parsed.prerelease.push_back(identifier);
        }
        if (parsed.prerelease.empty()) {
            return false;
        }
    }

    if (buildSeparator != std::string::npos) {
        const std::string build = version.substr(buildSeparator + 1);
        if (build.empty() || build.front() == '.' || build.back() == '.' ||
            build.find("..") != std::string::npos ||
            !std::all_of(build.begin(), build.end(), [](unsigned char ch) {
                return std::isalnum(ch) || ch == '-' || ch == '.';
            })) {
            return false;
        }
    }
    return !version.empty();
}

int compareNumericIdentifier(const std::string& left, const std::string& right) {
    if (left.size() != right.size()) {
        return left.size() < right.size() ? -1 : 1;
    }
    if (left == right) return 0;
    return left < right ? -1 : 1;
}

int compareSemanticVersions(const SemanticVersion& left,
                            const SemanticVersion& right) {
    for (std::size_t index = 0; index < left.core.size(); ++index) {
        const int comparison = compareNumericIdentifier(
            left.core[index], right.core[index]);
        if (comparison != 0) return comparison;
    }
    if (left.prerelease.empty() != right.prerelease.empty()) {
        return left.prerelease.empty() ? 1 : -1;
    }
    for (std::size_t index = 0;
         index < std::min(left.prerelease.size(), right.prerelease.size());
         ++index) {
        const std::string& leftIdentifier = left.prerelease[index];
        const std::string& rightIdentifier = right.prerelease[index];
        const bool leftNumeric = std::all_of(
            leftIdentifier.begin(), leftIdentifier.end(), [](unsigned char ch) {
                return std::isdigit(ch);
            });
        const bool rightNumeric = std::all_of(
            rightIdentifier.begin(), rightIdentifier.end(), [](unsigned char ch) {
                return std::isdigit(ch);
            });
        if (leftNumeric != rightNumeric) return leftNumeric ? -1 : 1;
        const int comparison = leftNumeric
            ? compareNumericIdentifier(leftIdentifier, rightIdentifier)
            : (leftIdentifier == rightIdentifier ? 0 : (leftIdentifier < rightIdentifier ? -1 : 1));
        if (comparison != 0) return comparison;
    }
    if (left.prerelease.size() == right.prerelease.size()) return 0;
    return left.prerelease.size() < right.prerelease.size() ? -1 : 1;
}

bool validVersion(const std::string& version) {
    SemanticVersion parsed;
    return parseSemanticVersion(version, parsed);
}

bool copyBackup(const std::filesystem::path& source,
                const std::filesystem::path& destination,
                std::string& error) {
    if (std::filesystem::exists(destination)) {
        struct stat destinationInfo {};
        if (::lstat(destination.c_str(), &destinationInfo) != 0 ||
            !S_ISREG(destinationInfo.st_mode)) {
            error = "configuration backup is not a regular file: " +
                destination.string();
            return false;
        }
        return true;
    }
    std::string content;
    if (!readRegularFile(source, content, error)) {
        return false;
    }
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    if (!setManagedFileMetadata(destination.parent_path(), options, error)) {
        return false;
    }
    return AtomicFileWriter::write(destination.string(), content, options, &error);
}
} // namespace

bool UpgradeManager::ensureConfigs(
    const std::filesystem::path& defaultConfigDirectory,
    const std::filesystem::path& configDirectory,
    std::string& error) {
    error.clear();
    if (!validAbsoluteNormalized(defaultConfigDirectory) ||
        !validAbsoluteNormalized(configDirectory)) {
        error = "default and working config directories must be absolute and normalized";
        return false;
    }
    struct stat defaultDirectoryInfo {};
    if (::lstat(defaultConfigDirectory.c_str(), &defaultDirectoryInfo) != 0 ||
        !S_ISDIR(defaultDirectoryInfo.st_mode)) {
        error = "default config path is not a real directory: " +
            defaultConfigDirectory.string();
        return false;
    }
    if (!ensureRealDirectory(configDirectory, error)) {
        return false;
    }

    for (const char* fileName : CONFIG_FILES) {
        std::string defaultContent;
        if (!readDefaultConfig(
                defaultConfigDirectory / fileName, defaultContent, error)) {
            return false;
        }
        const std::filesystem::path workingPath = configDirectory / fileName;
        struct stat workingInfo {};
        if (::lstat(workingPath.c_str(), &workingInfo) == 0) {
            if (!S_ISREG(workingInfo.st_mode)) {
                error = "working configuration is not a regular file: " +
                    workingPath.string();
                return false;
            }
            continue;
        }
        if (errno != ENOENT) {
            error = "could not inspect working configuration " +
                workingPath.string() + ": " + std::strerror(errno);
            return false;
        }

        AtomicWriteOptions options;
        options.createIfMissing = true;
        options.rejectSymlink = true;
        options.exclusiveCreate = true;
        if (!setManagedFileMetadata(configDirectory, options, error) ||
            !AtomicFileWriter::write(
                workingPath.string(), defaultContent, options, &error)) {
            return false;
        }
    }
    return true;
}

bool UpgradeManager::readState(const std::filesystem::path& stateDirectory,
                               UpgradeState& state,
                               bool& exists,
                               std::string& error) {
    state = {};
    exists = false;
    error.clear();
    if (!validAbsoluteNormalized(stateDirectory)) {
        error = "state directory must be absolute and normalized";
        return false;
    }
    const std::filesystem::path path = journalPath(stateDirectory);
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (errno == ENOENT) {
            return true;
        }
        error = "could not inspect upgrade journal: " + std::string(std::strerror(errno));
        return false;
    }
    exists = true;
    if (!S_ISREG(info.st_mode) || info.st_size > 16384) {
        error = "upgrade journal is not a bounded regular file";
        return false;
    }
    std::ifstream input(path);
    std::string line;
    std::string format;
    bool formatSeen = false;
    bool targetSeen = false;
    bool phaseSeen = false;
    bool transactionSeen = false;
    bool databaseBackupSeen = false;
    while (std::getline(input, line)) {
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos) {
            error = "upgrade journal contains an invalid line";
            return false;
        }
        const std::string key = line.substr(0, separator);
        const std::string value = line.substr(separator + 1);
        if (key == "format" && !formatSeen) {
            format = value;
            formatSeen = true;
        } else if (key == "target_version" && !targetSeen) {
            state.targetVersion = value;
            targetSeen = true;
        } else if (key == "phase" && !phaseSeen) {
            state.phase = value;
            phaseSeen = true;
        } else if (key == "transaction_directory" && !transactionSeen) {
            state.transactionDirectory = value;
            transactionSeen = true;
        } else if (key == "database_backup" && !databaseBackupSeen) {
            state.databaseBackup = value;
            databaseBackupSeen = true;
        } else if (key == "format" || key == "target_version" ||
                   key == "phase" || key == "transaction_directory" ||
                   key == "database_backup") {
            error = "upgrade journal contains a duplicate field: " + key;
            return false;
        }
        else {
            error = "upgrade journal contains an unknown field: " + key;
            return false;
        }
    }
    if (!input.eof()) {
        error = "could not read upgrade journal";
        return false;
    }
    if (format != "1" || !validVersion(state.targetVersion) || state.phase.empty() ||
        !validAbsoluteNormalized(state.transactionDirectory) ||
        state.transactionDirectory.parent_path() != stateDirectory / "upgrades" ||
        !databaseBackupSeen ||
        (!state.databaseBackup.empty() &&
         (!validAbsoluteNormalized(state.databaseBackup) ||
          state.databaseBackup.parent_path() != stateDirectory / "db-backups"))) {
        error = "upgrade journal is incomplete or invalid";
        return false;
    }
    return true;
}

bool UpgradeManager::begin(const std::filesystem::path& stateDirectory,
                           const std::string& targetVersion,
                           UpgradeState& state,
                           std::string& error) {
    error.clear();
    if (!validVersion(targetVersion) || !ensureRealDirectory(stateDirectory, error) ||
        !ensureRealDirectory(stateDirectory / "upgrades", error)) {
        if (error.empty()) {
            error = "invalid target product version";
        }
        return false;
    }
    UpgradeFileLock lock;
    if (!lock.acquire(stateDirectory, error)) {
        return false;
    }
    bool exists = false;
    if (!readState(stateDirectory, state, exists, error)) {
        return false;
    }
    if (exists && state.phase != "committed") {
        if (state.targetVersion != targetVersion) {
            error = "another product upgrade is incomplete: " + state.targetVersion;
            return false;
        }
        return true;
    }
    if (exists) {
        SemanticVersion previous;
        SemanticVersion target;
        if (!parseSemanticVersion(state.targetVersion, previous) ||
            !parseSemanticVersion(targetVersion, target) ||
            compareSemanticVersions(target, previous) < 0) {
            error = "product downgrade is not supported: committed=" +
                state.targetVersion + ", requested=" + targetVersion;
            return false;
        }
    }

    state.targetVersion = targetVersion;
    state.phase = "prepared";
    state.databaseBackup.clear();
    const std::string transactionName =
        targetVersion + "-" +
        std::to_string(static_cast<long long>(std::time(nullptr))) + "-" +
        std::to_string(::getpid());
    state.transactionDirectory = stateDirectory / "upgrades" / transactionName;
    for (unsigned int suffix = 1;
         std::filesystem::exists(state.transactionDirectory);
         ++suffix) {
        state.transactionDirectory = stateDirectory / "upgrades" /
            (transactionName + "-" + std::to_string(suffix));
    }
    return ensureRealDirectory(state.transactionDirectory, error) &&
        writeState(stateDirectory, state, error);
}

bool UpgradeManager::verifyConfigs(const std::filesystem::path& configDirectory,
                                   std::string& error) {
    error.clear();
    if (!validAbsoluteNormalized(configDirectory)) {
        error = "config directory must be absolute and normalized";
        return false;
    }
    for (const char* fileName : CONFIG_FILES) {
        std::string content;
        int version = 0;
        if (!readRegularFile(configDirectory / fileName, content, error) ||
            !parseSchemaVersion(content, version, error)) {
            return false;
        }
        if (version != fic::version::CONFIG_SCHEMA_VERSION) {
            error = version > fic::version::CONFIG_SCHEMA_VERSION
                ? std::string(fileName) + " is newer than this binary"
                : std::string(fileName) + " requires offline migration";
            return false;
        }
    }
    return true;
}

bool UpgradeManager::migrateConfigs(const std::filesystem::path& configDirectory,
                                    const std::filesystem::path& stateDirectory,
                                    ConfigMigrationResult& result,
                                    std::string& error) {
    result = {};
    UpgradeFileLock lock;
    if (!lock.acquire(stateDirectory, error)) {
        return false;
    }
    UpgradeState state;
    bool exists = false;
    if (!readState(stateDirectory, state, exists, error) || !exists) {
        if (error.empty()) error = "upgrade journal does not exist; run begin-upgrade first";
        return false;
    }
    if (state.phase != "prepared" && state.phase != "config_migrated") {
        error = "config migration is not allowed in upgrade phase " + state.phase;
        return false;
    }
    result.backupDirectory = state.transactionDirectory / "config";
    if (!ensureRealDirectory(result.backupDirectory, error)) {
        return false;
    }

    for (const char* fileName : CONFIG_FILES) {
        const std::filesystem::path configFile = configDirectory / fileName;
        if (!copyBackup(configFile, result.backupDirectory / fileName, error)) {
            return false;
        }
    }
    for (const char* fileName : CONFIG_FILES) {
        const std::filesystem::path configFile = configDirectory / fileName;
        std::string content;
        int version = 0;
        if (!readRegularFile(configFile, content, error) ||
            !parseSchemaVersion(content, version, error)) {
            return false;
        }
        if (version > fic::version::CONFIG_SCHEMA_VERSION) {
            error = std::string(fileName) + " is newer than this binary; downgrade refused";
            return false;
        }
        if (version == fic::version::CONFIG_SCHEMA_VERSION) {
            continue;
        }
        if (version != 0) {
            error = "no config migration path exists for " + std::string(fileName);
            return false;
        }
        const std::string migrated =
            "_schema_version=" + std::to_string(fic::version::CONFIG_SCHEMA_VERSION) +
            "\n" + content;
        AtomicWriteOptions options;
        options.rejectSymlink = true;
        if (!AtomicFileWriter::write(configFile.string(), migrated, options, &error)) {
            return false;
        }
        ++result.migratedFiles;
    }
    if (!verifyConfigs(configDirectory, error)) {
        return false;
    }
    state.phase = "config_migrated";
    return writeState(stateDirectory, state, error);
}

bool UpgradeManager::markDatabaseMigratedIfActive(
    const std::filesystem::path& stateDirectory,
    const std::filesystem::path& databaseBackup,
    std::string& error) {
    UpgradeFileLock lock;
    if (!lock.acquire(stateDirectory, error)) {
        return false;
    }
    UpgradeState state;
    bool exists = false;
    if (!readState(stateDirectory, state, exists, error)) {
        return false;
    }
    if (!exists || state.phase == "committed") {
        return true;
    }
    if (state.phase != "config_migrated" && state.phase != "database_migrated") {
        error = "database migration is not allowed in upgrade phase " + state.phase;
        return false;
    }
    if (!databaseBackup.empty() &&
        !validDatabaseBackupPath(stateDirectory, databaseBackup, error)) {
        return false;
    }
    if (!databaseBackup.empty()) {
        if (!state.databaseBackup.empty() &&
            state.databaseBackup != databaseBackup) {
            error = "database migration backup differs from the journal";
            return false;
        }
        state.databaseBackup = databaseBackup;
    }
    state.phase = "database_migrated";
    return writeState(stateDirectory, state, error);
}

bool UpgradeManager::recordDatabaseBackupIfActive(
    const std::filesystem::path& stateDirectory,
    const std::filesystem::path& databaseBackup,
    std::string& error) {
    UpgradeFileLock lock;
    if (!lock.acquire(stateDirectory, error)) {
        return false;
    }
    UpgradeState state;
    bool exists = false;
    if (!readState(stateDirectory, state, exists, error)) {
        return false;
    }
    if (!exists || state.phase == "committed") {
        return true;
    }
    if (state.phase != "config_migrated") {
        error = "database backup is not allowed in upgrade phase " + state.phase;
        return false;
    }
    if (!validDatabaseBackupPath(stateDirectory, databaseBackup, error)) {
        return false;
    }
    struct stat info {};
    if (::lstat(databaseBackup.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "database backup is not a regular file";
        return false;
    }
    state.databaseBackup = databaseBackup;
    return writeState(stateDirectory, state, error);
}

bool UpgradeManager::commit(const std::filesystem::path& stateDirectory,
                            std::string& error) {
    UpgradeFileLock lock;
    if (!lock.acquire(stateDirectory, error)) {
        return false;
    }
    UpgradeState state;
    bool exists = false;
    if (!readState(stateDirectory, state, exists, error) || !exists) {
        if (error.empty()) error = "upgrade journal does not exist";
        return false;
    }
    if (state.phase != "database_migrated" && state.phase != "committed") {
        error = "upgrade cannot commit in phase " + state.phase;
        return false;
    }
    state.phase = "committed";
    return writeState(stateDirectory, state, error);
}

bool UpgradeManager::requireNoIncompleteUpgrade(
    const std::filesystem::path& stateDirectory,
    std::string& error) {
    UpgradeState state;
    bool exists = false;
    if (!readState(stateDirectory, state, exists, error)) {
        return false;
    }
    if (exists && state.phase != "committed") {
        error = "product upgrade is incomplete at phase " + state.phase +
            "; target=" + state.targetVersion;
        return false;
    }
    if (exists && state.targetVersion != fic::version::PRODUCT_VERSION) {
        error = "installed product version has not completed its upgrade: running=" +
            std::string(fic::version::PRODUCT_VERSION) + ", committed=" +
            state.targetVersion;
        return false;
    }
    return true;
}

} // namespace fic::core
