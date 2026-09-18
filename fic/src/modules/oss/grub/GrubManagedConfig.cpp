#include "modules/oss/grub/GrubManagedConfig.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <system_error>

#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr const char* kManagedHeader = "# Managed by FIC. Do not edit.";
constexpr std::uintmax_t kMaximumManagedConfigSize = 1024U * 1024U;
constexpr std::array<const char*, 3> kAllowedKeys = {
    "GRUB_CMDLINE_LINUX",
    "GRUB_DISABLE_RECOVERY",
    "GRUB_TIMEOUT"
};

bool allowedKey(const std::string& key) {
    return std::find(kAllowedKeys.begin(), kAllowedKeys.end(), key) !=
        kAllowedKeys.end();
}

std::string trimCopy(std::string value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char ch) {
            return ch == ' ' || ch == '\t';
        });
    if (first == value.end()) return {};
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char ch) {
            return ch == ' ' || ch == '\t';
        }).base();
    return std::string(first, last);
}

bool decodeQuotedValue(const std::string& text,
                       std::string& value,
                       std::string& error) {
    if (text.size() < 2 || text.front() != '"' || text.back() != '"') {
        error = "managed GRUB value must be a double-quoted literal";
        return false;
    }
    value.clear();
    for (std::size_t index = 1; index + 1 < text.size(); ++index) {
        const char ch = text[index];
        if (ch == '$' || ch == '`') {
            error = "dynamic shell expressions are not allowed in managed GRUB config";
            return false;
        }
        if (ch == '"') {
            error = "unescaped quote in managed GRUB value";
            return false;
        }
        if (ch != '\\') {
            value.push_back(ch);
            continue;
        }
        if (index + 2 >= text.size()) {
            error = "incomplete escape in managed GRUB value";
            return false;
        }
        const char escaped = text[++index];
        if (escaped != '"' && escaped != '\\' &&
            escaped != '$' && escaped != '`') {
            error = "unsupported escape in managed GRUB value";
            return false;
        }
        value.push_back(escaped);
    }
    return true;
}

std::string quoteValue(const std::string& value) {
    std::string quoted = "\"";
    for (const char ch : value) {
        if (ch == '\\' || ch == '"' || ch == '$' || ch == '`') {
            quoted.push_back('\\');
        }
        quoted.push_back(ch);
    }
    quoted.push_back('"');
    return quoted;
}

bool sameState(const AtomicTargetState& left,
               const AtomicTargetState& right) {
    return left.identity.device == right.identity.device &&
        left.identity.inode == right.identity.inode &&
        left.content == right.content && left.mode == right.mode &&
        left.owner == right.owner && left.group == right.group;
}

bool sameRestoredState(const AtomicTargetState& left,
                       const AtomicTargetState& right) {
    return left.content == right.content && left.mode == right.mode &&
        left.owner == right.owner && left.group == right.group;
}

bool syncDirectory(const std::filesystem::path& directory,
                   std::string& error) {
    const int descriptor = ::open(
        directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        error = "could not open GRUB config directory " + directory.string() +
            ": " + std::strerror(errno);
        return false;
    }
    const bool synced = ::fsync(descriptor) == 0;
    const int savedErrno = errno;
    ::close(descriptor);
    if (!synced) {
        error = "could not fsync GRUB config directory " + directory.string() +
            ": " + std::strerror(savedErrno);
    }
    return synced;
}

FileHandlerOptions fileOptions(bool enforceOwnership) {
    FileHandlerOptions options;
    options.writeOptions.createIfMissing = true;
    options.writeOptions.rejectSymlink = true;
    options.writeOptions.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.writeOptions.fileMode = 0644;
    if (enforceOwnership) {
        options.writeOptions.fileOwner = 0;
        options.writeOptions.fileGroup = 0;
    }
    return options;
}

} // namespace

GrubManagedConfig::GrubManagedConfig(GrubManagedConfigOptions options)
    : ConfigFileHandler(
          options.path.string(), "=", fileOptions(options.enforceOwnership)),
      managedOptions_(std::move(options)) {}

bool GrubManagedConfig::validateTopology(
    const GrubManagedConfigOptions& options,
    std::string& error) {
    const std::filesystem::path& path = options.path;
    if (!path.is_absolute() || path != path.lexically_normal() ||
        path.filename() != "zzzz-fic.cfg") {
        error = "managed GRUB path must be an absolute normalized zzzz-fic.cfg path";
        return false;
    }
    const std::filesystem::path directory = path.parent_path();
    for (std::filesystem::path current = directory; !current.empty();
         current = current.parent_path()) {
        struct stat directoryStatus {};
        if (::lstat(current.c_str(), &directoryStatus) != 0 ||
            S_ISLNK(directoryStatus.st_mode) ||
            !S_ISDIR(directoryStatus.st_mode)) {
            error = "managed GRUB directory is missing or unsafe: " +
                current.string();
            return false;
        }
        if (options.enforceOwnership &&
            (directoryStatus.st_uid != 0 || directoryStatus.st_gid != 0 ||
             (directoryStatus.st_mode & 0022) != 0)) {
            error = "managed GRUB directory has unsafe ownership or mode: " +
                current.string();
            return false;
        }
        if (current == current.root_path()) break;
    }

    std::error_code iterationError;
    for (std::filesystem::directory_iterator iterator(directory, iterationError), end;
         !iterationError && iterator != end;
         iterator.increment(iterationError)) {
        const std::filesystem::path candidate = iterator->path();
        const std::string filename = candidate.filename().string();
        // Debian's shell glob "*.cfg" does not include dotfiles.
        if (filename.empty() || filename.front() == '.' ||
            candidate.extension() != ".cfg") {
            continue;
        }

        struct stat status {};
        if (::lstat(candidate.c_str(), &status) != 0 ||
            S_ISLNK(status.st_mode) || !S_ISREG(status.st_mode)) {
            error = "GRUB drop-in is not a safe regular file: " +
                candidate.string();
            return false;
        }
        if (options.enforceOwnership &&
            (status.st_uid != 0 || status.st_gid != 0 ||
             (status.st_mode & 0022) != 0)) {
            error = "GRUB drop-in has unsafe ownership or mode: " +
                candidate.string();
            return false;
        }
        // Rebuild runs with an empty environment, hence the distro shell glob
        // uses the default C locale and bytewise filename order.
        if (filename > path.filename().string()) {
            error = "GRUB drop-in is loaded after zzzz-fic.cfg: " +
                candidate.string();
            return false;
        }
    }
    if (iterationError) {
        error = "could not enumerate GRUB drop-ins in " + directory.string() +
            ": " + iterationError.message();
        return false;
    }
    return true;
}

bool GrubManagedConfig::readSnapshot(
    bool allowMissing,
    Snapshot& snapshot,
    std::string& error) const {
    snapshot = {};
    const std::filesystem::path& path = managedOptions_.path;
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        if (allowMissing && errno == ENOENT) return true;
        error = "could not open managed GRUB config " + path.string() +
            ": " + std::strerror(errno);
        return false;
    }

    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode)) {
        const int savedErrno = errno;
        ::close(descriptor);
        error = "managed GRUB config is not a readable regular file: " +
            path.string();
        if (savedErrno != 0) error += ": " + std::string(std::strerror(savedErrno));
        return false;
    }
    if (managedOptions_.enforceOwnership &&
        (status.st_uid != 0 || status.st_gid != 0 ||
         (status.st_mode & 0022) != 0)) {
        ::close(descriptor);
        error = "managed GRUB config has unsafe ownership or mode: " +
            path.string();
        return false;
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        kMaximumManagedConfigSize) {
        ::close(descriptor);
        error = "managed GRUB config exceeds the size limit";
        return false;
    }

    std::string content;
    char buffer[8192];
    while (true) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            const int savedErrno = errno;
            ::close(descriptor);
            error = "could not read managed GRUB config " + path.string() +
                ": " + std::strerror(savedErrno);
            return false;
        }
        content.append(buffer, static_cast<std::size_t>(count));
        if (content.size() > kMaximumManagedConfigSize) {
            ::close(descriptor);
            error = "managed GRUB config exceeds the size limit";
            return false;
        }
    }

    struct stat finalStatus {};
    struct stat pathStatus {};
    const bool finalStatOk = ::fstat(descriptor, &finalStatus) == 0;
    const int finalStatErrno = finalStatOk ? 0 : errno;
    const bool pathStatOk = ::lstat(path.c_str(), &pathStatus) == 0;
    const int pathStatErrno = pathStatOk ? 0 : errno;
    if (!finalStatOk || !pathStatOk ||
        finalStatus.st_dev != status.st_dev ||
        finalStatus.st_ino != status.st_ino ||
        finalStatus.st_size != static_cast<off_t>(content.size()) ||
        finalStatus.st_uid != status.st_uid ||
        finalStatus.st_gid != status.st_gid ||
        (finalStatus.st_mode & 07777) != (status.st_mode & 07777) ||
        pathStatus.st_dev != status.st_dev ||
        pathStatus.st_ino != status.st_ino ||
        pathStatus.st_uid != status.st_uid ||
        pathStatus.st_gid != status.st_gid ||
        (pathStatus.st_mode & 07777) != (status.st_mode & 07777)) {
        ::close(descriptor);
        error = "managed GRUB config changed while it was being read: " +
            path.string();
        const int statErrno = finalStatErrno != 0
            ? finalStatErrno
            : pathStatErrno;
        if (statErrno != 0 && statErrno != ENOENT) {
            error += ": " + std::string(std::strerror(statErrno));
        }
        return false;
    }
    if (::close(descriptor) != 0) {
        error = "could not close managed GRUB config " + path.string();
        return false;
    }
    snapshot.exists = true;
    snapshot.state = {
        {status.st_dev, status.st_ino},
        std::move(content),
        static_cast<mode_t>(status.st_mode & 07777),
        status.st_uid,
        status.st_gid
    };
    return true;
}

bool GrubManagedConfig::parse(const std::string& content,
                              std::string& error) {
    if (content.find('\0') != std::string::npos ||
        content.find('\r') != std::string::npos) {
        error = "managed GRUB config contains forbidden control characters";
        return false;
    }
    std::istringstream input(content);
    std::string line;
    std::size_t lineNumber = 0;
    bool headerSeen = false;
    while (std::getline(input, line)) {
        ++lineNumber;
        if (lineNumber == 1) {
            if (line != kManagedHeader) {
                error = "existing zzzz-fic.cfg is not owned by FIC";
                return false;
            }
            headerSeen = true;
            continue;
        }
        const std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed.front() == '#') continue;
        if (trimmed != line) {
            error = "unexpected whitespace in managed GRUB assignment at line " +
                std::to_string(lineNumber);
            return false;
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string::npos) {
            error = "malformed managed GRUB assignment at line " +
                std::to_string(lineNumber);
            return false;
        }
        const std::string key = line.substr(0, equals);
        if (!allowedKey(key)) {
            error = "unknown key in managed GRUB config: " + key;
            return false;
        }
        if (config_.find(key) != config_.end()) {
            error = "duplicate key in managed GRUB config: " + key;
            return false;
        }
        std::string value;
        if (!decodeQuotedValue(line.substr(equals + 1), value, error)) {
            error += " at line " + std::to_string(lineNumber);
            return false;
        }
        config_.emplace(key, std::move(value));
    }
    if (!headerSeen) {
        error = "existing zzzz-fic.cfg is empty and is not owned by FIC";
        return false;
    }
    return true;
}

bool GrubManagedConfig::loadConfig() {
    loaded_ = false;
    config_.clear();
    original_lines_.clear();
    installed_.reset();
    lastError_.clear();
    if (!validateTopology(managedOptions_, lastError_) ||
        !readSnapshot(true, original_, lastError_)) {
        return false;
    }
    if (original_.exists && !parse(original_.state.content, lastError_)) {
        config_.clear();
        return false;
    }
    loaded_ = true;
    canonicalize();
    return true;
}

bool GrubManagedConfig::setValue(const std::string& parameter,
                                 const std::string& value) {
    if (!loaded_ || !allowedKey(parameter)) {
        lastError_ = "unsupported managed GRUB key: " + parameter;
        return false;
    }
    if (value.find_first_of("\r\n") != std::string::npos ||
        value.find('\0') != std::string::npos) {
        lastError_ = "managed GRUB value contains CR, LF, or NUL";
        return false;
    }
    config_[parameter] = value;
    canonicalize();
    return true;
}

bool GrubManagedConfig::removeValue(const std::string& parameter) {
    if (!loaded_ || !allowedKey(parameter)) return false;
    config_.erase(parameter);
    canonicalize();
    return true;
}

void GrubManagedConfig::canonicalize() {
    original_lines_.clear();
    original_lines_.push_back(kManagedHeader);
    original_lines_.push_back("");
    for (const char* key : kAllowedKeys) {
        const auto found = config_.find(key);
        if (found != config_.end()) {
            original_lines_.push_back(
                std::string(key) + "=" + quoteValue(found->second));
        }
    }
}

std::string GrubManagedConfig::canonicalContent() const {
    std::string content;
    for (const std::string& line : original_lines_) {
        content += line;
        content.push_back('\n');
    }
    return content;
}

bool GrubManagedConfig::saveConfig(std::string& error, bool& installed) {
    installed = false;
    if (!loaded_) {
        error = "managed GRUB config was not loaded";
        return false;
    }
    if (!validateTopology(managedOptions_, error)) return false;
    AtomicWriteOptions options = options_.writeOptions;
    if (original_.exists) {
        options.expectedTargetState = original_.state;
    } else {
        options.exclusiveCreate = true;
    }
    AtomicWriteResult writeResult;
    const bool ok = AtomicFileWriter::writeWithResult(
        managedOptions_.path.string(), canonicalContent(), options,
        &error, &writeResult);
    installed = writeResult.installed;
    // Remember the exact state FIC installed (identity, content, mode,
    // owner, group) as reported by the writer itself. Compensation after a
    // failed rebuild is proven against THIS snapshot, never against a fresh
    // re-read of the file: a concurrent external writer must be detected as
    // drift, not adopted as the expected current state.
    if (writeResult.installed && writeResult.installedTargetState) {
        installed_ = *writeResult.installedTargetState;
    }
    return ok;
}

bool GrubManagedConfig::snapshotUnchanged(std::string& error) const {
    if (!validateTopology(managedOptions_, error)) return false;
    Snapshot current;
    if (!readSnapshot(true, current, error)) return false;
    if (current.exists != original_.exists ||
        (current.exists && !sameState(current.state, original_.state))) {
        error = "managed GRUB config changed after it was loaded";
        return false;
    }
    return true;
}

bool GrubManagedConfig::restoreOriginal(std::string& error,
                                        bool& concurrentDrift) const {
    concurrentDrift = false;
    if (!installed_) {
        error = "no FIC-installed managed GRUB state was recorded; "
            "compensation refused";
        return false;
    }
    // Compensation may only run while the target still IS exactly the state
    // FIC installed (identity, content, mode, owner, group — not merely the
    // original or installed inode). An externally mutated, replaced, or
    // removed file is a concurrent-drift conflict: FIC must neither restore
    // the original over it nor delete it.
    std::string matchError;
    if (!AtomicFileWriter::targetStateMatches(
            managedOptions_.path.string(), *installed_, &matchError)) {
        concurrentDrift = true;
        error = "managed GRUB config is no longer in the state installed by "
            "FIC (concurrent external modification); compensation refused: " +
            matchError;
        return false;
    }
    if (!original_.exists) {
        if (::unlink(managedOptions_.path.c_str()) != 0) {
            error = "could not remove newly created managed GRUB config: " +
                std::string(std::strerror(errno));
            return false;
        }
        return syncDirectory(managedOptions_.path.parent_path(), error);
    }
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = original_.state.mode;
    options.fileOwner = original_.state.owner;
    options.fileGroup = original_.state.group;
    options.expectedTargetState = *installed_;
    return AtomicFileWriter::write(
        managedOptions_.path.string(), original_.state.content, options, &error);
}

bool GrubManagedConfig::verifyOriginal(std::string& error) const {
    Snapshot current;
    if (!readSnapshot(true, current, error)) return false;
    if (current.exists != original_.exists) {
        error = "original managed GRUB file presence was not restored";
        return false;
    }
    if (current.exists &&
        !sameRestoredState(current.state, original_.state)) {
        error = "original managed GRUB file content or metadata was not restored";
        return false;
    }
    return true;
}

bool GrubManagedConfig::existedAtLoad() const {
    return original_.exists;
}

bool GrubManagedConfig::originalStateAtLoad(AtomicTargetState& stateOut) const {
    if (!original_.exists) {
        return false;
    }
    stateOut = original_.state;
    return true;
}

const std::optional<AtomicTargetState>& GrubManagedConfig::installedState()
    const {
    return installed_;
}

const std::string& GrubManagedConfig::lastError() const {
    return lastError_;
}
