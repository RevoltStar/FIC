#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"

#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/ExclusivePidLock.h>
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/runtime/FicRuntimePaths.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iterator>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

struct SettingDescription {
    const char* path;
    const char* group;
    const char* schema;
    const char* key;
    enum class Type { Boolean, Uint32 } type;
};

constexpr SettingDescription kSettings[] = {
    {"/org/gnome/desktop/session/idle-delay",
     "org/gnome/desktop/session", "org.gnome.desktop.session", "idle-delay",
     SettingDescription::Type::Uint32},
    {"/org/gnome/desktop/screensaver/lock-enabled",
     "org/gnome/desktop/screensaver", "org.gnome.desktop.screensaver",
     "lock-enabled", SettingDescription::Type::Boolean},
    {"/org/gnome/desktop/screensaver/lock-delay",
     "org/gnome/desktop/screensaver", "org.gnome.desktop.screensaver",
     "lock-delay", SettingDescription::Type::Uint32},
    {"/org/gnome/desktop/lockdown/disable-lock-screen",
     "org/gnome/desktop/lockdown", "org.gnome.desktop.lockdown",
     "disable-lock-screen", SettingDescription::Type::Boolean},
};

class UniqueFd {
public:
    explicit UniqueFd(int value = -1) : value_(value) {}
    ~UniqueFd() { if (value_ >= 0) ::close(value_); }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            if (value_ >= 0) ::close(value_);
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }
    int get() const { return value_; }
private:
    int value_;
};

std::string systemError() { return std::strerror(errno); }

bool validateDirectoryFd(int fd, const std::filesystem::path& path,
                         const GnomeSystemBackendOptions& options,
                         std::string& error) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        error = "cannot inspect trusted directory " + path.string() + ": " +
            systemError();
        return false;
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != options.trustedOwner ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        error = "unsafe trusted directory: " + path.string();
        return false;
    }
    return true;
}

bool validateOrdinaryTraversalFd(int fd, const std::filesystem::path& path,
                                 std::string& error) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        error = "cannot inspect GNOME dconf directory " + path.string() + ": " +
            systemError();
        return false;
    }
    if ((info.st_mode & S_IXOTH) == 0) {
        error = "GNOME dconf directory is not traversable by ordinary users: " +
            path.string();
        return false;
    }
    return true;
}

enum class DirectoryAccess { SecureOnly, OrdinaryTraversal };

bool relativeComponents(const std::filesystem::path& path,
                        const GnomeSystemBackendOptions& options,
                        std::vector<std::string>& components,
                        std::string& error) {
    const auto root = options.trustedRoot.lexically_normal();
    const auto target = path.lexically_normal();
    if (!root.is_absolute() || !target.is_absolute()) {
        error = "GNOME dconf paths must be absolute";
        return false;
    }
    const auto relative = target.lexically_relative(root);
    if (relative.empty() && target != root) {
        error = "path is outside trusted root: " + target.string();
        return false;
    }
    components.clear();
    for (const auto& component : relative) {
        const std::string value = component.string();
        if (value.empty() || value == ".") continue;
        if (value == "..") {
            error = "path is outside trusted root: " + target.string();
            return false;
        }
        components.push_back(value);
    }
    return true;
}

bool openDirectory(const std::filesystem::path& path, bool create,
                   const GnomeSystemBackendOptions& options,
                   UniqueFd& result, std::string& error,
                   DirectoryAccess access = DirectoryAccess::SecureOnly,
                   bool* missing = nullptr, bool* created = nullptr) {
    if (missing != nullptr) *missing = false;
    if (created != nullptr) *created = false;
    std::vector<std::string> components;
    if (!relativeComponents(path, options, components, error)) return false;
    UniqueFd current(::open(options.trustedRoot.c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (current.get() < 0 ||
        !validateDirectoryFd(current.get(), options.trustedRoot, options, error)) {
        if (current.get() < 0)
            error = "cannot securely open trusted root " +
                options.trustedRoot.string() + ": " + systemError();
        return false;
    }
    if (access == DirectoryAccess::OrdinaryTraversal &&
        !validateOrdinaryTraversalFd(current.get(), options.trustedRoot, error))
        return false;
    std::filesystem::path traversed = options.trustedRoot;
    for (const std::string& component : components) {
        traversed /= component;
        bool createdHere = false;
        int next = ::openat(current.get(), component.c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT && create) {
            if (::mkdirat(current.get(), component.c_str(), 0755) == 0) {
                createdHere = true;
            } else {
                const int mkdirError = errno;
                if (mkdirError != EEXIST) {
                    errno = mkdirError;
                    error = "cannot create trusted directory " +
                        traversed.string() + ": " + systemError();
                    return false;
                }
                // Another process created this component after our ENOENT.
                // Treat it as foreign existing state: validate it below, but
                // never claim ownership by changing its mode.
            }
            next = ::openat(current.get(), component.c_str(),
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        if (next < 0) {
            if (errno == ENOENT && !create && missing != nullptr) {
                *missing = true;
                error.clear();
                return false;
            }
            error = "cannot securely open directory " + traversed.string() +
                ": " + systemError();
            return false;
        }
        UniqueFd opened(next);
        if (!validateDirectoryFd(opened.get(), traversed, options, error))
            return false;
        if (access == DirectoryAccess::OrdinaryTraversal &&
            !validateOrdinaryTraversalFd(opened.get(), traversed, error))
            return false;
        if (createdHere) {
            // The daemon umask (fic.service UMask=0027) would otherwise leave
            // FIC-created public dconf directories at 0750, hiding system dconf
            // state from ordinary desktop users. Deterministic mode is forced
            // through the already-validated directory fd; no path-based chmod.
            if (::fchmod(opened.get(), 0755) != 0) {
                error = "cannot set mode on created directory " +
                    traversed.string() + ": " + systemError();
                return false;
            }
        }
        if (created != nullptr && createdHere) *created = true;
        current = std::move(opened);
    }
    result = std::move(current);
    return true;
}

// Ordinary GNOME users must be able to traverse (and read within) the system
// dconf directories FIC relies on. Existing foreign directories are only
// validated, never re-permissioned: an unfixable parent fails closed.
bool pathTraversableByOrdinaryUsers(
    const std::filesystem::path& path,
    const GnomeSystemBackendOptions& options, std::string& error) {
    UniqueFd dir;
    return openDirectory(path, false, options, dir, error,
                         DirectoryAccess::OrdinaryTraversal);
}

// Trusted, non-world/group-writable, ordinary-user-readable regular file.
bool fileAccessibleToOrdinaryUsers(const std::filesystem::path& path,
                                   const GnomeSystemBackendOptions& options,
                                   std::string& error) {
    UniqueFd parent;
    if (!openDirectory(path.parent_path(), false, options, parent, error,
                       DirectoryAccess::OrdinaryTraversal))
        return false;
    struct stat info {};
    if (::fstatat(parent.get(), path.filename().c_str(), &info,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        error = "cannot inspect GNOME dconf file " + path.string() + ": " +
            systemError();
        return false;
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != options.trustedOwner ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (info.st_mode & S_IROTH) == 0) {
        error = "GNOME dconf file is not readable by ordinary users: " +
            path.string();
        return false;
    }
    return true;
}

bool readOptionalFile(const std::filesystem::path& path,
                      const GnomeSystemBackendOptions& options,
                      bool& exists, std::string& content, std::string& error) {
    exists = false;
    content.clear();
    UniqueFd parent;
    bool parentMissing = false;
    if (!openDirectory(path.parent_path(), false, options, parent, error,
                       DirectoryAccess::SecureOnly, &parentMissing)) {
        if (parentMissing) return true;
        return false;
    }
    UniqueFd file(::openat(parent.get(), path.filename().c_str(),
                           O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) {
        if (errno == ENOENT) { error.clear(); return true; }
        error = "cannot securely open " + path.string() + ": " + systemError();
        return false;
    }
    struct stat info {};
    if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != options.trustedOwner ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        error = "unsafe managed file: " + path.string();
        return false;
    }
    char buffer[8192];
    for (;;) {
        const ssize_t count = ::read(file.get(), buffer, sizeof(buffer));
        if (count > 0) { content.append(buffer, static_cast<size_t>(count)); continue; }
        if (count == 0) break;
        if (errno == EINTR) continue;
        error = "cannot read " + path.string() + ": " + systemError();
        return false;
    }
    exists = true;
    error.clear();
    return true;
}

const SettingDescription* settingFor(const std::string& path) {
    for (const auto& setting : kSettings)
        if (path == setting.path) return &setting;
    return nullptr;
}

bool validValue(const SettingDescription& setting, const std::string& value) {
    if (setting.type == SettingDescription::Type::Boolean)
        return value == "true" || value == "false";
    static const std::regex uint32Pattern("uint32 (0|[1-9][0-9]*)");
    if (!std::regex_match(value, uint32Pattern)) return false;
    try { return std::stoull(value.substr(7)) <= 0xffffffffULL; }
    catch (...) { return false; }
}

using Keyfile = std::map<std::string, std::map<std::string, std::string>>;

bool parseKeyfile(const std::string& content, Keyfile& parsed,
                  std::string& error) {
    parsed.clear();
    std::string group;
    std::istringstream input(content);
    std::string line;
    const std::regex groupPattern(
        "\\[([A-Za-z0-9_][A-Za-z0-9_.-]*"
        "(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*)\\]");
    const std::regex keyPattern("([A-Za-z0-9_][A-Za-z0-9_.-]*)=(.+)");
    size_t lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        std::smatch match;
        if (std::regex_match(line, match, groupPattern)) {
            group = match[1].str();
            if (parsed.count(group) != 0) {
                error = "duplicate group in FIC dconf keyfile at line " +
                    std::to_string(lineNumber);
                return false;
            }
            parsed[group] = {};
        } else if (!group.empty() && std::regex_match(line, match, keyPattern)) {
            auto& values = parsed[group];
            if (!values.emplace(match[1].str(), match[2].str()).second) {
                error = "duplicate key in FIC dconf keyfile at line " +
                    std::to_string(lineNumber);
                return false;
            }
        } else {
            error = "malformed FIC dconf keyfile at line " +
                std::to_string(lineNumber);
            return false;
        }
    }
    return true;
}

bool parseLocks(const std::string& content, std::set<std::string>& locks,
                std::string& error) {
    locks.clear();
    std::istringstream input(content);
    std::string line;
    const std::regex pathPattern(
        "/[A-Za-z0-9_][A-Za-z0-9_.-]*"
        "(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)+");
    size_t lineNumber = 0;
    while (std::getline(input, line)) {
        ++lineNumber;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        if (!std::regex_match(line, pathPattern)) {
            error = "malformed FIC dconf lock file at line " +
                std::to_string(lineNumber);
            return false;
        }
        locks.insert(line);
    }
    return true;
}

struct ProfileEntry {
    // Исходная строка профиля без завершающего перевода строки. Чужие строки
    // администратора сохраняются byte-for-byte при любой перезаписи.
    std::string raw;
    bool isSource = false;
    bool writable = false;
    bool fic = false;
};

struct Profile {
    std::vector<ProfileEntry> entries;
};

std::string trimmed(std::string value);

// Разбирает одну строку dconf profile. Поддерживаются документированные
// конструкции dconf: user-db:, service-db:, system-db: и file-db:, ведущие и
// замыкающие пробелы, а также inline '#'-комментарий. Полные строки-комментарии
// и пустые строки источниками не являются. Всё остальное отвергается fail-closed.
bool parseProfileEntry(const std::string& raw, ProfileEntry& entry,
                       std::string& error) {
    entry = ProfileEntry{raw, false, false, false};
    std::string text = raw;
    const auto comment = text.find('#');
    if (comment != std::string::npos) text.resize(comment);
    text = trimmed(text);
    if (text.empty()) return true;
    static const std::regex sourceEntry(
        "(user-db|service-db|system-db|file-db):[ \t]*([^ \t]+)[ \t]*");
    std::smatch match;
    if (!std::regex_match(text, match, sourceEntry)) {
        error = "malformed dconf profile entry: " + raw;
        return false;
    }
    const std::string type = match[1].str();
    const std::string value = match[2].str();
    static const std::regex databaseName(
        "[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*");
    // dconf accepts a non-empty path after file-db:; FIC requires an absolute
    // Unix path without control characters but does not restrict the charset
    // to a narrow allowlist (paths with '+', '@', '=' etc. are valid).
    bool validValue = false;
    if (type == "file-db") {
        validValue = value.size() > 1 && value.front() == '/' &&
            std::none_of(value.begin(), value.end(),
                         [](unsigned char ch) { return ch < 0x20 || ch == 0x7f; });
    } else {
        validValue = std::regex_match(value, databaseName);
    }
    if (!validValue) {
        error = "malformed dconf profile entry: " + raw;
        return false;
    }
    entry.isSource = true;
    entry.writable = type == "user-db" || type == "service-db";
    entry.fic = type == "system-db" && value == "fic";
    return true;
}

bool parseProfile(const std::string& content, Profile& profile,
                  std::string& error) {
    profile.entries.clear();
    std::istringstream input(content);
    std::string line;
    bool sawSource = false;
    size_t ficCount = 0;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        ProfileEntry entry;
        if (!parseProfileEntry(line, entry, error)) return false;
        if (entry.isSource && !sawSource) {
            sawSource = true;
            if (!entry.writable) {
                error =
                    "dconf profile has no writable database before read-only "
                    "databases";
                return false;
            }
        }
        if (entry.fic) ++ficCount;
        profile.entries.push_back(std::move(entry));
    }
    if (!sawSource) {
        error = "dconf profile has no database entries";
        return false;
    }
    if (ficCount > 1) {
        error = "dconf profile contains duplicate system-db:fic entries";
        return false;
    }
    return true;
}

bool profileHasFicAfterWritable(const Profile& profile) {
    bool sawWritable = false;
    for (const auto& entry : profile.entries) {
        if (!entry.isSource) continue;
        if (!sawWritable) {
            sawWritable = true;
            continue;
        }
        return entry.fic;
    }
    return false;
}

std::string trimmed(std::string value) {
    while (!value.empty() &&
           (value.back() == '\n' || value.back() == '\r' ||
            value.back() == ' ' || value.back() == '\t')) value.pop_back();
    size_t first = 0;
    while (first < value.size() && (value[first] == ' ' || value[first] == '\t'))
        ++first;
    return value.substr(first);
}

std::string processFailure(const char* command, const ProcessResult& result) {
    if (!result.error.empty()) return std::string(command) + ": " + result.error;
    if (result.timedOut) return std::string(command) + " timed out";
    if (result.outputLimitExceeded)
        return std::string(command) + " exceeded output limit";
    return std::string(command) + " exited with code " +
        std::to_string(result.exitCode) +
        (result.standardError.empty() ? "" : ": " + trimmed(result.standardError));
}

ProcessOptions commandOptions(const std::filesystem::path& profile = {}) {
    ProcessOptions options;
    options.timeout = std::chrono::seconds(10);
    options.maxOutputBytes = 64 * 1024;
    options.clearEnvironment = true;
    options.environment = {{"LC_ALL", "C"}, {"LANG", "C"}};
    if (!profile.empty()) {
        options.environment.push_back({"DCONF_PROFILE", profile.string()});
        options.environment.push_back({"HOME", "/"});
        options.environment.push_back({"XDG_CONFIG_HOME", "/nonexistent"});
        options.environment.push_back({"XDG_RUNTIME_DIR", "/nonexistent"});
    }
    return options;
}

} // namespace

GnomeSystemBackend::GnomeSystemBackend(
    const fic::platform::PlatformExecutableResolver& executables,
    GnomeSystemBackendOptions options)
    : GnomeSystemBackend(
          { [&executables](fic::platform::ExecutableId id,
                           std::filesystem::path& path, std::string& error) {
                return executables.resolve(id, path, error);
            },
            [](const std::filesystem::path& path,
               const std::vector<std::string>& arguments,
               const ProcessOptions& processOptions) {
                return VerifiedProcessExecutor::execute(
                    path.string(), arguments, processOptions);
            } },
          std::move(options)) {}

GnomeSystemBackend::GnomeSystemBackend(
    GnomeSystemBackendDependencies dependencies,
    GnomeSystemBackendOptions options)
    : dependencies_(std::move(dependencies)), options_(std::move(options)) {
    if (options_.lockPath.empty() && fic::core::FicRuntimePaths::isInitialized())
        options_.lockPath = fic::core::FicRuntimePaths::get().runtimeDir / "desktop-config.lock";
}

DesktopEnvironmentKind GnomeSystemBackend::desktop() const {
    return DesktopEnvironmentKind::Gnome;
}

std::string GnomeSystemBackend::backendName() const { return "gnome"; }

bool GnomeSystemBackend::ensureManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) { error.clear(); return true; }
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (!journal) { if (error.empty()) error = "GNOME mutation journal unavailable"; return false; }
    DesktopGlobalConfigRequirements requirements;
    for (const auto& [key, value] : required)
        requirements.emplace(key, GlobalDesktopConfigValue{value, {{"OSS", "DesktopEnvironment", "screenlock_timeout"}}});
    return reconcileJournaled(requirements, *journal, error);
}

bool GnomeSystemBackend::verifyManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) { error.clear(); return true; }
    for (const auto& [key, value] : required) {
        const auto* description = settingFor(key.setting);
        if (description == nullptr || !validValue(*description, value)) {
            error = "invalid required GNOME setting: " + key.setting;
            return false;
        }
    }
    // Required persistent state includes usable permissions, not only content:
    // the compiled database and the profile must stay readable by ordinary
    // users, and the parent paths must stay traversable. A later permission
    // regression therefore fails this independent verify pass too.
    const auto compiledPath = options_.databaseRoot / options_.databaseName;
    const auto profileDir = options_.profilePath.parent_path();
    if (!pathTraversableByOrdinaryUsers(profileDir, options_, error) ||
        !pathTraversableByOrdinaryUsers(options_.databaseRoot, options_, error))
        return false;
    if (!fileAccessibleToOrdinaryUsers(options_.profilePath, options_, error) ||
        !fileAccessibleToOrdinaryUsers(compiledPath, options_, error))
        return false;
    std::filesystem::path gsettings;
    if (!dependencies_.resolveExecutable(fic::platform::ExecutableId::Gsettings,
                                         gsettings, error)) {
        error = "cannot resolve gsettings: " + error;
        return false;
    }
    return verifyWithExecutable(required, gsettings, error);
}

bool GnomeSystemBackend::verifyWithExecutable(
    const DesktopManagedSettings& required,
    const std::filesystem::path& gsettings, std::string& error) const {
    bool exists = false;
    std::string profileText;
    if (!readOptionalFile(options_.profilePath, options_, exists,
                          profileText, error)) return false;
    if (!exists) { error = "dconf profile is missing"; return false; }
    Profile profile;
    if (!parseProfile(profileText, profile, error) ||
        !profileHasFicAfterWritable(profile)) {
        if (error.empty())
            error = "system-db:fic is not the highest-priority system database";
        return false;
    }
    for (const auto& [key, expected] : required) {
        const auto& setting = *settingFor(key.setting);
        ProcessResult value = dependencies_.execute(
            gsettings, {"get", setting.schema, setting.key},
            commandOptions(options_.profilePath));
        if (!value.success()) {
            error = processFailure("gsettings get", value);
            return false;
        }
        if (trimmed(value.standardOutput) != expected) {
            error = "effective value mismatch for " + key.setting +
                ": expected " + expected + ", got " +
                trimmed(value.standardOutput);
            return false;
        }
        ProcessResult writable = dependencies_.execute(
            gsettings, {"writable", setting.schema, setting.key},
            commandOptions(options_.profilePath));
        if (!writable.success()) {
            error = processFailure("gsettings writable", writable);
            return false;
        }
        if (trimmed(writable.standardOutput) != "false") {
            error = "GNOME dconf key remains writable: " + key.setting;
            return false;
        }
    }
    error.clear();
    return true;
}

namespace {
using namespace fic::rollback;
using fic::core::ContentDigest;
const PolicyRef gnomeScalarPolicy{"OSS", "DesktopEnvironment", "screenlock_timeout"};
struct GnomeLine {
    std::optional<std::string> raw;
    std::size_t offset = 0;
    std::size_t insertion = 0;
    bool groupPresent = false;
};
struct GnomeJournalInputs {
    std::map<std::string, AtomicTargetState> files;
    std::map<std::string, AtomicTargetState> cacheSources;
    AtomicTargetState profile;
    AtomicTargetState compiled;
    std::map<std::string, MutationRecord> active;
    std::filesystem::path sourceDirectory;
    bool inactive = false;
    bool compiledMissing = false;
};
struct GnomeLayout {
    std::map<std::string, MutationRecord> artifacts;
    std::vector<std::string> missing;
    std::map<std::string, AtomicTargetState> files;
    std::map<std::string, AtomicTargetState> originalFiles;
    AtomicTargetState profile, compiled;
    bool compiledMissing = false;
    std::map<std::filesystem::path, std::optional<AtomicTargetState>> before;
};
bool renderGnomeLayout(MutationJournal&, const GnomeSystemBackendOptions&, GnomeLayout&, std::string&);
bool ensureGnomeLayout(MutationJournal&, const GnomeSystemBackendOptions&,
                       const GnomeSystemBackendDependencies&, std::string&);
bool releaseGnomeLayout(MutationJournal&, const GnomeSystemBackendOptions&,
                        const GnomeSystemBackendDependencies&, std::string&, bool preview = false);
std::string gnomeMarker(const MutationRecord& record, bool lock) {
    return "# FIC-DE " + std::to_string(record.id) + " " + record.resource +
        (lock ? "/lock\n" : "/value\n");
}
bool gnomeProjection(const std::string& text, const SettingDescription& setting,
                     bool lock, GnomeLine& result, std::string& error) {
    result = {};
    bool group = lock;
    for (std::size_t offset = 0; offset < text.size();) {
        const auto end = text.find('\n', offset);
        const auto size = end == std::string::npos ? text.size() - offset : end - offset + 1;
        const auto raw = text.substr(offset, size);
        const auto line = trimmed(raw);
        if (!lock && line == "[" + std::string(setting.group) + "]") {
            group = true;
            result.groupPresent = true;
            result.insertion = offset + size;
        } else if (!lock && !line.empty() && line.front() == '[') {
            group = false;
        } else if (group) {
            result.insertion = offset + size;
            const bool matches = lock ? line == setting.path :
                line.compare(0, std::strlen(setting.key) + 1,
                             std::string(setting.key) + "=") == 0;
            if (matches) {
                if (result.raw) { error = "duplicate GNOME scalar or lock"; return false; }
                result.raw = raw;
                result.offset = offset;
            }
        }
        offset += size;
    }
    if (lock) { result.groupPresent = true; result.insertion = text.size(); }
    return true;
}
bool captureGnomeFile(const std::filesystem::path& path,
                      const GnomeSystemBackendOptions& options,
                      AtomicTargetState& snapshot, std::string& error) {
    bool exists = false;
    std::string text;
    if (!readOptionalFile(path, options, exists, text, error)) return false;
    if (!exists) { error = "GNOME ownership requires an existing container: " + path.string(); return false; }
    if (!fileAccessibleToOrdinaryUsers(path, options, error) ||
        !AtomicFileWriter::captureTargetState(path.string(), snapshot, &error)) return false;
    if (snapshot.content != text || snapshot.owner != options.trustedOwner ||
        (snapshot.mode & (S_IWGRP | S_IWOTH)) || !(snapshot.mode & S_IROTH)) {
        error = "GNOME file changed during trusted capture"; return false;
    }
    return true;
}
bool gnomeMarkerProof(const std::string& text, const GnomeLine& line,
                      const MutationRecord& record, bool lock,
                      bool& marked, std::string& error) {
    const auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
    const auto marker = gnomeMarker(record, lock);
    const auto position = text.find(marker);
    marked = position != std::string::npos;
    const auto expected = lock ? std::string(scalar.setting) + "\n" : scalar.appliedLine;
    const auto original = lock ? scalar.originalLockLine : scalar.originalLine;
    if (marked) {
        if (!line.raw || line.offset < marker.size() || position != line.offset - marker.size() ||
            text.find(marker, position + 1) != std::string::npos ||
            (*line.raw != expected && (lock || !scalar.previousAppliedLine ||
                                      *line.raw != *scalar.previousAppliedLine))) {
            error = "GNOME ownership marker or applied projection mismatch: " + record.resource;
            return false;
        }
        return true;
    }
    if (line.raw == original && (scalar.phase == "release" ||
        (record.status == MutationStatus::Prepared && !scalar.hadApplied &&
         (lock || !scalar.previousAppliedLine)))) return true;
    error = "GNOME applied ownership disappeared or the original projection changed: " + record.resource;
    return false;
}
bool gnomeSourceInventory(const GnomeSystemBackendOptions& options,
                          std::map<std::string, AtomicTargetState>& files,
                          std::string& error) {
    files.clear();
    const auto source = options.databaseRoot / (options.databaseName + ".d");
    if (!pathTraversableByOrdinaryUsers(source, options, error) ||
        !pathTraversableByOrdinaryUsers(source / "locks", options, error)) return false;
    for (const std::string directory : {std::string(), std::string("locks")}) {
        std::error_code ec;
        std::filesystem::directory_iterator iterator(source / directory, ec);
        if (ec) { error = "cannot enumerate GNOME source directory: " + ec.message(); return false; }
        for (const auto& entry : iterator) {
            if (directory.empty() && entry.path().filename() == "locks") continue;
            const auto name = entry.path().filename().string();
            if (name.empty() || name == "." || name == "..") { error = "unsafe GNOME source name"; return false; }
            AtomicTargetState state;
            if (!captureGnomeFile(entry.path(), options, state, error)) return false;
            files.emplace(directory.empty() ? name : directory + "/" + name, std::move(state));
        }
    }
    return true;
}
bool gnomeInputs(const DesktopGlobalConfigRequirements& required, MutationJournal& journal,
                 const GnomeSystemBackendOptions& options, GnomeJournalInputs& inputs,
                 std::string& error) {
    inputs = {};
    if (!journal.usable()) { error = "GNOME mutation journal is unhealthy"; return false; }
    if (options.databaseName != "fic" || options.keyfileName != "99-fic.conf" || options.lockfileName != "99-fic") {
        error = "GNOME journal resource route does not match the trusted fic layout"; return false;
    }
    for (const auto& [key, value] : required) {
        const auto* setting = settingFor(key.setting);
        if (!setting || !validValue(*setting, value.value) || value.owners.empty()) {
            error = "invalid GNOME physical requirement"; return false;
        }
        for (const auto& owner : value.owners)
            if (owner.moduleName != "OSS" || owner.submoduleName != "DesktopEnvironment" ||
                (owner.policyName != "screenlock_timeout" && owner.policyName != "disable_kde_lock_screen_media_controls")) {
                error = "unknown GNOME requirement owner"; return false;
            }
    }
    for (const auto& record : journal.records()) {
        if (!record.isActive() || record.undo.backend != MutationBackend::Desktop) continue;
        const auto* scalar = std::get_if<UndoRestoreDesktopScalar>(&record.undo.payload);
        if (std::holds_alternative<UndoOwnDesktopArtifact>(record.undo.payload)) continue;
        if (!scalar) { error = "desktop journal payload mismatch"; return false; }
        if (scalar->desktop != "GNOME") continue;
        if (!settingFor(scalar->setting) || record.resource != "GNOME" + scalar->setting ||
            record.policy != gnomeScalarPolicy || !inputs.active.emplace(scalar->setting, record).second) {
            error = "GNOME physical journal identity conflict"; return false;
        }
    }
    inputs.sourceDirectory = options.databaseRoot / (options.databaseName + ".d");
    if (required.empty() && inputs.active.empty()) {
        // No desired/owned state authorizes no writes. Still reject an orphan
        // marker in either trusted managed fragment, when present.
        for (const auto& path : {inputs.sourceDirectory / options.keyfileName,
                                inputs.sourceDirectory / "locks" / options.lockfileName}) {
            bool exists = false;
            std::string text;
            if (!readOptionalFile(path, options, exists, text, error)) return false;
            if (exists && text.find("# FIC-DE ") != std::string::npos) {
                error = "orphan GNOME marker without journal provenance"; return false;
            }
        }
        inputs.inactive = true;
        error.clear(); return true;
    }
    if (!required.empty()) {
        GnomeLayout layout;
        if (!renderGnomeLayout(journal, options, layout, error)) return false;
        inputs.files = std::move(layout.files); inputs.profile = std::move(layout.profile);
        inputs.cacheSources = std::move(layout.originalFiles);
        inputs.compiled = std::move(layout.compiled); inputs.compiledMissing = layout.compiledMissing;
    } else if (!gnomeSourceInventory(options, inputs.files, error) ||
        !captureGnomeFile(options.profilePath, options, inputs.profile, error) ||
        !captureGnomeFile(options.databaseRoot / options.databaseName, options, inputs.compiled, error)) return false;
    if (required.empty()) inputs.cacheSources = inputs.files;
    if (!inputs.files.count(options.keyfileName) || !inputs.files.count("locks/" + options.lockfileName)) {
        error = "GNOME source/lock container creation provenance is unavailable"; return false;
    }
    Profile profile;
    if (!parseProfile(inputs.profile.content, profile, error) || !profileHasFicAfterWritable(profile)) {
        if (error.empty()) error = "existing GNOME profile does not expose fic at the required priority";
        return false;
    }
    const auto& source = inputs.files.at(options.keyfileName).content;
    const auto& locks = inputs.files.at("locks/" + options.lockfileName).content;
    Keyfile parsed;
    std::set<std::string> parsedLocks;
    if (!parseKeyfile(source, parsed, error) || !parseLocks(locks, parsedLocks, error)) return false;
    for (const bool lock : {false, true}) {
        const auto& text = lock ? locks : source;
        std::set<std::string> expectedMarkers;
        for (const auto& [key, record] : inputs.active) { (void)key; expectedMarkers.insert(gnomeMarker(record, lock)); }
        for (std::size_t start = text.find("# FIC-DE "); start != std::string::npos;
             start = text.find("# FIC-DE ", start + 1)) {
            const auto end = text.find('\n', start);
            if (end == std::string::npos || !expectedMarkers.count(text.substr(start, end - start + 1))) {
                error = "unknown GNOME ownership marker/mutation ID"; return false;
            }
        }
    }
    std::set<std::string> keys;
    for (const auto& [key, value] : required) { (void)value; keys.insert(key.setting); }
    for (const auto& [key, record] : inputs.active) { (void)record; keys.insert(key); }
    for (const auto& key : keys) {
        const auto& setting = *settingFor(key);
        for (const bool lock : {false, true}) {
            const auto& text = lock ? locks : source;
            GnomeLine projection;
            if (!gnomeProjection(text, setting, lock, projection, error)) return false;
            if (!lock && !projection.groupPresent) {
                error = "GNOME group creation provenance is unavailable: " + std::string(setting.group); return false;
            }
            const auto active = inputs.active.find(key);
            bool marked = false;
            if (active != inputs.active.end() && !gnomeMarkerProof(text, projection, active->second, lock, marked, error)) return false;
            if (required.count({key}) && !projection.raw && projection.insertion && text[projection.insertion - 1] != '\n') {
                error = "GNOME scalar insertion would rewrite an unterminated foreign line"; return false;
            }
        }
    }
    error.clear(); return true;
}
// A scratch compilation is an independent native proof of ALL current source
// fragments, including foreign keys/locks. Nothing in the protected tree is
// touched; native output is never used as a backup of a shared database.
bool compileGnomeSources(const std::map<std::string, AtomicTargetState>& files,
                         const GnomeSystemBackendOptions& options,
                         const GnomeSystemBackendDependencies& dependencies,
                         const std::filesystem::path& dconf,
                         std::string& output, std::string& error, bool update = false) {
    GnomeSystemBackendOptions scratchOptions = options;
    scratchOptions.trustedRoot = options.lockPath.parent_path();
    UniqueFd parent;
    if (!openDirectory(scratchOptions.trustedRoot, false, scratchOptions, parent, error)) return false;
    std::string pattern = (scratchOptions.trustedRoot / ".fic-gnome-compile.XXXXXX").string();
    std::vector<char> name(pattern.begin(), pattern.end()); name.push_back('\0');
    char* created = ::mkdtemp(name.data());
    if (!created) { error = "cannot create private GNOME native compilation probe: " + systemError(); return false; }
    const std::filesystem::path temporary(created);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    } cleanup{temporary};
    std::error_code ec;
    std::filesystem::create_directories(temporary / "fic.d/locks", ec);
    if (ec) { error = "cannot stage GNOME sources: " + ec.message(); return false; }
    for (const auto& [relative, state] : files) {
        AtomicWriteOptions write;
        write.createIfMissing = true; write.exclusiveCreate = true; write.rejectSymlink = true;
        write.fileMode = 0600;
        if (!AtomicFileWriter::write((temporary / "fic.d" / relative).string(), state.content, write, &error)) return false;
    }
    auto processOptions = commandOptions(); processOptions.childUmask = 0022;
    const auto result = dependencies.execute(dconf, update
        ? std::vector<std::string>{"update", temporary.string()}
        : std::vector<std::string>{"compile", (temporary / "compiled").string(), (temporary / "fic.d").string()}, processOptions);
    if (!result.success()) { error = processFailure(update ? "dconf update" : "dconf compile", result); return false; }
    bool exists = false;
    if (!readOptionalFile(temporary / (update ? "fic" : "compiled"), scratchOptions, exists, output, error)) return false;
    if (!exists || output.empty()) { error = "native dconf compile did not produce a database"; return false; }
    error.clear(); return true;
}
bool proveGnomeCache(const GnomeJournalInputs& inputs, const std::string& nativeBefore,
                     std::string& error) {
    if (inputs.compiledMissing) return true;
    if (inputs.compiled.content == nativeBefore) return true;
    const auto digest = ContentDigest::sha256Hex(inputs.compiled.content);
    for (const auto& [key, record] : inputs.active) {
        (void)key;
        const auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        if (digest == scalar.compiledTargetDigest ||
            (record.status != MutationStatus::Applied && digest == scalar.compiledBeforeDigest)) return true;
    }
    error = "GNOME compiled database disagrees with native sources and has no pending journal authority";
    return false;
}
bool casGnome(const std::filesystem::path& path, const AtomicTargetState& before,
              const std::string& target, std::string& error) {
    if (target == before.content) return AtomicFileWriter::ensureTargetDurableIfCurrentState(path.string(), before, &error);
    AtomicWriteOptions write; write.rejectSymlink = true; write.expectedTargetState = before;
    AtomicWriteResult result;
    if (AtomicFileWriter::writeWithResult(path.string(), target, write, &error, &result)) return true;
    return result.installed && result.installedTargetState &&
        AtomicFileWriter::ensureTargetDurableIfCurrentState(path.string(), *result.installedTargetState, &error);
}
void patchGnomeProjection(std::string& text, const SettingDescription& setting, bool lock,
                          const MutationRecord& record, bool release) {
    GnomeLine line; std::string ignored;
    gnomeProjection(text, setting, lock, line, ignored);
    const auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
    const auto marker = gnomeMarker(record, lock);
    const bool marked = line.raw && line.offset >= marker.size() &&
        text.substr(line.offset - marker.size(), marker.size()) == marker;
    const auto original = lock ? scalar.originalLockLine : scalar.originalLine;
    const auto replacement = release ? original.value_or("") :
        marker + (lock ? scalar.setting + "\n" : scalar.appliedLine);
    if (marked) text.replace(line.offset - marker.size(), marker.size() + line.raw->size(), replacement);
    else if (line.raw) text.replace(line.offset, line.raw->size(), replacement);
    else if (!release) text.insert(line.insertion, replacement);
}

std::string artifactMarker(const MutationRecord& record) {
    return "# FIC-DE-ARTIFACT " + std::to_string(record.id) + " " +
        std::get<UndoOwnDesktopArtifact>(record.undo.payload).kind + "\n";
}
MutationRecord artifactRecord(const std::string& kind) {
    MutationRecord record; record.policy = gnomeScalarPolicy;
    record.resource = "GNOME/artifact/" + kind;
    record.undo = {MutationBackend::Desktop, UndoOwnDesktopArtifact{kind}};
    return record;
}
bool artifactRecords(MutationJournal& journal, std::map<std::string, MutationRecord>& out, std::string& error) {
    if (!journal.usable()) { error = "GNOME artifact journal unavailable"; return false; }
    out.clear();
    for (const auto& record : journal.records()) {
        if (!record.isActive()) continue;
        const auto* artifact = std::get_if<UndoOwnDesktopArtifact>(&record.undo.payload);
        if (!artifact) continue;
        if (record.undo.backend != MutationBackend::Desktop || record.policy != gnomeScalarPolicy ||
            record.resource != "GNOME/artifact/" + artifact->kind || !out.emplace(artifact->kind, record).second) {
            error = "GNOME artifact identity conflict"; return false;
        }
    }
    return true;
}
std::filesystem::path artifactDirectoryPath(const std::string& kind, const GnomeSystemBackendOptions& options) {
    const std::map<std::string, std::filesystem::path> paths{{"dconf-directory", options.databaseRoot.parent_path()},
        {"database-directory", options.databaseRoot}, {"profile-directory", options.profilePath.parent_path()},
        {"source-directory", options.databaseRoot / "fic.d"}, {"locks-directory", options.databaseRoot / "fic.d/locks"}};
    const auto found = paths.find(kind);
    return found == paths.end() ? std::filesystem::path{} : found->second;
}
bool capturePrivateGnomeFile(const std::filesystem::path& path, const GnomeSystemBackendOptions& options,
                            AtomicTargetState& state, std::string& error) {
    bool exists = false; std::string text;
    if (!readOptionalFile(path, options, exists, text, error) || !exists ||
        !AtomicFileWriter::captureTargetState(path.string(), state, &error)) return false;
    if (state.content != text || state.owner != options.trustedOwner || (state.mode & (S_IWGRP | S_IWOTH))) {
        error = "unsafe/changed private GNOME creation marker"; return false;
    }
    return true;
}
bool inspectCreationStage(const std::filesystem::path& path, const std::map<std::string, MutationRecord>& records,
                          const GnomeSystemBackendOptions& options, bool& owned, std::string& error) {
    owned = false;
    for (const auto& [kind, record] : records) {
        const auto target = artifactDirectoryPath(kind, options);
        if (target.empty() || path.parent_path() != target.parent_path() ||
            path.filename().string().find(".fic-de-stage." + std::to_string(record.id) + ".") != 0) continue;
        const auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
        struct stat state{};
        if (artifact.hadApplied || !artifact.inode || ::lstat(path.c_str(), &state) != 0 || !S_ISDIR(state.st_mode) ||
            state.st_uid != options.trustedOwner || (state.st_mode & (S_IWGRP | S_IWOTH)) ||
            state.st_dev != artifact.device || state.st_ino != artifact.inode) {
            error = "GNOME creation stage identity conflict"; return false;
        }
        std::error_code ec;
        for (std::filesystem::directory_iterator it(path, ec), end; !ec && it != end; it.increment(ec)) {
            const auto name = it->path().filename().string();
            if (name != ".fic-de-owner" && name.find("..fic-de-owner.tmp.") != 0) {
                error = "GNOME creation stage contains foreign data"; return false;
            }
            AtomicTargetState marker;
            if (!capturePrivateGnomeFile(it->path(), options, marker, error) || marker.content != artifactMarker(record)) {
                error = "GNOME creation stage marker content mismatch"; return false;
            }
        }
        if (ec) { error = "GNOME creation stage enumeration failed"; return false; }
        owned = true; return true;
    }
    return true;
}
bool renderGnomeLayout(MutationJournal& journal, const GnomeSystemBackendOptions& options,
                       GnomeLayout& layout, std::string& error) {
    layout = {};
    if (!artifactRecords(journal, layout.artifacts, error)) return false;
    UniqueFd parent;
    const auto source = options.databaseRoot / "fic.d";
    const auto recordFor = [&](const std::string& kind) {
        const auto found = layout.artifacts.find(kind);
        return found == layout.artifacts.end() ? artifactRecord(kind) : found->second;
    };
    const auto claimMissing = [&](const std::string& kind) {
        const auto record = recordFor(kind);
        const auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
        if (artifact.hadApplied || artifact.phase != "ensure") {
            error = "GNOME owned artifact disappeared or is releasing: " + kind; return false;
        }
        layout.missing.push_back(kind); return true;
    };
    for (const auto& [kind, path] : std::vector<std::pair<std::string, std::filesystem::path>>{
            {"dconf-directory", options.databaseRoot.parent_path()}, {"database-directory", options.databaseRoot},
            {"profile-directory", options.profilePath.parent_path()}}) {
        bool missing = false;
        if (!openDirectory(path, false, options, parent, error, DirectoryAccess::OrdinaryTraversal, &missing)) {
            if (!missing || !claimMissing(kind)) return false;
        } else {
            bool markerExists = false; std::string marker;
            if (!readOptionalFile(path / ".fic-de-owner", options, markerExists, marker, error)) return false;
            if (layout.artifacts.count(kind)) {
                const auto record = recordFor(kind);
                const auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
                struct stat identity{};
                if (!markerExists || marker != artifactMarker(record) || ::fstat(parent.get(), &identity) != 0 ||
                    identity.st_dev != artifact.device || identity.st_ino != artifact.inode) {
                    error = "GNOME parent directory creation identity mismatch: " + kind; return false;
                }
            } else if (markerExists) { error = "orphan GNOME directory creation marker"; return false; }
        }
    }
    const auto file = [&](const std::filesystem::path& path, AtomicTargetState& state, bool& exists) {
        std::string text;
        if (!readOptionalFile(path, options, exists, text, error)) return false;
        if (!exists) { layout.before[path] = std::nullopt; state = {}; return true; }
        if (!captureGnomeFile(path, options, state, error)) return false;
        layout.before[path] = state; return true;
    };
    for (const std::string relative : {std::string(), std::string("locks")}) {
        const auto directory = source / relative;
        const std::string kind = relative.empty() ? "source-directory" : "locks-directory";
        bool missing = false;
        UniqueFd fd;
        if (!openDirectory(directory, false, options, fd, error, DirectoryAccess::OrdinaryTraversal, &missing)) {
            if (!missing || !claimMissing(kind)) return false;
            layout.files[relative.empty() ? ".fic-de-owner" : "locks/.fic-de-owner"].content = artifactMarker(recordFor(kind));
        } else {
            std::error_code ec;
            for (std::filesystem::directory_iterator it(directory, ec), end; !ec && it != end; it.increment(ec)) {
                if (relative.empty() && it->path().filename() == "locks") continue;
                bool stage = false;
                if (!inspectCreationStage(it->path(), layout.artifacts, options, stage, error)) return false;
                if (stage) continue;
                const auto name = relative.empty() ? it->path().filename().string() : "locks/" + it->path().filename().string();
                AtomicTargetState snapshot;
                if (!captureGnomeFile(it->path(), options, snapshot, error)) return false;
                layout.files[name] = snapshot; layout.before[it->path()] = snapshot;
            }
            if (ec) { error = "GNOME source enumeration failed: " + ec.message(); return false; }
            if (layout.artifacts.count(kind)) {
                struct stat identity{};
                const auto directoryRecord = recordFor(kind);
                const auto& artifact = std::get<UndoOwnDesktopArtifact>(directoryRecord.undo.payload);
                if (::fstat(fd.get(), &identity) != 0 || identity.st_dev != artifact.device || identity.st_ino != artifact.inode) {
                    error = "GNOME directory creation identity mismatch: " + kind; return false;
                }
                const std::string markerFile = relative.empty() ? ".fic-de-owner" : "locks/.fic-de-owner";
                if (!layout.files.count(markerFile) || layout.files.at(markerFile).content != artifactMarker(recordFor(kind))) {
                    error = "GNOME directory creation marker disappeared: " + kind; return false;
                }
            }
        }
    }
    layout.originalFiles = layout.files;
    // Virtual directory markers contain no native settings. They may be
    // omitted from the authoritative before-state of a missing directory.
    for (const auto& kind : layout.missing) {
        if (kind == "source-directory") layout.originalFiles.erase(".fic-de-owner");
        if (kind == "locks-directory") layout.originalFiles.erase("locks/.fic-de-owner");
    }
    for (const auto& [relative, kind] : std::map<std::string, std::string>{{"99-fic.conf", "keyfile"}, {"locks/99-fic", "lockfile"}}) {
        if (!layout.files.count(relative)) {
            if (!claimMissing(kind)) return false;
            layout.files[relative].content = artifactMarker(recordFor(kind));
            layout.before[source / relative] = std::nullopt;
        } else if (layout.artifacts.count(kind) && layout.files.at(relative).content.find(artifactMarker(recordFor(kind))) != 0) {
            error = "GNOME file creation marker disappeared: " + kind; return false;
        }
    }
    auto& text = layout.files.at("99-fic.conf").content;
    Keyfile parsed;
    if (!parseKeyfile(text, parsed, error)) return false;
    for (const auto& [kind, group] : std::map<std::string, std::string>{{"session-group", "org/gnome/desktop/session"},
            {"screensaver-group", "org/gnome/desktop/screensaver"}, {"lockdown-group", "org/gnome/desktop/lockdown"}}) {
        if (!parsed.count(group)) {
            if (!claimMissing(kind)) return false;
            if (!text.empty() && text.back() != '\n') { error = "GNOME group insertion would alter foreign final line"; return false; }
            text += artifactMarker(recordFor(kind)) + "[" + group + "]\n";
        } else if (layout.artifacts.count(kind) && text.find(artifactMarker(recordFor(kind)) + "[" + group + "]\n") == std::string::npos) {
            error = "GNOME group creation marker disappeared: " + kind; return false;
        }
    }
    bool profileExists = false;
    if (!file(options.profilePath, layout.profile, profileExists)) return false;
    if (!profileExists) {
        if (!claimMissing("profile")) return false;
        layout.profile.content = artifactMarker(recordFor("profile")) + "user-db:user\n";
    } else if (layout.artifacts.count("profile") && layout.profile.content.find(artifactMarker(recordFor("profile"))) != 0) {
        error = "GNOME profile creation marker disappeared"; return false;
    }
    Profile profile;
    if (!parseProfile(layout.profile.content, profile, error)) return false;
    const bool hasFic = std::any_of(profile.entries.begin(), profile.entries.end(), [](const auto& entry) { return entry.fic; });
    if (hasFic) {
        if (!profileHasFicAfterWritable(profile)) { error = "foreign GNOME profile priority cannot be rewritten"; return false; }
        if (layout.artifacts.count("profile-entry") && layout.profile.content.find(
                artifactMarker(recordFor("profile-entry")) + "system-db:fic\n") == std::string::npos) {
            error = "GNOME profile entry ownership disappeared"; return false;
        }
    } else {
        if (!claimMissing("profile-entry")) return false;
        std::size_t position = 0;
        for (const auto& entry : profile.entries) {
            const auto newline = layout.profile.content.find('\n', position);
            if (newline == std::string::npos) { error = "profile insertion would alter foreign final line"; return false; }
            position = newline + 1;
            if (entry.isSource && entry.writable) break;
        }
        layout.profile.content.insert(position, artifactMarker(recordFor("profile-entry")) + "system-db:fic\n");
    }
    bool compiledExists = false;
    if (!file(options.databaseRoot / "fic", layout.compiled, compiledExists)) return false;
    layout.compiledMissing = !compiledExists;
    if (!compiledExists && !claimMissing("cache")) return false;
    if (layout.artifacts.count("cache") || !compiledExists) {
        const auto record = recordFor("cache");
        const std::string metadata = artifactMarker(record) + "[fic/ownership]\ncache-id='" + std::to_string(record.id) + "'\n";
        if (layout.files.count("00-fic-ownership") && layout.files.at("00-fic-ownership").content != metadata) {
            error = "GNOME native cache creation identity mismatch"; return false;
        }
        if (!layout.files.count("00-fic-ownership")) {
            if (std::get<UndoOwnDesktopArtifact>(record.undo.payload).hadApplied) {
                error = "GNOME native cache identity source disappeared"; return false;
            }
            layout.files["00-fic-ownership"].content = metadata;
            layout.before[source / "00-fic-ownership"] = std::nullopt;
        }
    }
    std::set<std::string> expected;
    for (const auto& [kind, record] : layout.artifacts) { (void)kind; expected.insert(artifactMarker(record)); }
    for (const auto& kind : layout.missing) expected.insert(artifactMarker(recordFor(kind)));
    const auto checkMarkers = [&](const std::string& body, const std::string& location) {
        for (auto pos = body.find("# FIC-DE-ARTIFACT "); pos != std::string::npos; pos = body.find("# FIC-DE-ARTIFACT ", pos + 1)) {
            const auto end = body.find('\n', pos);
            if (end == std::string::npos || !expected.count(body.substr(pos, end - pos + 1))) {
                error = "orphan GNOME artifact marker"; return false;
            }
            const auto marker = body.substr(pos, end - pos + 1);
            const auto kind = marker.substr(marker.find_last_of(' ') + 1, marker.size() - marker.find_last_of(' ') - 2);
            const std::map<std::string, std::string> locations{{"profile", "profile"}, {"profile-entry", "profile"},
                {"keyfile", "99-fic.conf"}, {"lockfile", "locks/99-fic"}, {"cache", "00-fic-ownership"},
                {"session-group", "99-fic.conf"}, {"screensaver-group", "99-fic.conf"}, {"lockdown-group", "99-fic.conf"},
                {"source-directory", ".fic-de-owner"}, {"locks-directory", "locks/.fic-de-owner"}};
            if (!locations.count(kind) || locations.at(kind) != location || body.find(marker, end + 1) != std::string::npos) {
                error = "GNOME artifact marker route/uniqueness mismatch"; return false;
            }
        }
        return true;
    };
    if (!checkMarkers(layout.profile.content, "profile")) return false;
    for (const auto& [relative, state] : layout.files) if (!checkMarkers(state.content, relative)) return false;
    return true;
}

bool publishOwnedDirectory(const std::filesystem::path& path, MutationRecord record, MutationJournal& journal,
                           const GnomeSystemBackendOptions& options, std::string& error) {
    UniqueFd parent;
    if (!openDirectory(path.parent_path(), false, options, parent, error)) return false;
    const auto prefix = ".fic-de-stage." + std::to_string(record.id) + ".";
    std::filesystem::path temporary;
    std::map<std::filesystem::path, AtomicTargetState> stagedMarkerTemps;
    std::error_code ec;
    const auto& previous = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
    for (std::filesystem::directory_iterator it(path.parent_path(), ec), end; !ec && it != end; it.increment(ec)) {
        if (it->path().filename().string().find(prefix) != 0) continue;
        struct stat state{};
        if (::lstat(it->path().c_str(), &state) != 0 || !S_ISDIR(state.st_mode) || state.st_uid != options.trustedOwner ||
            (state.st_mode & (S_IWGRP | S_IWOTH))) { error = "unsafe GNOME creation staging candidate"; return false; }
        bool markerExists = false; std::string marker;
        if (!readOptionalFile(it->path() / ".fic-de-owner", options, markerExists, marker, error)) return false;
        const bool identity = previous.inode && previous.device == state.st_dev && previous.inode == state.st_ino;
        if (!identity && (!markerExists || marker != artifactMarker(record))) continue;
        if (previous.inode && !identity) { error = "GNOME creation staging inode mismatch"; return false; }
        if (markerExists && marker != artifactMarker(record)) { error = "GNOME staging marker edited"; return false; }
        for (const auto& child : std::filesystem::directory_iterator(it->path())) {
            const auto name = child.path().filename().string();
            if (name == ".fic-de-owner") continue;
            AtomicTargetState state;
            if (name.find("..fic-de-owner.tmp.") != 0 || !capturePrivateGnomeFile(child.path(), options, state, error) ||
                state.content != artifactMarker(record)) { error = "GNOME creation staging contains foreign data"; return false; }
            stagedMarkerTemps.emplace(child.path(), state);
        }
        if (!temporary.empty()) { error = "ambiguous GNOME directory staging provenance"; return false; }
        temporary = it->path();
    }
    if (ec) { error = "cannot inspect GNOME creation staging: " + ec.message(); return false; }
    if (temporary.empty()) {
        std::string pattern = (path.parent_path() / (prefix + "XXXXXX")).string();
        std::vector<char> buffer(pattern.begin(), pattern.end()); buffer.push_back('\0');
        char* created = ::mkdtemp(buffer.data());
        if (!created) { error = "GNOME directory staging failed"; return false; }
        temporary = created;
    }
    struct Cleanup {
        std::filesystem::path path; std::string marker;
        ~Cleanup() {
            AtomicTargetState state; AtomicRemoveResult result; std::string ignored;
            const auto file = path / ".fic-de-owner";
            if (AtomicFileWriter::captureTargetState(file.string(), state, &ignored) && state.content == marker)
                (void)AtomicFileWriter::removeIfCurrentState(file.string(), state, &ignored, &result);
            (void)::rmdir(path.c_str()); // Never recursively erase a foreign child.
        }
    } cleanup{temporary, artifactMarker(record)};
    AtomicWriteOptions write; write.createIfMissing = true; write.exclusiveCreate = true; write.rejectSymlink = true;
    write.fileMode = 0644; write.fileOwner = options.trustedOwner; write.fileGroup = options.trustedGroup;
    struct stat staged{};
    if (::lstat(temporary.c_str(), &staged) != 0) { error = "GNOME directory staging identity failed"; return false; }
    auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
    artifact.device = staged.st_dev; artifact.inode = staged.st_ino;
    MutationId id = 0;
    if (!journal.prepareMutation(record, id, error)) return false;
    for (const auto& [path, state] : stagedMarkerTemps) {
        AtomicRemoveResult result;
        if (!AtomicFileWriter::removeIfCurrentState(path.string(), state, &error, &result) || !result.durabilityConfirmed) return false;
    }
    bool exists = false; std::string marker;
    if (!readOptionalFile(temporary / ".fic-de-owner", options, exists, marker, error)) return false;
    if (!exists && !AtomicFileWriter::write((temporary / ".fic-de-owner").string(), artifactMarker(record), write, &error)) return false;
    if (::chmod(temporary.c_str(), 0755) != 0) { error = "GNOME directory staging permissions failed"; return false; }
    UniqueFd stagedFd;
    if (!openDirectory(temporary, false, options, stagedFd, error) || ::fsync(stagedFd.get()) != 0) return false;
#ifdef SYS_renameat2
    if (::syscall(SYS_renameat2, AT_FDCWD, temporary.c_str(), parent.get(), path.filename().c_str(), RENAME_NOREPLACE) != 0) {
        error = "GNOME exclusive directory publication failed: " + systemError(); return false;
    }
#else
    error = "GNOME directory publication requires renameat2"; return false;
#endif
    return ::fsync(parent.get()) == 0;
}

bool ensureGnomeLayout(MutationJournal& journal, const GnomeSystemBackendOptions& options,
                       const GnomeSystemBackendDependencies& dependencies, std::string& error) {
    GnomeLayout initial;
    if (!renderGnomeLayout(journal, options, initial, error)) return false;
    if (initial.missing.empty() && std::all_of(initial.artifacts.begin(), initial.artifacts.end(),
        [](const auto& entry) { return entry.second.status == MutationStatus::Applied; })) return true;
    for (const auto& kind : initial.missing) {
        if (initial.artifacts.count(kind)) continue;
        MutationId id = 0;
        if (!journal.prepareMutation(artifactRecord(kind), id, error)) return false;
    }
    GnomeLayout layout;
    if (!renderGnomeLayout(journal, options, layout, error)) return false;
    const auto source = options.databaseRoot / "fic.d";
    for (const auto& kind : {"dconf-directory", "database-directory", "profile-directory", "source-directory", "locks-directory"}) {
        if (std::find(layout.missing.begin(), layout.missing.end(), kind) == layout.missing.end()) continue;
        const std::map<std::string, std::filesystem::path> paths{{"dconf-directory", options.databaseRoot.parent_path()},
            {"database-directory", options.databaseRoot}, {"profile-directory", options.profilePath.parent_path()},
            {"source-directory", source}, {"locks-directory", source / "locks"}};
        const auto path = paths.at(kind);
        if (!publishOwnedDirectory(path, layout.artifacts.at(kind), journal, options, error)) return false;
        std::map<std::string, MutationRecord> refreshed;
        if (!artifactRecords(journal, refreshed, error)) return false;
        layout.artifacts.at(kind) = refreshed.at(kind);
    }
    const auto publish = [&](const std::filesystem::path& path, const std::string& body) {
        const auto before = layout.before.find(path);
        if (before != layout.before.end() && before->second) return casGnome(path, *before->second, body, error);
        // Directory marker was already installed with its staged parent.
        if (path.filename() == ".fic-de-owner") return true;
        AtomicWriteOptions write; write.createIfMissing = true; write.exclusiveCreate = true; write.rejectSymlink = true;
        write.fileMode = 0644; write.fileOwner = options.trustedOwner; write.fileGroup = options.trustedGroup;
        return AtomicFileWriter::write(path.string(), body, write, &error);
    };
    for (const auto& [relative, state] : layout.files)
        if (!publish(source / relative, state.content)) return false;
    if (!publish(options.profilePath, layout.profile.content)) return false;
    if (!layout.missing.empty()) {
        std::filesystem::path dconf;
        std::string compiled;
        if (!dependencies.resolveExecutable(fic::platform::ExecutableId::Dconf, dconf, error) ||
            !compileGnomeSources(layout.files, options, dependencies, dconf, compiled, error)) return false;
        if (layout.compiledMissing) {
            if (!publish(options.databaseRoot / "fic", compiled)) return false;
        } else if (!casGnome(options.databaseRoot / "fic", layout.compiled, compiled, error)) return false;
    }
    for (auto& [kind, record] : layout.artifacts) {
        (void)kind;
        auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
        if (artifact.phase != "ensure") { error = "GNOME artifact release must finish before re-enrollment"; return false; }
        artifact.hadApplied = true; MutationId id = 0;
        if (!journal.prepareMutation(record, id, error) || !journal.setStatus(id, MutationStatus::Applied, error)) return false;
    }
    return true;
}

bool releaseGnomeLayout(MutationJournal& journal, const GnomeSystemBackendOptions& options,
                        const GnomeSystemBackendDependencies& dependencies, std::string& error, bool preview) {
    std::map<std::string, MutationRecord> artifacts;
    if (!artifactRecords(journal, artifacts, error)) return false;
    if (artifacts.empty()) {
        for (const auto& path : {options.profilePath, options.databaseRoot / "fic.d/99-fic.conf",
                options.databaseRoot / "fic.d/locks/99-fic", options.databaseRoot / "fic.d/00-fic-ownership",
                options.databaseRoot / "fic.d/.fic-de-owner", options.databaseRoot / "fic.d/locks/.fic-de-owner",
                options.databaseRoot / ".fic-de-owner", options.databaseRoot.parent_path() / ".fic-de-owner",
                options.profilePath.parent_path() / ".fic-de-owner"}) {
            bool exists = false; std::string body;
            if (!readOptionalFile(path, options, exists, body, error)) return false;
            if (exists && body.find("# FIC-DE-ARTIFACT ") != std::string::npos) {
                error = "orphan GNOME creation marker without active artifact provenance"; return false;
            }
        }
        return true;
    }
    const auto source = options.databaseRoot / "fic.d";
    const std::map<std::string, std::filesystem::path> directoryPaths{{"dconf-directory", options.databaseRoot.parent_path()},
        {"database-directory", options.databaseRoot}, {"profile-directory", options.profilePath.parent_path()},
        {"source-directory", source}, {"locks-directory", source / "locks"}};
    std::map<std::string, AtomicTargetState> files;
    const auto inventory = [&](std::map<std::string, AtomicTargetState>& output) {
    output.clear();
    bool sourceMissing = false; UniqueFd fd;
    if (!openDirectory(source, false, options, fd, error, DirectoryAccess::OrdinaryTraversal, &sourceMissing) && !sourceMissing) return false;
    if (!sourceMissing) {
        for (const std::string relative : {std::string(), std::string("locks")}) {
            bool missing = false;
            if (!openDirectory(source / relative, false, options, fd, error, DirectoryAccess::OrdinaryTraversal, &missing)) {
                if (missing) continue; return false;
            }
            std::error_code ec;
            for (std::filesystem::directory_iterator it(source / relative, ec), end; !ec && it != end; it.increment(ec)) {
                if (relative.empty() && it->path().filename() == "locks") continue;
                bool stage = false;
                if (!inspectCreationStage(it->path(), artifacts, options, stage, error)) return false;
                if (stage) continue;
                AtomicTargetState state; if (!captureGnomeFile(it->path(), options, state, error)) return false;
                output[relative.empty() ? it->path().filename().string() : "locks/" + it->path().filename().string()] = state;
            }
            if (ec) { error = "GNOME release inventory failed"; return false; }
        }
    }
    return true;
    };
    if (!inventory(files)) return false;
    const auto proveInventory = [&](const std::map<std::string, AtomicTargetState>& expected) {
        std::map<std::string, AtomicTargetState> actual;
        if (!inventory(actual)) return false;
        if (actual.size() != expected.size()) { error = "GNOME release inventory changed"; return false; }
        for (const auto& [name, state] : expected)
            if (!actual.count(name) || !AtomicFileWriter::targetStateMatches((source / name).string(), state, &error)) return false;
        return true;
    };
    auto target = files;
    for (const auto& record : journal.records()) {
        if (!record.isActive()) continue;
        const auto* scalar = std::get_if<UndoRestoreDesktopScalar>(&record.undo.payload);
        if (!scalar || scalar->desktop != "GNOME") continue;
        if (!preview) { error = "GNOME layout release still has active scalar owners"; return false; }
        if (!target.count("99-fic.conf") || !target.count("locks/99-fic")) { error = "GNOME release scalar containers missing"; return false; }
        const auto& setting = *settingFor(scalar->setting);
        patchGnomeProjection(target.at("99-fic.conf").content, setting, false, record, true);
        patchGnomeProjection(target.at("locks/99-fic").content, setting, true, record, true);
    }
    const auto isReleasing = [&](const std::string& kind) {
        const auto& artifact = std::get<UndoOwnDesktopArtifact>(artifacts.at(kind).undo.payload);
        return artifact.phase == "release" || !artifact.hadApplied;
    };
    const auto stripMarker = [&](std::string& text, const std::string& kind) {
        const auto marker = artifactMarker(artifacts.at(kind)); const auto pos = text.find(marker);
        if (pos == std::string::npos) {
            if (isReleasing(kind)) return true;
            error = "GNOME artifact release marker missing: " + kind; return false;
        }
        if (text.find(marker, pos + marker.size()) != std::string::npos) { error = "duplicate GNOME artifact marker"; return false; }
        text.erase(pos, marker.size()); return true;
    };
    std::set<std::string> detached;
    for (const auto& [kind, group] : std::map<std::string, std::string>{{"session-group", "org/gnome/desktop/session"},
            {"screensaver-group", "org/gnome/desktop/screensaver"}, {"lockdown-group", "org/gnome/desktop/lockdown"}}) {
        if (!artifacts.count(kind)) continue;
        if (!target.count("99-fic.conf")) { if (isReleasing(kind)) continue; error = "GNOME group container missing"; return false; }
        auto& text = target.at("99-fic.conf").content;
        const auto block = artifactMarker(artifacts.at(kind)) + "[" + group + "]\n";
        const auto start = text.find(block);
        if (start == std::string::npos) { if (!stripMarker(text, kind)) return false; detached.insert(kind); continue; }
        const auto body = start + block.size();
        auto end = body;
        while (end < text.size()) {
            const auto newline = text.find('\n', end);
            const auto size = newline == std::string::npos ? text.size() - end : newline - end + 1;
            const auto line = trimmed(text.substr(end, size));
            if ((!line.empty() && line.front() == '[') || line.find("# FIC-DE-ARTIFACT ") == 0) break;
            end += size;
        }
        if (trimmed(text.substr(body, end - body)).empty()) text.erase(start, end - start);
        else { if (!stripMarker(text, kind)) return false; detached.insert(kind); }
    }
    for (const auto& [kind, relative] : std::map<std::string, std::string>{{"keyfile", "99-fic.conf"}, {"lockfile", "locks/99-fic"}}) {
        if (!artifacts.count(kind)) continue;
        if (!target.count(relative)) { if (isReleasing(kind)) continue; error = "GNOME created file disappeared"; return false; }
        if (!stripMarker(target.at(relative).content, kind)) return false;
        if (target.at(relative).content.empty()) target.erase(relative);
        else detached.insert(kind);
    }
    bool cacheIdentityPresent = false;
    if (artifacts.count("cache")) {
        const auto& record = artifacts.at("cache");
        const auto expected = artifactMarker(record) + "[fic/ownership]\ncache-id='" + std::to_string(record.id) + "'\n";
        if (target.count("00-fic-ownership")) {
            if (target.at("00-fic-ownership").content != expected) { error = "GNOME native cache creation proof changed"; return false; }
            target.erase("00-fic-ownership");
            cacheIdentityPresent = true;
        } else if (!isReleasing("cache")) { error = "GNOME native cache proof missing"; return false; }
    }
    bool foreignSources = false;
    for (const auto& [name, state] : target)
        if (name != ".fic-de-owner" && name != "locks/.fic-de-owner" && !state.content.empty()) foreignSources = true;
    AtomicTargetState profileState, cacheState;
    bool profileExists = false, cacheExists = false; std::string profileText, cacheText;
    if (!readOptionalFile(options.profilePath, options, profileExists, profileText, error) ||
        !readOptionalFile(options.databaseRoot / "fic", options, cacheExists, cacheText, error)) return false;
    if (profileExists && !captureGnomeFile(options.profilePath, options, profileState, error)) return false;
    if (cacheExists && !captureGnomeFile(options.databaseRoot / "fic", options, cacheState, error)) return false;
    if (artifacts.count("cache") && cacheExists && !cacheIdentityPresent) detached.insert("cache");
    std::string profileTarget = profileText;
    if (artifacts.count("profile-entry")) {
        const auto block = artifactMarker(artifacts.at("profile-entry")) + "system-db:fic\n";
        const auto pos = profileTarget.find(block);
        if (pos != std::string::npos && profileTarget.find(block, pos + block.size()) != std::string::npos) {
            error = "duplicate GNOME owned profile entry"; return false;
        }
        if (pos == std::string::npos) { if (!isReleasing("profile-entry")) { error = "GNOME profile entry release proof missing"; return false; } }
        else if (foreignSources) { if (!stripMarker(profileTarget, "profile-entry")) return false; detached.insert("profile-entry"); }
        else profileTarget.erase(pos, block.size());
    }
    bool deleteProfile = false;
    if (artifacts.count("profile")) {
        if (profileExists && !stripMarker(profileTarget, "profile")) return false;
        deleteProfile = !profileExists || profileTarget == "user-db:user\n";
        if (!deleteProfile) detached.insert("profile");
    }
    std::filesystem::path dconf;
    std::string nativeBefore, nativeAfter;
    if (artifacts.count("cache") && (cacheExists || foreignSources) &&
        !dependencies.resolveExecutable(fic::platform::ExecutableId::Dconf, dconf, error)) return false;
    if (cacheExists && artifacts.count("cache")) {
        if (!compileGnomeSources(files, options, dependencies, dconf, nativeBefore, error)) return false;
        GnomeJournalInputs proof; proof.files = files; proof.compiled = cacheState;
        for (const auto& record : journal.records()) {
            const auto* scalar = std::get_if<UndoRestoreDesktopScalar>(&record.undo.payload);
            if (record.isActive() && scalar && scalar->desktop == "GNOME") proof.active.emplace(scalar->setting, record);
        }
        if (!proveGnomeCache(proof, nativeBefore, error)) return false;
    }
    if (foreignSources && artifacts.count("cache") && cacheIdentityPresent) {
        if (!compileGnomeSources(target, options, dependencies, dconf, nativeAfter, error, true)) return false;
        detached.insert("cache");
    }
    std::map<std::filesystem::path, AtomicTargetState> outerMarkers;
    std::map<std::filesystem::path, MutationRecord> unpublishedDirectories;
    for (const auto& [kind, record] : artifacts) {
        if (!directoryPaths.count(kind)) continue;
        const auto path = directoryPaths.at(kind);
        struct stat state{};
        if (::lstat(path.c_str(), &state) != 0) {
            if (errno == ENOENT && isReleasing(kind)) {
                const auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
                bool parentMissing = false; UniqueFd parent;
                if (!openDirectory(path.parent_path(), false, options, parent, error, DirectoryAccess::SecureOnly, &parentMissing)) {
                    if (parentMissing) continue; return false;
                }
                const auto prefix = ".fic-de-stage." + std::to_string(record.id) + ".";
                std::error_code ec;
                for (std::filesystem::directory_iterator it(path.parent_path(), ec), end; !ec && it != end; it.increment(ec)) {
                    if (it->path().filename().string().find(prefix) != 0) continue;
                    struct stat staged{};
                    if (::lstat(it->path().c_str(), &staged) != 0 || !S_ISDIR(staged.st_mode) || staged.st_uid != options.trustedOwner ||
                        staged.st_dev != artifact.device || staged.st_ino != artifact.inode) continue;
                    bool proven = false;
                    if (!inspectCreationStage(it->path(), artifacts, options, proven, error) || !proven) return false;
                    bool exists = false; std::string marker;
                    if (!readOptionalFile(it->path() / ".fic-de-owner", options, exists, marker, error)) return false;
                    if (exists && marker != artifactMarker(record)) { error = "unpublished GNOME marker changed"; return false; }
                    unpublishedDirectories.emplace(it->path(), record);
                }
                if (ec) { error = "GNOME unpublished directory inventory failed"; return false; }
                continue;
            }
            error = "GNOME owned directory disappeared"; return false;
        }
        const auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
        if (!S_ISDIR(state.st_mode) || state.st_uid != options.trustedOwner || state.st_dev != artifact.device || state.st_ino != artifact.inode) {
            error = "GNOME owned directory identity changed"; return false;
        }
        if (kind != "source-directory" && kind != "locks-directory") {
            bool exists = false; std::string marker;
            if (!readOptionalFile(path / ".fic-de-owner", options, exists, marker, error)) return false;
            if (exists) {
                if (marker != artifactMarker(record) || !captureGnomeFile(path / ".fic-de-owner", options, outerMarkers[path / ".fic-de-owner"], error)) {
                    error = "GNOME parent directory marker mismatch"; return false;
                }
            } else if (!isReleasing(kind)) { error = "GNOME parent directory marker disappeared"; return false; }
            continue;
        }
        const auto markerFile = kind == "source-directory" ? ".fic-de-owner" : "locks/.fic-de-owner";
        if (files.count(markerFile) && files.at(markerFile).content != artifactMarker(record)) { error = "GNOME directory marker changed"; return false; }
        if (!files.count(markerFile) && !isReleasing(kind)) { error = "GNOME directory marker missing"; return false; }
        target.erase(markerFile);
    }
    if (preview) return true;
    for (auto& [kind, record] : artifacts) {
        (void)kind; auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
        artifact.phase = "release"; record.status = MutationStatus::Prepared; MutationId id = 0;
        if (!journal.prepareMutation(record, id, error)) return false;
    }
    const auto remove = [&](const std::filesystem::path& path, const AtomicTargetState& state) {
        AtomicRemoveResult result;
        return AtomicFileWriter::removeIfCurrentState(path.string(), state, &error, &result) && result.durabilityConfirmed;
    };
    if (!proveInventory(files)) return false;
    if (artifacts.count("cache") && cacheExists && cacheIdentityPresent) {
        if (foreignSources) { if (!casGnome(options.databaseRoot / "fic", cacheState, nativeAfter, error)) return false; }
        else if (!remove(options.databaseRoot / "fic", cacheState)) return false;
    }
    auto published = files;
    for (const auto& [name, before] : files) {
        if (!proveInventory(published)) return false;
        if (!target.count(name)) {
            if (!remove(source / name, before)) return false;
            published.erase(name);
        } else {
            if (!casGnome(source / name, before, target.at(name).content, error)) return false;
            if (!captureGnomeFile(source / name, options, published.at(name), error) ||
                published.at(name).content != target.at(name).content) return false;
        }
    }
    if (!proveInventory(published)) return false;
    if (profileExists) {
        if (deleteProfile) { if (!remove(options.profilePath, profileState)) return false; }
        else if (!casGnome(options.profilePath, profileState, profileTarget, error)) return false;
    }
    for (const auto& [path, state] : outerMarkers) if (!remove(path, state)) return false;
    for (const auto& [path, record] : unpublishedDirectories) {
        struct stat identity{};
        const auto& artifact = std::get<UndoOwnDesktopArtifact>(record.undo.payload);
        if (::lstat(path.c_str(), &identity) != 0 || !S_ISDIR(identity.st_mode) ||
            identity.st_dev != artifact.device || identity.st_ino != artifact.inode) {
            error = "GNOME unpublished directory identity changed before cleanup"; return false;
        }
        bool proven = false;
        if (!inspectCreationStage(path, artifacts, options, proven, error) || !proven) return false;
        for (const auto& child : std::filesystem::directory_iterator(path)) {
            AtomicTargetState state;
            if (!capturePrivateGnomeFile(child.path(), options, state, error) || state.content != artifactMarker(record) ||
                !remove(child.path(), state)) return false;
        }
        if (::rmdir(path.c_str()) != 0) { error = "GNOME unpublished directory removal failed"; return false; }
        UniqueFd parent;
        if (!openDirectory(path.parent_path(), false, options, parent, error) || ::fsync(parent.get()) != 0) return false;
    }
    for (const auto& kind : {"locks-directory", "source-directory", "profile-directory", "database-directory", "dconf-directory"}) {
        if (!artifacts.count(kind)) continue;
        const auto path = directoryPaths.at(kind);
        std::error_code ec;
        if (std::filesystem::exists(path, ec)) {
            if (std::filesystem::is_empty(path, ec)) {
                if (::rmdir(path.c_str()) != 0) { error = "GNOME owned directory removal failed"; return false; }
            } else detached.insert(kind);
        }
        UniqueFd parent;
        auto barrier = path.parent_path();
        while (!std::filesystem::exists(barrier, ec) && barrier != options.trustedRoot && barrier != barrier.parent_path()) barrier = barrier.parent_path();
        if (!openDirectory(barrier, false, options, parent, error) || ::fsync(parent.get()) != 0) return false;
    }
    for (const auto& [kind, record] : artifacts)
        if (!journal.setStatus(record.id, detached.count(kind) ? MutationStatus::Detached : MutationStatus::RolledBack, error)) return false;
    return true;
}
} // namespace

bool GnomeSystemBackend::preflightJournaled(const DesktopGlobalConfigRequirements& required,
                                           fic::rollback::MutationJournal& journal,
                                           std::string& error) {
    ExclusivePidLock lock(options_.lockPath.string(), "", false);
    if (!lock.acquire()) { error = "cannot acquire FIC desktop-config lock"; return false; }
    GnomeJournalInputs inputs;
    if (!gnomeInputs(required, journal, options_, inputs, error)) return false;
    if (inputs.inactive) return releaseGnomeLayout(journal, options_, dependencies_, error, true);
    std::filesystem::path dconf, gsettings;
    if (!dependencies_.resolveExecutable(fic::platform::ExecutableId::Dconf, dconf, error) ||
        !dependencies_.resolveExecutable(fic::platform::ExecutableId::Gsettings, gsettings, error)) return false;
    for (const auto& [key, value] : required) {
        const auto& setting = *settingFor(key.setting);
        auto options = commandOptions(); options.environment.push_back({"GSETTINGS_BACKEND", "memory"});
        const auto range = dependencies_.execute(gsettings, {"range", setting.schema, setting.key}, options);
        if (!range.success()) { error = processFailure("GNOME schema preflight", range); return false; }
        const auto description = trimmed(range.standardOutput);
        const bool boolean = setting.type == SettingDescription::Type::Boolean;
        if (description == (boolean ? "type b" : "type u")) continue;
        if (!boolean) {
            std::istringstream input(description); std::string kind, type, extra;
            std::uint64_t minimum = 0, maximum = 0;
            if ((input >> kind >> type >> minimum >> maximum) && !(input >> extra) && kind == "range" && type == "u" &&
                minimum <= maximum && maximum <= 0xffffffffULL) {
                const auto wanted = std::stoull(value.value.substr(7));
                if (wanted >= minimum && wanted <= maximum) continue;
            }
        }
        error = "GNOME schema range/type does not admit requirement: " + key.setting; return false;
    }
    std::string nativeBefore;
    if (!compileGnomeSources(inputs.cacheSources, options_, dependencies_, dconf, nativeBefore, error) ||
        !proveGnomeCache(inputs, nativeBefore, error)) return false;
    auto target = inputs.files;
    // Preview the same scalar inverse used by release, including completion
    // of an interrupted release before a fresh enrollment. These scratch
    // projections grant no ownership and allocate no journal IDs.
    for (const auto& [setting, record] : inputs.active) {
        const auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        if (required.count({setting}) && scalar.phase != "release") continue;
        const auto& description = *settingFor(setting);
        patchGnomeProjection(target.at(options_.keyfileName).content, description, false, record, true);
        patchGnomeProjection(target.at("locks/" + options_.lockfileName).content, description, true, record, true);
    }
    for (const auto& [key, value] : required) {
        MutationRecord preview;
        const auto existing = inputs.active.find(key.setting);
        if (existing != inputs.active.end() &&
            std::get<UndoRestoreDesktopScalar>(existing->second.undo.payload).phase != "release")
            preview = existing->second;
        else {
            preview.resource = "GNOME" + key.setting;
            preview.undo = {MutationBackend::Desktop, UndoRestoreDesktopScalar{}};
        }
        const auto& description = *settingFor(key.setting);
        auto& scalar = std::get<UndoRestoreDesktopScalar>(preview.undo.payload);
        scalar.appliedLine = std::string(description.key) + "=" + value.value + "\n";
        patchGnomeProjection(target.at(options_.keyfileName).content, description, false, preview, false);
        patchGnomeProjection(target.at("locks/" + options_.lockfileName).content, description, true, preview, false);
    }
    std::string compiledTarget, updatedTarget;
    if (!compileGnomeSources(target, options_, dependencies_, dconf, compiledTarget, error) ||
        !compileGnomeSources(target, options_, dependencies_, dconf, updatedTarget, error, true)) return false;
    if (compiledTarget != updatedTarget) {
        error = "dconf update disagrees with native compilation in preflight";
        return false;
    }
    if (required.empty()) return releaseGnomeLayout(journal, options_, dependencies_, error, true);
    return true;
}

bool GnomeSystemBackend::releaseOwnerJournaled(const PolicyRef& owner,
                                              fic::rollback::MutationJournal& journal,
                                              std::string& error, bool preview) {
    if (owner.moduleName != "OSS" || owner.submoduleName != "DesktopEnvironment" ||
        (owner.policyName != "screenlock_timeout" && owner.policyName != "disable_kde_lock_screen_media_controls")) {
        error = "unknown GNOME release owner"; return false;
    }
    ExclusivePidLock lock(options_.lockPath.string(), "", false);
    if (!lock.acquire()) { error = "cannot acquire FIC desktop-config lock"; return false; }
    if (!journal.usable()) { error = "GNOME mutation journal is unhealthy"; return false; }
    DesktopGlobalConfigRequirements remaining;
    for (const auto& record : journal.records()) {
        if (!record.isActive() || record.undo.backend != MutationBackend::Desktop) continue;
        const auto* scalar = std::get_if<UndoRestoreDesktopScalar>(&record.undo.payload);
        if (std::holds_alternative<UndoOwnDesktopArtifact>(record.undo.payload)) continue;
        if (!scalar) { error = "desktop journal payload mismatch"; return false; }
        if (scalar->desktop != "GNOME") continue;
        const auto* description = settingFor(scalar->setting);
        if (!description || record.policy != gnomeScalarPolicy || record.resource != "GNOME" + scalar->setting) {
            error = "GNOME release journal identity conflict"; return false;
        }
        std::set<PolicyRef> owners(scalar->owners.begin(), scalar->owners.end());
        owners.erase(owner);
        if (owners.empty()) continue;
        const auto prefix = std::string(description->key) + "=";
        const auto line = trimmed(scalar->appliedLine);
        if (line.compare(0, prefix.size(), prefix) != 0 ||
            !remaining.emplace(GlobalDesktopConfigKey{scalar->setting},
                GlobalDesktopConfigValue{line.substr(prefix.size()), std::move(owners)}).second) {
            error = "GNOME release scalar identity conflict"; return false;
        }
    }
    return preview ? preflightJournaled(remaining, journal, error) : reconcileJournaled(remaining, journal, error);
}

bool GnomeSystemBackend::reconcileJournaled(const DesktopGlobalConfigRequirements& required,
                                           fic::rollback::MutationJournal& journal,
                                           std::string& error) {
    ExclusivePidLock lock(options_.lockPath.string(), "", false);
    if (!lock.acquire()) { error = "cannot acquire FIC desktop-config lock"; return false; }
    if (!required.empty()) {
        for (const auto& record : journal.records()) {
            const auto* artifact = std::get_if<UndoOwnDesktopArtifact>(&record.undo.payload);
            if (record.isActive() && artifact && artifact->phase == "release") {
                if (!reconcileJournaled({}, journal, error)) return false;
                break;
            }
        }
    }
    if (!required.empty() && (!preflightJournaled(required, journal, error) ||
        !ensureGnomeLayout(journal, options_, dependencies_, error))) return false;
    GnomeJournalInputs inputs;
    if (!gnomeInputs(required, journal, options_, inputs, error)) return false;
    if (inputs.inactive) return releaseGnomeLayout(journal, options_, dependencies_, error);
    std::filesystem::path dconf, gsettings;
    if (!dependencies_.resolveExecutable(fic::platform::ExecutableId::Dconf, dconf, error) ||
        !dependencies_.resolveExecutable(fic::platform::ExecutableId::Gsettings, gsettings, error)) return false;
    std::string nativeBefore;
    if (!compileGnomeSources(inputs.cacheSources, options_, dependencies_, dconf, nativeBefore, error) ||
        !proveGnomeCache(inputs, nativeBefore, error)) return false;
    std::vector<MutationRecord> plans;
    for (const auto& [key, value] : required) {
        const auto existing = inputs.active.find(key.setting);
        if (existing != inputs.active.end() &&
            std::get<UndoRestoreDesktopScalar>(existing->second.undo.payload).phase == "release") {
            auto reduced = required;
            for (const auto& [pendingKey, pending] : inputs.active)
                if (std::get<UndoRestoreDesktopScalar>(pending.undo.payload).phase == "release") reduced.erase({pendingKey});
            if (!reconcileJournaled(reduced, journal, error)) return false;
            return reconcileJournaled(required, journal, error);
        }
        MutationRecord record;
        UndoRestoreDesktopScalar scalar;
        const auto& setting = *settingFor(key.setting);
        GnomeLine valueLine, lockLine;
        gnomeProjection(inputs.files.at(options_.keyfileName).content, setting, false, valueLine, error);
        gnomeProjection(inputs.files.at("locks/" + options_.lockfileName).content, setting, true, lockLine, error);
        if (existing != inputs.active.end()) {
            record = existing->second;
            scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
            bool marked = false;
            gnomeMarkerProof(inputs.files.at(options_.keyfileName).content, valueLine, record, false, marked, error);
            if (marked) {
                const auto desiredLine = std::string(setting.key) + "=" + value.value + "\n";
                if (valueLine.raw != desiredLine) scalar.previousAppliedLine = valueLine.raw;
                else scalar.previousAppliedLine.reset();
            }
        } else {
            record.policy = gnomeScalarPolicy; record.resource = "GNOME" + key.setting;
            scalar.desktop = "GNOME"; scalar.setting = key.setting;
            scalar.originalLine = valueLine.raw; scalar.originalLockLine = lockLine.raw;
        }
        scalar.appliedLine = std::string(setting.key) + "=" + value.value + "\n";
        scalar.owners.assign(value.owners.begin(), value.owners.end()); scalar.phase = "ensure";
        record.status = MutationStatus::Prepared; record.undo = {MutationBackend::Desktop, scalar};
        plans.push_back(std::move(record));
    }
    for (const auto& [key, existing] : inputs.active) {
        if (required.count({key})) continue;
        auto record = existing;
        auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        scalar.phase = "release"; scalar.owners.clear(); record.status = MutationStatus::Prepared;
        plans.push_back(std::move(record));
    }
    auto targetFiles = inputs.files;
    // ID zero is only a compilation placeholder in a comment. Native dconf
    // ignores ownership comments; real IDs are allocated durably below.
    for (const auto& record : plans) {
        const auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        const auto& setting = *settingFor(scalar.setting);
        patchGnomeProjection(targetFiles.at(options_.keyfileName).content, setting, false, record, scalar.phase == "release");
        patchGnomeProjection(targetFiles.at("locks/" + options_.lockfileName).content, setting, true, record, scalar.phase == "release");
    }
    std::string nativeTarget;
    if (!compileGnomeSources(targetFiles, options_, dependencies_, dconf, nativeTarget, error)) return false;
    const auto beforeDigest = ContentDigest::sha256Hex(inputs.compiled.content);
    const auto targetDigest = ContentDigest::sha256Hex(nativeTarget);
    if (beforeDigest.empty() || targetDigest.empty()) { error = "GNOME native digest failed"; return false; }
    for (auto& record : plans) {
        auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        scalar.compiledBeforeDigest = beforeDigest; scalar.compiledTargetDigest = targetDigest;
        MutationId id = 0;
        if (!journal.prepareMutation(record, id, error)) return false;
        record.id = id;
    }
    targetFiles = inputs.files;
    for (const auto& record : plans) {
        const auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        const auto& setting = *settingFor(scalar.setting);
        patchGnomeProjection(targetFiles.at(options_.keyfileName).content, setting, false, record, scalar.phase == "release");
        patchGnomeProjection(targetFiles.at("locks/" + options_.lockfileName).content, setting, true, record, scalar.phase == "release");
    }
    // Inventory and profile proof bracket each publication. This captures all
    // foreign source filenames as well as their bytes/metadata/identity.
    const auto proveFiles = [&](const std::map<std::string, AtomicTargetState>& expected) {
        std::map<std::string, AtomicTargetState> current;
        if (!gnomeSourceInventory(options_, current, error)) return false;
        if (current.size() != expected.size()) { error = "GNOME source directory membership changed"; return false; }
        for (const auto& [name, state] : expected) {
            if (!current.count(name)) { error = "GNOME source file disappeared: " + name; return false; }
            if (!AtomicFileWriter::targetStateMatches((inputs.sourceDirectory / name).string(), state, &error)) return false;
        }
        return AtomicFileWriter::targetStateMatches(options_.profilePath.string(), inputs.profile, &error);
    };
    if (!proveFiles(inputs.files)) return false;
    auto published = inputs.files;
    for (const std::string relative : {options_.keyfileName, "locks/" + options_.lockfileName}) {
        if (!proveFiles(published) || !casGnome(inputs.sourceDirectory / relative, published.at(relative),
                targetFiles.at(relative).content, error)) return false;
        if (!captureGnomeFile(inputs.sourceDirectory / relative, options_, published.at(relative), error) ||
            published.at(relative).content != targetFiles.at(relative).content) return false;
    }
    // Native update operates on an isolated copy of fic.d, so it cannot
    // regenerate unrelated system databases. Only its verified fic output is
    // published into the real DB directory through the existing snapshot CAS.
    std::string updatedNative;
    if (!proveFiles(published) ||
        !compileGnomeSources(published, options_, dependencies_, dconf, updatedNative, error, true)) return false;
    if (updatedNative != nativeTarget) { error = "dconf update disagrees with native compilation"; return false; }
    if (!proveFiles(published) || !casGnome(options_.databaseRoot / options_.databaseName,
            inputs.compiled, updatedNative, error)) return false;
    if (!proveFiles(published)) return false;
    AtomicTargetState compiled;
    if (!captureGnomeFile(options_.databaseRoot / options_.databaseName, options_, compiled, error) ||
        compiled.content != nativeTarget) { if (error.empty()) error = "GNOME compiled bytes do not match native sources"; return false; }
    DesktopManagedSettings wanted;
    for (const auto& [key, value] : required) wanted.emplace(key, value.value);
    if (!verifyWithExecutable(wanted, gsettings, error)) return false;
    for (const auto& record : plans) {
        const auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        if (scalar.phase != "release") continue;
        const auto& setting = *settingFor(scalar.setting);
        for (const auto* operation : {"get", "writable"}) {
            const auto result = dependencies_.execute(gsettings,
                {operation, setting.schema, setting.key}, commandOptions(options_.profilePath));
            if (!result.success()) { error = processFailure("GNOME release effective read", result); return false; }
            // Other databases/foreign locks may legitimately keep this value
            // or keep it non-writable. Release proves our projection is gone,
            // not that a foreign policy became writable or changed its value.
            if ((std::string(operation) == "get" && !validValue(setting, trimmed(result.standardOutput))) ||
                (std::string(operation) == "writable" && trimmed(result.standardOutput) != "true" &&
                 trimmed(result.standardOutput) != "false")) { error = "invalid GNOME release effective state"; return false; }
        }
    }
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            (options_.databaseRoot / options_.databaseName).string(), compiled, &error)) return false;
    for (const auto& [name, state] : published)
        if (!AtomicFileWriter::ensureTargetDurableIfCurrentState((inputs.sourceDirectory / name).string(), state, &error)) return false;
    if (!proveFiles(published)) return false;
    if (!AtomicFileWriter::targetStateMatches((options_.databaseRoot / options_.databaseName).string(), compiled, &error)) return false;
    for (auto& record : plans) {
        auto& scalar = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        if (scalar.phase == "release") {
            if (!journal.setStatus(record.id, MutationStatus::RolledBack, error)) return false;
        } else {
            scalar.hadApplied = true; scalar.previousAppliedLine.reset();
            MutationId id = 0;
            if (!journal.prepareMutation(record, id, error) || !journal.setStatus(id, MutationStatus::Applied, error)) return false;
        }
    }
    if (required.empty()) return releaseGnomeLayout(journal, options_, dependencies_, error);
    error.clear(); return true;
}
