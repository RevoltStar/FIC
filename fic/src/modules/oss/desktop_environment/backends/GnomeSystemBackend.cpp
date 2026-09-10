#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <atomic>
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

bool writeAll(int fd, const std::string& content) {
    size_t offset = 0;
    while (offset < content.size()) {
        const ssize_t count = ::write(fd, content.data() + offset,
                                      content.size() - offset);
        if (count > 0) { offset += static_cast<size_t>(count); continue; }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool atomicWrite(const std::filesystem::path& path, const std::string& content,
                 const GnomeSystemBackendOptions& options,
                 std::string& error) {
    UniqueFd parent;
    if (!openDirectory(path.parent_path(), false, options, parent, error))
        return false;
    struct stat oldInfo {};
    if (::fstatat(parent.get(), path.filename().c_str(), &oldInfo,
                  AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(oldInfo.st_mode) || oldInfo.st_uid != options.trustedOwner ||
            (oldInfo.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            error = "refusing to replace unsafe managed file: " + path.string();
            return false;
        }
    } else if (errno != ENOENT) {
        error = "cannot inspect managed file " + path.string() + ": " + systemError();
        return false;
    }
    static std::atomic<unsigned long> sequence{0};
    const std::string temp = "." + path.filename().string() + ".tmp." +
        std::to_string(::getpid()) + "." + std::to_string(sequence++);
    UniqueFd file(::openat(parent.get(), temp.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (file.get() < 0) {
        error = "cannot create temporary file for " + path.string() + ": " +
            systemError();
        return false;
    }
    auto cleanup = [&] { ::unlinkat(parent.get(), temp.c_str(), 0); };
    if (::fchown(file.get(), options.trustedOwner, options.trustedGroup) != 0 ||
        ::fchmod(file.get(), 0644) != 0 || !writeAll(file.get(), content) ||
        ::fsync(file.get()) != 0) {
        error = "cannot write managed file " + path.string() + ": " + systemError();
        cleanup();
        return false;
    }
    if (::renameat(parent.get(), temp.c_str(), parent.get(),
                   path.filename().c_str()) != 0) {
        error = "cannot atomically replace " + path.string() + ": " + systemError();
        cleanup();
        return false;
    }
    if (::fsync(parent.get()) != 0) {
        error = "cannot fsync directory for " + path.string() + ": " + systemError();
        return false;
    }
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

std::string serializeKeyfile(const Keyfile& keyfile) {
    std::string result;
    for (const auto& [group, values] : keyfile) {
        if (!result.empty()) result += '\n';
        result += "[" + group + "]\n";
        for (const auto& [key, value] : values)
            result += key + "=" + value + "\n";
    }
    return result;
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

std::string serializeLocks(const std::set<std::string>& locks) {
    std::string result;
    for (const auto& lock : locks) result += lock + "\n";
    return result;
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

std::string serializeProfile(const Profile& profile) {
    std::string result;
    for (const auto& entry : profile.entries) result += entry.raw + "\n";
    return result;
}

// Размещает system-db:fic сразу после первого writable-источника, перед всеми
// read-only базами. Перемещается/добавляется только строка FIC; порядок и
// содержимое чужих строк не меняются.
void ensureFicEntry(Profile& profile) {
    std::vector<ProfileEntry> kept;
    kept.reserve(profile.entries.size() + 1);
    for (auto& entry : profile.entries)
        if (!entry.fic) kept.push_back(entry);
    const auto writable = std::find_if(
        kept.begin(), kept.end(), [](const ProfileEntry& entry) {
            return entry.isSource && entry.writable;
        });
    // parseProfile гарантирует наличие writable-источника первым источником.
    ProfileEntry fic;
    fic.raw = "system-db:fic";
    fic.isSource = true;
    kept.insert(std::next(writable), fic);
    profile.entries = std::move(kept);
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
    : dependencies_(std::move(dependencies)), options_(std::move(options)) {}

DesktopEnvironmentKind GnomeSystemBackend::desktop() const {
    return DesktopEnvironmentKind::Gnome;
}

std::string GnomeSystemBackend::backendName() const { return "gnome"; }

bool GnomeSystemBackend::ensureManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) { error.clear(); return true; }

    const std::regex safeName("[A-Za-z0-9_][A-Za-z0-9_.-]*");
    if (!std::regex_match(options_.databaseName, safeName) ||
        !std::regex_match(options_.keyfileName, safeName) ||
        !std::regex_match(options_.lockfileName, safeName)) {
        error = "unsafe GNOME dconf database or fragment name";
        return false;
    }

    Keyfile keyfile;
    std::set<std::string> locks;
    for (const auto& [key, value] : required) {
        const auto* description = settingFor(key.setting);
        if (description == nullptr || !validValue(*description, value)) {
            error = description == nullptr
                ? "unsupported GNOME dconf key: " + key.setting
                : "invalid value for GNOME dconf key " + key.setting + ": " + value;
            return false;
        }
    }

    const auto keyfilePath = options_.databaseRoot /
        (options_.databaseName + ".d") / options_.keyfileName;
    const auto lockfilePath = options_.databaseRoot /
        (options_.databaseName + ".d") / "locks" / options_.lockfileName;
    bool profileExists = false, keyfileExists = false, lockfileExists = false;
    std::string profileText, keyfileText, lockfileText;
    if (!readOptionalFile(options_.profilePath, options_, profileExists,
                          profileText, error) ||
        !readOptionalFile(keyfilePath, options_, keyfileExists,
                          keyfileText, error) ||
        !readOptionalFile(lockfilePath, options_, lockfileExists,
                          lockfileText, error)) return false;
    if (!keyfileExists) keyfileText.clear();
    if (!lockfileExists) lockfileText.clear();
    if (!parseKeyfile(keyfileText, keyfile, error) ||
        !parseLocks(lockfileText, locks, error)) return false;

    Profile profile;
    if (!profileExists) {
        ProfileEntry userDb;
        userDb.raw = "user-db:user";
        userDb.isSource = true;
        userDb.writable = true;
        profile.entries = {userDb};
    } else if (!parseProfile(profileText, profile, error)) {
        return false;
    }
    for (const auto& [key, value] : required) {
        const auto& setting = *settingFor(key.setting);
        keyfile[setting.group][setting.key] = value;
        locks.insert(key.setting);
    }
    ensureFicEntry(profile);
    const std::string finalProfile = serializeProfile(profile);
    const std::string finalKeyfile = serializeKeyfile(keyfile);
    const std::string finalLocks = serializeLocks(locks);

    std::filesystem::path dconf, gsettings;
    if (!dependencies_.resolveExecutable(fic::platform::ExecutableId::Dconf,
                                         dconf, error)) {
        error = "cannot resolve dconf: " + error;
        return false;
    }
    if (!dependencies_.resolveExecutable(fic::platform::ExecutableId::Gsettings,
                                         gsettings, error)) {
        error = "cannot resolve gsettings: " + error;
        return false;
    }

    UniqueFd ignored;
    const auto profileDir = options_.profilePath.parent_path();
    const auto keyfileDir = keyfilePath.parent_path();
    const auto lockfileDir = lockfilePath.parent_path();
    if (!openDirectory(profileDir, true, options_, ignored, error) ||
        !openDirectory(options_.databaseRoot, true, options_, ignored, error) ||
        !openDirectory(keyfileDir, true, options_, ignored, error) ||
        !openDirectory(lockfileDir, true, options_, ignored, error))
        return false;

    // Persistent state is only usable if ordinary desktop users can actually
    // reach it. Existing foreign parent directories are validated, never
    // re-permissioned; an inaccessible one fails closed. FIC-created public
    // directories were forced to 0755 above.
    if (!pathTraversableByOrdinaryUsers(profileDir, options_, error) ||
        !pathTraversableByOrdinaryUsers(options_.databaseRoot, options_,
                                       error) ||
        !pathTraversableByOrdinaryUsers(keyfileDir, options_, error) ||
        !pathTraversableByOrdinaryUsers(lockfileDir, options_, error))
        return false;

    const bool profileChanged = !profileExists || profileText != finalProfile;
    const bool keyfileChanged = !keyfileExists || keyfileText != finalKeyfile;
    const bool locksChanged = !lockfileExists || lockfileText != finalLocks;
    if ((keyfileChanged && !atomicWrite(keyfilePath, finalKeyfile,
                                        options_, error)) ||
        (locksChanged && !atomicWrite(lockfilePath, finalLocks,
                                      options_, error)) ||
        (profileChanged && !atomicWrite(options_.profilePath, finalProfile,
                                        options_, error))) return false;

    bool compiledExists = false;
    std::string compiled;
    const auto compiledPath = options_.databaseRoot / options_.databaseName;
    if (!readOptionalFile(compiledPath, options_, compiledExists,
                          compiled, error)) return false;

    bool updateNeeded = profileChanged || keyfileChanged || locksChanged ||
        !compiledExists;
    if (!updateNeeded) {
        std::string verifyError;
        if (!verifyWithExecutable(required, gsettings, verifyError)) {
            // dconf update recompiles only databases whose source directory is
            // newer. Reinstall the already validated FIC source atomically so
            // one bounded retry can repair a stale/corrupt compiled database.
            if (!atomicWrite(keyfilePath, finalKeyfile, options_, error))
                return false;
            updateNeeded = true;
        }
    }
    if (updateNeeded) {
        // dconf update must not inherit the daemon's restrictive umask
        // (fic.service UMask=0027): the compiled database is world-readable
        // system state. The mask applies to the child process only.
        ProcessOptions updateOptions = commandOptions();
        updateOptions.childUmask = 0022;
        const ProcessResult result = dependencies_.execute(
            dconf, {"update"}, updateOptions);
        if (!result.success()) {
            error = processFailure("dconf update", result);
            return false;
        }
    }
    // The compiled database is what user sessions actually read; root-only
    // readability or a restrictive compiled mode hides the policy from
    // ordinary users and must not count as verified.
    if (!fileAccessibleToOrdinaryUsers(compiledPath, options_, error)) {
        error = "compiled GNOME FIC dconf database is not readable by ordinary "
            "users: " + error;
        return false;
    }
    if (!verifyWithExecutable(required, gsettings, error)) {
        error = "GNOME state is not effective after dconf update: " + error;
        return false;
    }
    error.clear();
    return true;
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
