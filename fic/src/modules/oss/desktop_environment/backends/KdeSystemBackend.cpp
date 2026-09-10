#include "modules/oss/desktop_environment/backends/KdeSystemBackend.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

struct SettingDescription {
    const char* setting;
    const char* key;
};

constexpr std::array<SettingDescription, 5> kSettings{{
    {"kscreenlockerrc/Daemon/Autolock", "Autolock"},
    {"kscreenlockerrc/Daemon/Timeout", "Timeout"},
    {"kscreenlockerrc/Daemon/Lock", "Lock"},
    {"kscreenlockerrc/Daemon/LockGrace", "LockGrace"},
    {"kscreenlockerrc/Daemon/RequirePassword", "RequirePassword"},
}};

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

class TemporaryTree {
public:
    TemporaryTree(const std::filesystem::path& parent, std::string& error) {
        std::string pattern =
            (parent / "fic-kconfig-verify-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        char* created = ::mkdtemp(writable.data());
        if (created == nullptr) {
            error = "cannot create temporary KDE verification directory: " +
                std::string(std::strerror(errno));
            return;
        }
        root_ = created;
    }
    ~TemporaryTree() {
        if (!root_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(root_, ignored);
        }
    }
    bool valid() const { return !root_.empty(); }
    const std::filesystem::path& root() const { return root_; }
private:
    std::filesystem::path root_;
};

std::string systemError() { return std::strerror(errno); }

std::string trim(std::string value) {
    const auto whitespace = [](unsigned char ch) {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
    };
    while (!value.empty() &&
           whitespace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    std::size_t first = 0;
    while (first < value.size() &&
           whitespace(static_cast<unsigned char>(value[first])))
        ++first;
    return value.substr(first);
}

const SettingDescription* settingFor(const std::string& setting) {
    for (const auto& candidate : kSettings)
        if (setting == candidate.setting) return &candidate;
    return nullptr;
}

bool validRequiredValue(const SettingDescription& setting,
                        const std::string& value) {
    const std::string key = setting.key;
    if (key == "Timeout") {
        if (value.empty() ||
            !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
                return std::isdigit(ch) != 0;
            }))
            return false;
        try {
            const int timeout = std::stoi(value);
            return timeout >= 1 && timeout <= 20;
        } catch (...) {
            return false;
        }
    }
    if (key == "LockGrace") return value == "0";
    return value == "true";
}

bool relativeComponents(const std::filesystem::path& path,
                        const KdeSystemBackendOptions& options,
                        std::vector<std::string>& components,
                        std::string& error) {
    const auto root = options.trustedRoot.lexically_normal();
    const auto target = path.lexically_normal();
    if (!root.is_absolute() || !target.is_absolute()) {
        error = "KDE system config paths must be absolute";
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

bool validateDirectoryFd(int fd, const std::filesystem::path& path,
                         const KdeSystemBackendOptions& options,
                         bool ordinaryTraversal, std::string& error) {
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
    if (ordinaryTraversal && (info.st_mode & S_IXOTH) == 0) {
        error = "KDE config directory is not traversable by ordinary users: " +
            path.string();
        return false;
    }
    return true;
}

bool openDirectory(const std::filesystem::path& path, bool create,
                   bool ordinaryTraversal,
                   const KdeSystemBackendOptions& options,
                   UniqueFd& result, std::string& error,
                   bool* missing = nullptr) {
    if (missing != nullptr) *missing = false;
    std::vector<std::string> components;
    if (!relativeComponents(path, options, components, error)) return false;
    UniqueFd current(::open(options.trustedRoot.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    if (current.get() < 0) {
        error = "cannot securely open trusted root " +
            options.trustedRoot.string() + ": " + systemError();
        return false;
    }
    if (!validateDirectoryFd(current.get(), options.trustedRoot, options,
                             ordinaryTraversal, error))
        return false;

    std::filesystem::path traversed = options.trustedRoot;
    for (const auto& component : components) {
        traversed /= component;
        bool createdHere = false;
        int next = ::openat(current.get(), component.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT && create) {
            if (::mkdirat(current.get(), component.c_str(), 0755) == 0) {
                createdHere = true;
            } else if (errno != EEXIST) {
                error = "cannot create trusted directory " +
                    traversed.string() + ": " + systemError();
                return false;
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
        if (!validateDirectoryFd(opened.get(), traversed, options,
                                 ordinaryTraversal, error))
            return false;
        if (createdHere && ::fchmod(opened.get(), 0755) != 0) {
            error = "cannot set mode on created directory " +
                traversed.string() + ": " + systemError();
            return false;
        }
        current = std::move(opened);
    }
    result = std::move(current);
    return true;
}

bool readOptionalFile(const std::filesystem::path& path,
                      const KdeSystemBackendOptions& options,
                      bool& exists, std::string& content, std::string& error) {
    exists = false;
    content.clear();
    UniqueFd parent;
    bool parentMissing = false;
    if (!openDirectory(path.parent_path(), false, false, options, parent, error,
                       &parentMissing)) {
        if (parentMissing) return true;
        return false;
    }
    UniqueFd file(::openat(parent.get(), path.filename().c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) {
        if (errno == ENOENT) {
            error.clear();
            return true;
        }
        error = "cannot securely open " + path.string() + ": " + systemError();
        return false;
    }
    struct stat info {};
    if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != options.trustedOwner ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        error = "unsafe KDE system config file: " + path.string();
        return false;
    }
    char buffer[8192];
    for (;;) {
        const ssize_t count = ::read(file.get(), buffer, sizeof(buffer));
        if (count > 0) {
            content.append(buffer, static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) break;
        if (errno == EINTR) continue;
        error = "cannot read " + path.string() + ": " + systemError();
        return false;
    }
    exists = true;
    error.clear();
    return true;
}

bool fileAccessibleToOrdinaryUsers(
    const std::filesystem::path& path,
    const KdeSystemBackendOptions& options, std::string& error) {
    UniqueFd parent;
    if (!openDirectory(path.parent_path(), false, true, options, parent, error))
        return false;
    struct stat info {};
    if (::fstatat(parent.get(), path.filename().c_str(), &info,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        error = "cannot inspect KDE system config file " + path.string() +
            ": " + systemError();
        return false;
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != options.trustedOwner ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (info.st_mode & S_IROTH) == 0) {
        error = "KDE system config file is not readable by ordinary users: " +
            path.string();
        return false;
    }
    return true;
}

bool writeAll(int fd, const std::string& content) {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const ssize_t count = ::write(
            fd, content.data() + offset, content.size() - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool atomicWrite(const std::filesystem::path& path,
                 const std::string& content,
                 const KdeSystemBackendOptions& options,
                 std::string& error) {
    UniqueFd parent;
    if (!openDirectory(path.parent_path(), false, false, options, parent, error))
        return false;
    struct stat oldInfo {};
    if (::fstatat(parent.get(), path.filename().c_str(), &oldInfo,
                  AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(oldInfo.st_mode) ||
            oldInfo.st_uid != options.trustedOwner ||
            (oldInfo.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            error = "refusing to replace unsafe KDE system config: " +
                path.string();
            return false;
        }
    } else if (errno != ENOENT) {
        error = "cannot inspect KDE system config " + path.string() + ": " +
            systemError();
        return false;
    }
    static std::atomic<unsigned long> sequence{0};
    const std::string temporary = "." + path.filename().string() + ".tmp." +
        std::to_string(::getpid()) + "." + std::to_string(sequence++);
    UniqueFd file(::openat(parent.get(), temporary.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (file.get() < 0) {
        error = "cannot create temporary KDE system config: " + systemError();
        return false;
    }
    const auto cleanup = [&] {
        ::unlinkat(parent.get(), temporary.c_str(), 0);
    };
    if (::fchown(file.get(), options.trustedOwner, options.trustedGroup) != 0 ||
        ::fchmod(file.get(), 0644) != 0 ||
        !writeAll(file.get(), content) || ::fsync(file.get()) != 0) {
        error = "cannot write KDE system config " + path.string() + ": " +
            systemError();
        cleanup();
        return false;
    }
    if (::renameat(parent.get(), temporary.c_str(), parent.get(),
                   path.filename().c_str()) != 0) {
        error = "cannot atomically replace KDE system config " +
            path.string() + ": " + systemError();
        cleanup();
        return false;
    }
    if (::fsync(parent.get()) != 0) {
        error = "cannot fsync KDE system config directory: " + systemError();
        return false;
    }
    return true;
}

std::vector<std::string> splitLines(const std::string& content) {
    std::vector<std::string> lines;
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

bool groupHeader(const std::string& line, std::string& group) {
    const std::string value = trim(line);
    if (value.size() < 2 || value.front() != '[' || value.back() != ']')
        return false;
    group = value.substr(1, value.size() - 2);
    return true;
}

const SettingDescription* managedAssignment(const std::string& line,
                                            std::string& left,
                                            std::string& value) {
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos) return nullptr;
    left = trim(line.substr(0, equals));
    value = trim(line.substr(equals + 1));
    for (const auto& setting : kSettings) {
        const std::string key = setting.key;
        if (left == key ||
            (left.size() > key.size() && left.compare(0, key.size(), key) == 0 &&
             left[key.size()] == '['))
            return &setting;
    }
    return nullptr;
}

bool validateManagedSyntax(const std::string& content,
                           const std::filesystem::path& path,
                           std::string& error) {
    bool inDaemon = false;
    bool sawDaemon = false;
    std::set<std::string> managedKeys;
    for (const auto& line : splitLines(content)) {
        std::string group;
        if (groupHeader(line, group)) {
            if (group.rfind("Daemon][", 0) == 0) {
                error = "group-wide immutability is unsupported in " +
                    path.string();
                return false;
            }
            if (group == "Daemon") {
                if (sawDaemon) {
                    error = "ambiguous duplicate [Daemon] group in " +
                        path.string();
                    return false;
                }
                sawDaemon = true;
                inDaemon = true;
            } else {
                inDaemon = false;
            }
            continue;
        }
        if (!inDaemon) continue;
        std::string left;
        std::string value;
        const auto* setting = managedAssignment(line, left, value);
        if (setting == nullptr) continue;
        const std::string key = setting->key;
        if (left != key && left != key + "[$i]") {
            error = "unsupported modifier on managed KDE key " + key +
                " in " + path.string();
            return false;
        }
        if (!managedKeys.insert(key).second) {
            error = "ambiguous duplicate managed KDE key " + key +
                " in " + path.string();
            return false;
        }
    }
    return true;
}

std::map<std::string, std::string> valuesByKey(
    const DesktopManagedSettings& required) {
    std::map<std::string, std::string> values;
    for (const auto& [physical, value] : required)
        values.emplace(settingFor(physical.setting)->key, value);
    return values;
}

std::string mergeManagedSettings(const std::string& content,
                                 const DesktopManagedSettings& required) {
    const auto requiredValues = valuesByKey(required);
    const auto lines = splitLines(content);
    std::vector<std::string> output;
    std::set<std::string> emitted;
    bool inDaemon = false;
    bool sawDaemon = false;
    bool leftFirstDaemon = false;
    const auto emitMissing = [&] {
        for (const auto& [key, value] : requiredValues) {
            if (emitted.insert(key).second)
                output.push_back(key + "[$i]=" + value);
        }
    };

    for (const auto& line : lines) {
        std::string group;
        if (groupHeader(line, group)) {
            if (inDaemon && !leftFirstDaemon) {
                emitMissing();
                leftFirstDaemon = true;
            }
            inDaemon = group == "Daemon";
            sawDaemon = sawDaemon || inDaemon;
            output.push_back(line);
            continue;
        }
        if (inDaemon) {
            std::string left;
            std::string value;
            const auto* setting = managedAssignment(line, left, value);
            if (setting != nullptr &&
                requiredValues.find(setting->key) != requiredValues.end()) {
                if (emitted.insert(setting->key).second) {
                    output.push_back(
                        std::string(setting->key) + "[$i]=" +
                        requiredValues.at(setting->key));
                }
                continue;
            }
        }
        output.push_back(line);
    }
    if (inDaemon && !leftFirstDaemon) {
        emitMissing();
    } else if (!sawDaemon) {
        if (!output.empty() && !output.back().empty()) output.emplace_back();
        output.push_back("[Daemon]");
        emitMissing();
    }
    std::ostringstream serialized;
    for (const auto& line : output) serialized << line << '\n';
    return serialized.str();
}

bool verifyManagedContent(const std::string& content,
                          const DesktopManagedSettings& required,
                          std::string& error) {
    const auto requiredValues = valuesByKey(required);
    std::map<std::string, int> counts;
    bool inDaemon = false;
    for (const auto& line : splitLines(content)) {
        std::string group;
        if (groupHeader(line, group)) {
            inDaemon = group == "Daemon";
            continue;
        }
        if (!inDaemon) continue;
        std::string left;
        std::string value;
        const auto* setting = managedAssignment(line, left, value);
        if (setting == nullptr ||
            requiredValues.find(setting->key) == requiredValues.end())
            continue;
        const std::string expectedLeft = std::string(setting->key) + "[$i]";
        if (left != expectedLeft || value != requiredValues.at(setting->key)) {
            error = "KDE setting is not immutable with the required value: " +
                std::string(setting->setting);
            return false;
        }
        ++counts[setting->key];
    }
    for (const auto& [key, value] : requiredValues) {
        if (counts[key] != 1) {
            error = "KDE immutable setting is missing or duplicated: " + key;
            return false;
        }
    }
    return true;
}

bool writePrivateFile(const std::filesystem::path& path,
                      const std::string& content, std::string& error) {
    UniqueFd file(::open(path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (file.get() < 0 || !writeAll(file.get(), content) ||
        ::fsync(file.get()) != 0) {
        error = "cannot create conflicting KDE user config: " + systemError();
        return false;
    }
    return true;
}

std::string conflictingUserConfig() {
    return "[Daemon]\n"
           "Autolock=false\n"
           "Timeout=999\n"
           "Lock=false\n"
           "LockGrace=999\n"
           "RequirePassword=false\n";
}

std::string conflictingImmutableDefaults() {
    return "[Daemon]\n"
           "Autolock[$i]=false\n"
           "Timeout[$i]=30\n"
           "Lock[$i]=false\n"
           "LockGrace[$i]=30\n"
           "RequirePassword[$i]=false\n";
}

ProcessOptions verificationOptions(
    const std::filesystem::path& root,
    const std::vector<std::filesystem::path>& systemConfigDirectories) {
    std::string configDirs = (root / "user" / "kdedefaults").string();
    for (const auto& directory : systemConfigDirectories)
        configDirs += ":" + directory.string();
    ProcessOptions options;
    options.timeout = std::chrono::seconds(10);
    options.maxOutputBytes = 64 * 1024;
    options.clearEnvironment = true;
    options.environment = {
        {"HOME", (root / "home").string()},
        {"XDG_CONFIG_HOME", (root / "user").string()},
        {"XDG_CONFIG_DIRS", configDirs},
        {"LC_ALL", "C"},
        {"LANG", "C"},
    };
    return options;
}

bool validateVerificationHierarchy(const KdeSystemBackendOptions& options,
                                   std::string& error) {
    if (options.systemConfigDirs.empty()) {
        error = "KDE system configuration hierarchy is empty";
        return false;
    }
    std::set<std::filesystem::path> unique;
    for (const auto& directory : options.systemConfigDirs) {
        if (!directory.is_absolute() || directory != directory.lexically_normal()) {
            error = "KDE system configuration directory must be absolute and normalized";
            return false;
        }
        if (!unique.insert(directory).second) {
            error = "KDE system configuration hierarchy contains a duplicate";
            return false;
        }
    }
    const auto configParent = options.configPath.parent_path().lexically_normal();
    const auto globalsParent = options.globalsPath.parent_path().lexically_normal();
    if (configParent != globalsParent) {
        error = "managed KDE configuration files must share one directory";
        return false;
    }
    if (unique.count(configParent) == 0 || unique.count(globalsParent) == 0) {
        error = "managed KDE configuration files are outside the verification hierarchy";
        return false;
    }
    return true;
}

bool parseVerifierOutput(const std::string& output,
                         const DesktopManagedSettings& required,
                         std::string& error) {
    const auto lines = splitLines(output);
    if (lines.size() != kSettings.size() + 1 ||
        lines.front() != "FIC-KCONFIG-V1") {
        error = "KDE verifier returned an invalid protocol response";
        return false;
    }
    const auto expected = valuesByKey(required);
    std::set<std::string> seen;
    for (std::size_t index = 1; index < lines.size(); ++index) {
        const auto first = lines[index].find('\t');
        const auto second = first == std::string::npos
            ? std::string::npos : lines[index].find('\t', first + 1);
        if (first == std::string::npos || second == std::string::npos ||
            lines[index].find('\t', second + 1) != std::string::npos) {
            error = "KDE verifier returned a malformed setting record";
            return false;
        }
        const std::string key = lines[index].substr(0, first);
        const std::string value = lines[index].substr(first + 1, second - first - 1);
        const std::string immutable = lines[index].substr(second + 1);
        const auto found = expected.find(key);
        if (found == expected.end() || !seen.insert(key).second) {
            error = "KDE verifier returned an unexpected or duplicate setting: " + key;
            return false;
        }
        if (value != found->second || immutable != "1") {
            error = "KDE effective setting is not immutable with the required value: " + key;
            return false;
        }
    }
    if (seen.size() != expected.size()) {
        error = "KDE verifier omitted a required setting";
        return false;
    }
    return true;
}

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) return result.error;
    if (result.timedOut) return "timed out";
    if (result.outputLimitExceeded) return "exceeded output limit";
    return "exited with code " + std::to_string(result.exitCode) +
        (result.standardError.empty() ? "" :
         ": " + trim(result.standardError));
}

KdeSystemBackendOptions withPlatformConfig(
    KdeSystemBackendOptions options,
    const fic::platform::KdePlatformConfig& platformConfig) {
    options.systemConfigDirs = platformConfig.systemConfigDirs;
    return options;
}

} // namespace

KdeSystemBackend::KdeSystemBackend(
    const fic::platform::PlatformExecutableResolver& executables,
    const fic::platform::KdePlatformConfig& platformConfig,
    KdeSystemBackendOptions options)
    : KdeSystemBackend(
          { [&executables](fic::platform::ExecutableId id,
                           std::filesystem::path& path, std::string& error) {
                return executables.resolve(id, path, error);
            },
            [](const std::filesystem::path& path,
               const std::vector<std::string>& arguments,
               const ProcessOptions& options) {
                return VerifiedProcessExecutor::execute(
                    path.string(), arguments, options);
            } },
          withPlatformConfig(std::move(options), platformConfig)) {}

KdeSystemBackend::KdeSystemBackend(
    KdeSystemBackendDependencies dependencies,
    KdeSystemBackendOptions options)
    : dependencies_(std::move(dependencies)),
      options_(std::move(options)) {}

DesktopEnvironmentKind KdeSystemBackend::desktop() const {
    return DesktopEnvironmentKind::Kde;
}

std::string KdeSystemBackend::backendName() const { return "kde"; }

bool KdeSystemBackend::validateRequirements(
    const DesktopManagedSettings& required, std::string& error) const {
    for (const auto& [physical, value] : required) {
        const auto* setting = settingFor(physical.setting);
        if (setting == nullptr) {
            error = "unsupported KDE system setting: " + physical.setting;
            return false;
        }
        if (!validRequiredValue(*setting, value)) {
            error = "invalid value for KDE system setting " +
                physical.setting + ": " + value;
            return false;
        }
    }
    error.clear();
    return true;
}

bool KdeSystemBackend::ensureManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) {
        error.clear();
        return true;
    }
    if (!validateRequirements(required, error)) return false;
    if (!validateVerificationHierarchy(options_, error)) return false;

    std::filesystem::path verifier;
    if (!dependencies_.resolveExecutable(
            fic::platform::ExecutableId::KconfigVerifier, verifier, error)) {
        error = "cannot resolve fic-kconfig-verifier: " + error;
        return false;
    }

    struct PlannedFile {
        std::filesystem::path path;
        bool exists = false;
        std::string current;
        std::string merged;
    };
    std::array<PlannedFile, 2> files{{
        {options_.configPath}, {options_.globalsPath}}};
    for (auto& file : files) {
        if (!readOptionalFile(file.path, options_, file.exists,
                              file.current, error) ||
            !validateManagedSyntax(file.current, file.path, error))
            return false;
        file.merged = mergeManagedSettings(file.current, required);
    }

    UniqueFd parent;
    if (!openDirectory(options_.configPath.parent_path(), true, false,
                       options_, parent, error) ||
        !openDirectory(options_.configPath.parent_path(), false, true,
                       options_, parent, error))
        return false;
    for (const auto& file : files) {
        if ((!file.exists || file.current != file.merged) &&
            !atomicWrite(file.path, file.merged, options_, error))
            return false;
    }
    return verifyWithExecutable(required, verifier, error);
}

bool KdeSystemBackend::verifyManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) {
        error.clear();
        return true;
    }
    if (!validateRequirements(required, error)) return false;
    if (!validateVerificationHierarchy(options_, error)) return false;
    std::filesystem::path verifier;
    if (!dependencies_.resolveExecutable(
            fic::platform::ExecutableId::KconfigVerifier, verifier, error)) {
        error = "cannot resolve fic-kconfig-verifier: " + error;
        return false;
    }
    return verifyWithExecutable(required, verifier, error);
}

bool KdeSystemBackend::verifyWithExecutable(
    const DesktopManagedSettings& required,
    const std::filesystem::path& verifier, std::string& error) const {
    for (const auto& path : {options_.configPath, options_.globalsPath}) {
        if (!fileAccessibleToOrdinaryUsers(path, options_, error)) return false;
        bool exists = false;
        std::string content;
        if (!readOptionalFile(path, options_, exists, content, error)) return false;
        if (!exists) {
            error = "KDE system configuration file is missing: " + path.string();
            return false;
        }
        if (!verifyManagedContent(content, required, error)) return false;
    }

    TemporaryTree temporary(options_.temporaryRoot, error);
    if (!temporary.valid()) return false;
    std::error_code filesystemError;
    std::filesystem::create_directories(
        temporary.root() / "home", filesystemError);
    if (!filesystemError) {
        std::filesystem::create_directories(
            temporary.root() / "user", filesystemError);
    }
    if (!filesystemError) {
        std::filesystem::create_directories(
            temporary.root() / "user" / "kdedefaults", filesystemError);
    }
    if (filesystemError) {
        error = "cannot create isolated KDE verification environment: " +
            filesystemError.message();
        return false;
    }
    if (!writePrivateFile(temporary.root() / "user" /
                              options_.configPath.filename(),
                          conflictingUserConfig(), error))
        return false;
    if (!writePrivateFile(temporary.root() / "user" / "kdedefaults" /
                              options_.globalsPath.filename(),
                          conflictingImmutableDefaults(), error))
        return false;

    const ProcessOptions processOptions = verificationOptions(
        temporary.root(), options_.systemConfigDirs);
    const ProcessResult result = dependencies_.execute(
        verifier, {}, processOptions);
    if (!result.success()) {
        error = "KDE FullConfig verification failed: " + processFailure(result);
        return false;
    }
    if (!parseVerifierOutput(result.standardOutput, required, error)) return false;
    error.clear();
    return true;
}
