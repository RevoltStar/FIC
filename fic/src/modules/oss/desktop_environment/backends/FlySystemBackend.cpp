#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
struct SettingDescription {
    const char* setting;
    const char* key;
};

constexpr std::array<SettingDescription, 1> kSettings{{
    {"themerc/Variables/ScreenSaverDelay", "ScreenSaverDelay"},
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

std::string systemError() { return std::strerror(errno); }

std::string trim(std::string value) {
    const auto whitespace = [](unsigned char ch) {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
    };
    while (!value.empty() && whitespace(
               static_cast<unsigned char>(value.back()))) value.pop_back();
    std::size_t first = 0;
    while (first < value.size() && whitespace(
               static_cast<unsigned char>(value[first]))) ++first;
    return value.substr(first);
}

const SettingDescription* settingFor(const std::string& setting) {
    for (const auto& candidate : kSettings)
        if (setting == candidate.setting) return &candidate;
    return nullptr;
}

bool validRequiredValue(const std::string& value) {
    if (value.empty() ||
        !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        })) return false;
    try {
        const int seconds = std::stoi(value);
        return seconds >= 60 && seconds <= 1200 && seconds % 60 == 0;
    } catch (...) {
        return false;
    }
}

bool validateRequirements(const DesktopManagedSettings& required,
                          std::string& error) {
    for (const auto& [physical, value] : required) {
        const auto* setting = settingFor(physical.setting);
        if (setting == nullptr) {
            error = "unknown FLY system setting: " + physical.setting;
            return false;
        }
        if (!validRequiredValue(value)) {
            error = "invalid value for FLY system setting " +
                physical.setting;
            return false;
        }
    }
    error.clear();
    return true;
}

bool relativeComponents(const std::filesystem::path& path,
                        const FlySystemBackendOptions& options,
                        std::vector<std::string>& components,
                        std::string& error) {
    const auto root = options.trustedRoot.lexically_normal();
    const auto target = path.lexically_normal();
    if (!root.is_absolute() || !target.is_absolute()) {
        error = "FLY system config paths must be absolute";
        return false;
    }
    const auto relative = target.lexically_relative(root);
    if ((relative.empty() && target != root) || relative.is_absolute()) {
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
                         const FlySystemBackendOptions& options,
                         std::string& error) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        error = "cannot inspect trusted directory " + path.string() + ": " +
            systemError();
        return false;
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != options.trustedOwner ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (info.st_mode & S_IXOTH) == 0) {
        error = "unsafe FLY system config directory: " + path.string();
        return false;
    }
    return true;
}

bool openDirectory(const std::filesystem::path& path,
                   const FlySystemBackendOptions& options,
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
                             error)) return false;
    std::filesystem::path traversed = options.trustedRoot;
    for (const auto& component : components) {
        traversed /= component;
        UniqueFd next(::openat(current.get(), component.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
        if (next.get() < 0) {
            if (errno == ENOENT && missing != nullptr) {
                *missing = true;
                error = "FLY theme.master directory is missing: " +
                    traversed.string();
                return false;
            }
            error = "cannot securely open directory " + traversed.string() +
                ": " + systemError();
            return false;
        }
        if (!validateDirectoryFd(next.get(), traversed, options, error))
            return false;
        current = std::move(next);
    }
    result = std::move(current);
    return true;
}

bool readOptionalFile(const std::filesystem::path& path,
                      const FlySystemBackendOptions& options,
                      bool& exists, std::string& content,
                      std::string& error) {
    exists = false;
    content.clear();
    UniqueFd parent;
    if (!openDirectory(path.parent_path(), options, parent, error)) return false;
    UniqueFd file(::openat(parent.get(), path.filename().c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.get() < 0) {
        if (errno == ENOENT) { error.clear(); return true; }
        error = "cannot securely open FLY system config " + path.string() +
            ": " + systemError();
        return false;
    }
    struct stat info {};
    if (::fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != options.trustedOwner ||
        (info.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (info.st_mode & S_IROTH) == 0) {
        error = "unsafe FLY system config file: " + path.string();
        return false;
    }
    char buffer[8192];
    for (;;) {
        const ssize_t count = ::read(file.get(), buffer, sizeof(buffer));
        if (count > 0) {
            content.append(buffer, static_cast<std::size_t>(count));
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            error = "cannot read FLY system config " + path.string() + ": " +
                systemError();
            return false;
        }
    }
    exists = true;
    error.clear();
    return true;
}

bool writeAll(int fd, const std::string& content) {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const ssize_t count = ::write(fd, content.data() + offset,
                                      content.size() - offset);
        if (count > 0) offset += static_cast<std::size_t>(count);
        else if (count < 0 && errno == EINTR) continue;
        else return false;
    }
    return true;
}

bool atomicWrite(const std::filesystem::path& path,
                 const std::string& content,
                 const FlySystemBackendOptions& options,
                 std::string& error) {
    UniqueFd parent;
    if (!openDirectory(path.parent_path(), options, parent, error)) return false;
    struct stat oldInfo {};
    if (::fstatat(parent.get(), path.filename().c_str(), &oldInfo,
                  AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISREG(oldInfo.st_mode) ||
            oldInfo.st_uid != options.trustedOwner ||
            (oldInfo.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            (oldInfo.st_mode & S_IROTH) == 0) {
            error = "refusing to replace unsafe FLY system config: " +
                path.string();
            return false;
        }
    } else if (errno != ENOENT) {
        error = "cannot inspect FLY system config " + path.string() + ": " +
            systemError();
        return false;
    }
    static std::atomic<unsigned long> sequence{0};
    const std::string temporary = "." + path.filename().string() + ".tmp." +
        std::to_string(::getpid()) + "." + std::to_string(sequence++);
    UniqueFd file(::openat(parent.get(), temporary.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (file.get() < 0) {
        error = "cannot create temporary FLY system config: " + systemError();
        return false;
    }
    const auto cleanup = [&] { ::unlinkat(parent.get(), temporary.c_str(), 0); };
    if (::fchown(file.get(), options.trustedOwner, options.trustedGroup) != 0 ||
        ::fchmod(file.get(), 0644) != 0 || !writeAll(file.get(), content) ||
        ::fsync(file.get()) != 0) {
        error = "cannot write FLY system config " + path.string() + ": " +
            systemError();
        cleanup();
        return false;
    }
    if (::renameat(parent.get(), temporary.c_str(), parent.get(),
                   path.filename().c_str()) != 0) {
        error = "cannot atomically replace FLY system config " +
            path.string() + ": " + systemError();
        cleanup();
        return false;
    }
    if (::fsync(parent.get()) != 0) {
        error = "cannot fsync FLY system config directory: " + systemError();
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
    for (const auto& setting : kSettings)
        if (left == setting.key) return &setting;
    return nullptr;
}

std::map<std::string, std::string> valuesByKey(
    const DesktopManagedSettings& required);

bool validateManagedSyntax(const std::string& content,
                           const DesktopManagedSettings& required,
                           const std::filesystem::path& path,
                           std::string& error) {
    const auto requiredValues = valuesByKey(required);
    bool inVariables = false;
    bool sawVariables = false;
    std::set<std::string> managedKeys;
    for (const auto& line : splitLines(content)) {
        std::string group;
        if (groupHeader(line, group)) {
            if (group == "Variables") {
                if (sawVariables) {
                    error = "ambiguous duplicate [Variables] group in " +
                        path.string();
                    return false;
                }
                sawVariables = true;
                inVariables = true;
            } else inVariables = false;
            continue;
        }
        if (!inVariables) continue;
        const std::string stripped = trim(line);
        if (stripped.empty() || stripped.front() == '#' ||
            stripped.front() == ';') continue;
        std::string left, value;
        const auto* setting = managedAssignment(line, left, value);
        if (setting != nullptr) {
            if (requiredValues.count(setting->key) != 0 &&
                !managedKeys.insert(setting->key).second) {
                error = "ambiguous duplicate managed FLY key " +
                    std::string(setting->key) + " in " + path.string();
                return false;
            }
            continue;
        }
        for (const auto& candidate : kSettings) {
            const std::string key = candidate.key;
            if (requiredValues.count(key) != 0 &&
                (stripped == key ||
                (stripped.size() > key.size() &&
                 stripped.compare(0, key.size(), key) == 0 &&
                 (stripped[key.size()] == '[' ||
                  std::isspace(static_cast<unsigned char>(
                      stripped[key.size()])) != 0)))) {
                error = "malformed managed FLY key " + key + " in " +
                    path.string();
                return false;
            }
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
    const auto values = valuesByKey(required);
    const auto lines = splitLines(content);
    std::vector<std::string> output;
    std::set<std::string> emitted;
    bool inVariables = false;
    bool sawVariables = false;
    bool leftVariables = false;
    const auto emitMissing = [&] {
        for (const auto& [key, value] : values)
            if (emitted.insert(key).second)
                output.push_back(key + "=" + value);
    };
    for (const auto& line : lines) {
        std::string group;
        if (groupHeader(line, group)) {
            if (inVariables && !leftVariables) {
                emitMissing();
                leftVariables = true;
            }
            inVariables = group == "Variables";
            sawVariables = sawVariables || inVariables;
            output.push_back(line);
            continue;
        }
        if (inVariables) {
            std::string left, value;
            const auto* setting = managedAssignment(line, left, value);
            if (setting != nullptr && values.count(setting->key) != 0) {
                if (emitted.insert(setting->key).second)
                    output.push_back(std::string(setting->key) + "=" +
                                     values.at(setting->key));
                continue;
            }
        }
        output.push_back(line);
    }
    if (inVariables && !leftVariables) emitMissing();
    else if (!sawVariables) {
        if (!output.empty() && !output.back().empty()) output.emplace_back();
        output.push_back("[Variables]");
        emitMissing();
    }
    std::ostringstream serialized;
    for (const auto& line : output) serialized << line << '\n';
    return serialized.str();
}

bool verifyContent(const std::string& content,
                   const DesktopManagedSettings& required,
                   std::string& error) {
    const auto values = valuesByKey(required);
    std::map<std::string, int> counts;
    bool inVariables = false;
    for (const auto& line : splitLines(content)) {
        std::string group;
        if (groupHeader(line, group)) {
            inVariables = group == "Variables";
            continue;
        }
        if (!inVariables) continue;
        std::string left, value;
        const auto* setting = managedAssignment(line, left, value);
        if (setting == nullptr || values.count(setting->key) == 0) continue;
        if (value != values.at(setting->key)) {
            error = "FLY system setting has the wrong value: " +
                std::string(setting->key);
            return false;
        }
        ++counts[setting->key];
    }
    for (const auto& [key, value] : values) {
        if (counts[key] != 1) {
            error = "FLY system setting is missing or duplicated: " + key;
            return false;
        }
    }
    error.clear();
    return true;
}
} // namespace

FlySystemBackend::FlySystemBackend(FlySystemBackendOptions options)
    : options_(std::move(options)) {}

DesktopEnvironmentKind FlySystemBackend::desktop() const {
    return DesktopEnvironmentKind::Fly;
}

std::string FlySystemBackend::backendName() const { return "fly"; }

bool FlySystemBackend::ensureManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) { error.clear(); return true; }
    if (!validateRequirements(required, error)) return false;
    bool exists = false;
    std::string current;
    if (!readOptionalFile(options_.configPath, options_, exists, current,
                          error)) return false;
    if (exists && !validateManagedSyntax(
            current, required, options_.configPath, error))
        return false;
    const std::string merged = mergeManagedSettings(current, required);
    if ((!exists || merged != current) &&
        !atomicWrite(options_.configPath, merged, options_, error)) return false;
    return verifyManagedSettings(required, error);
}

bool FlySystemBackend::verifyManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) { error.clear(); return true; }
    if (!validateRequirements(required, error)) return false;
    bool exists = false;
    std::string content;
    if (!readOptionalFile(options_.configPath, options_, exists, content,
                          error)) return false;
    if (!exists) {
        error = "FLY system config is missing: " + options_.configPath.string();
        return false;
    }
    return validateManagedSyntax(content, required, options_.configPath,
                                 error) &&
        verifyContent(content, required, error);
}
