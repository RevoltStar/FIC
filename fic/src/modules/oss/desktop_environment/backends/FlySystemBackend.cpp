#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/ExclusivePidLock.h>
#include <fic/core/runtime/FicRuntimePaths.h>

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
    : options_(std::move(options)) {
    if (options_.lockPath.empty() && fic::core::FicRuntimePaths::isInitialized())
        options_.lockPath = fic::core::FicRuntimePaths::get().runtimeDir / "desktop-config.lock";
}

DesktopEnvironmentKind FlySystemBackend::desktop() const {
    return DesktopEnvironmentKind::Fly;
}

std::string FlySystemBackend::backendName() const { return "fly"; }

bool FlySystemBackend::ensureManagedSettings(
    const DesktopManagedSettings& required, std::string& error) {
    if (required.empty()) { error.clear(); return true; }
    if (!validateRequirements(required, error)) return false;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if (!journal) return false;
    DesktopGlobalConfigRequirements owned;
    for (const auto& [key, value] : required)
        owned.emplace(key, GlobalDesktopConfigValue{value,
            {{"OSS", "DesktopEnvironment", "screenlock_timeout"}}});
    // Missing requirements are deliberately a no-op above. Only a coordinator
    // with a complete desired owner set may authorize obsolete-resource release.
    return reconcileJournaled(owned, *journal, error);
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

namespace {
using namespace fic::rollback;
const std::string flyResource = "FLY/themerc/Variables/ScreenSaverDelay";
const PolicyRef flyPolicy{"OSS", "DesktopEnvironment", "screenlock_timeout"};

struct FlyScalarView {
    std::optional<std::string> line;
    std::size_t offset = 0;
    std::size_t insertion = 0;
    bool variables = false;
};

// Byte offsets retain every foreign byte, including CRLF and final-newline
// state. The inverse delta stores only the one original parameter line.
bool scalarView(const std::string& content, FlyScalarView& result,
                std::string& error) {
    result = {};
    if (!validateManagedSyntax(content,
            {{{"themerc/Variables/ScreenSaverDelay"}, "300"}}, "themerc", error))
        return false;
    bool inVariables = false;
    for (std::size_t offset = 0; offset < content.size();) {
        const auto end = content.find('\n', offset);
        const auto size = end == std::string::npos ? content.size() - offset : end - offset + 1;
        const std::string raw = content.substr(offset, size);
        std::string group;
        if (groupHeader(raw, group)) {
            inVariables = group == "Variables";
            if (inVariables) {
                result.variables = true;
                result.insertion = offset + size;
            }
        } else if (inVariables) {
            result.insertion = offset + size;
            const std::string stripped = trim(raw);
            if (!stripped.empty() && stripped.front() != '#' && stripped.front() != ';') {
                std::string key, value;
                if (managedAssignment(raw, key, value)) {
                    result.offset = offset;
                    result.line = raw;
                }
            }
        }
        offset += size;
    }
    if (!result.variables) {
        error = "FLY rollback requires an existing unambiguous [Variables] group";
        return false;
    }
    return true;
}

std::string scalarMarker(MutationId id) {
    return "# FIC-DE " + std::to_string(id) + " " + flyResource + "\n";
}

bool activeScalar(MutationJournal& journal, std::optional<MutationRecord>& record,
                  std::string& error) {
    record.reset();
    if (!journal.usable()) { error = "Desktop mutation journal is unhealthy"; return false; }
    for (const auto& candidate : journal.records()) {
        if (!candidate.isActive() || candidate.undo.backend != MutationBackend::Desktop)
            continue;
        const auto* scalar = std::get_if<UndoRestoreDesktopScalar>(&candidate.undo.payload);
        if (std::holds_alternative<fic::rollback::UndoOwnDesktopArtifact>(candidate.undo.payload)) continue;
        if (!scalar) { error = "Desktop mutation payload mismatch"; return false; }
        if (scalar->desktop != "FLY") continue;
        if (candidate.resource != flyResource || candidate.policy != flyPolicy || record) {
            error = "FLY scalar identity/ownership conflict";
            return false;
        }
        record = candidate;
    }
    return true;
}

bool captureScalar(const FlySystemBackendOptions& options, AtomicTargetState& snapshot,
                   FlyScalarView& view, std::string& error) {
    bool exists = false;
    std::string content;
    if (!readOptionalFile(options.configPath, options, exists, content, error)) return false;
    if (!exists) {
        error = "FLY rollback requires the installed theme.master/themerc file; creation is not enrolled";
        return false;
    }
    if (!AtomicFileWriter::captureTargetState(options.configPath.string(), snapshot, &error)) return false;
    if (snapshot.content != content || snapshot.owner != options.trustedOwner ||
        (snapshot.mode & (S_IWGRP | S_IWOTH)) != 0 || (snapshot.mode & S_IROTH) == 0) {
        error = "FLY config changed during trusted capture";
        return false;
    }
    return scalarView(content, view, error);
}

bool scalarProof(const AtomicTargetState& snapshot, const FlyScalarView& view,
                 const std::optional<MutationRecord>& record,
                 bool& marked, std::string& error) {
    marked = false;
    const auto anyMarker = snapshot.content.find("# FIC-DE ");
    if (!record) {
        if (anyMarker != std::string::npos) {
            error = "Orphan FLY ownership marker without active journal provenance";
            return false;
        }
        return true;
    }
    const auto& scalar = std::get<UndoRestoreDesktopScalar>(record->undo.payload);
    const std::string marker = scalarMarker(record->id);
    if (anyMarker != std::string::npos) {
        if (!view.line || view.offset < marker.size() ||
            snapshot.content.substr(view.offset - marker.size(), marker.size()) != marker ||
            anyMarker != view.offset - marker.size() ||
            snapshot.content.find("# FIC-DE ", anyMarker + 1) != std::string::npos ||
            (*view.line != scalar.appliedLine &&
             (!scalar.previousAppliedLine || *view.line != *scalar.previousAppliedLine))) {
            error = "FLY ownership marker/mutation ID/applied scalar mismatch";
            return false;
        }
        marked = true;
        return true;
    }
    // An unmarked original is permitted only BEFORE first installation, or
    // AFTER a durably prepared release. Applied ownership never adopts it.
    if (view.line == scalar.originalLine &&
        (scalar.phase == "release" ||
         (record->status == MutationStatus::Prepared && !scalar.hadApplied &&
          !scalar.previousAppliedLine))) return true;
    error = "FLY applied ownership disappeared or the original scalar changed";
    return false;
}

bool replaceScalar(const FlySystemBackendOptions& options,
                   const AtomicTargetState& snapshot, const std::string& content,
                   std::string& error) {
    if (content == snapshot.content)
        return AtomicFileWriter::ensureTargetDurableIfCurrentState(
            options.configPath.string(), snapshot, &error);
    AtomicWriteOptions writeOptions;
    writeOptions.rejectSymlink = true;
    writeOptions.expectedTargetState = snapshot;
    AtomicWriteResult result;
    if (AtomicFileWriter::writeWithResult(options.configPath.string(), content,
            writeOptions, &error, &result)) return true;
    if (result.installed && result.installedTargetState &&
        AtomicFileWriter::ensureTargetDurableIfCurrentState(options.configPath.string(),
            *result.installedTargetState, &error)) return true;
    return false;
}

bool validFlyDesired(const DesktopGlobalConfigRequirements& required, std::string& error) {
    DesktopManagedSettings values;
    for (const auto& [key, value] : required) {
        if (value.owners.empty()) { error = "FLY requirement has no policy owner"; return false; }
        for (const auto& owner : value.owners) {
            if (owner.moduleName != "OSS" || owner.submoduleName != "DesktopEnvironment" ||
                (owner.policyName != "screenlock_timeout" &&
                 owner.policyName != "disable_kde_lock_screen_media_controls")) {
                error = "Unknown FLY physical requirement owner";
                return false;
            }
        }
        values.emplace(key, value.value);
        if (validRequiredValue(value.value) &&
            value.value != std::to_string(std::stoi(value.value))) {
            error = "Noncanonical FLY scalar value";
            return false;
        }
    }
    return validateRequirements(values, error);
}
} // namespace

bool FlySystemBackend::preflightJournaled(
    const DesktopGlobalConfigRequirements& required,
    fic::rollback::MutationJournal& journal, std::string& error) {
    if (!validFlyDesired(required, error)) return false;
    std::vector<std::string> components;
    if (!relativeComponents(options_.configPath, options_, components, error)) return false;
    std::optional<fic::rollback::MutationRecord> record;
    if (!activeScalar(journal, record, error)) return false;
    if (required.empty() && !record) {
        struct stat info {};
        if (::lstat(options_.configPath.c_str(), &info) != 0 && errno == ENOENT) {
            error.clear(); return true;
        }
    }
    AtomicTargetState snapshot;
    FlyScalarView view;
    bool marked = false;
    if (!captureScalar(options_, snapshot, view, error) ||
        !scalarProof(snapshot, view, record, marked, error)) return false;
    if (!required.empty() && !view.line && view.insertion != 0 &&
        snapshot.content[view.insertion - 1] != '\n') {
        error = "FLY scalar insertion needs a terminated [Variables] line";
        return false;
    }
    error.clear();
    return true;
}

bool FlySystemBackend::releaseJournaled(
    const fic::rollback::MutationRecord& request,
    fic::rollback::MutationJournal& journal, std::string& error) {
    ExclusivePidLock lock(options_.lockPath.string(), "", false);
    if (!lock.acquire()) { error = "Cannot acquire FIC desktop-config lock"; return false; }
    std::optional<fic::rollback::MutationRecord> active;
    if (!activeScalar(journal, active, error)) return false;
    if (!active || active->id != request.id || request.resource != flyResource ||
        request.policy != flyPolicy || request.undo.backend != fic::rollback::MutationBackend::Desktop) {
        error = "FLY release requires matching active journal identity";
        return false;
    }
    const auto* requested = std::get_if<fic::rollback::UndoRestoreDesktopScalar>(&request.undo.payload);
    const auto& current = std::get<fic::rollback::UndoRestoreDesktopScalar>(active->undo.payload);
    if (!requested || requested->desktop != current.desktop || requested->setting != current.setting ||
        requested->originalLine != current.originalLine || requested->originalLockLine != current.originalLockLine ||
        requested->appliedLine != current.appliedLine ||
        requested->previousAppliedLine != current.previousAppliedLine || requested->owners != current.owners ||
        requested->hadApplied != current.hadApplied || requested->phase != current.phase ||
        requested->compiledBeforeDigest != current.compiledBeforeDigest ||
        requested->compiledTargetDigest != current.compiledTargetDigest ||
        request.status != active->status) {
        error = "FLY release request is stale relative to current journal ownership";
        return false;
    }
    AtomicTargetState snapshot;
    FlyScalarView view;
    bool marked = false;
    if (!captureScalar(options_, snapshot, view, error) ||
        !scalarProof(snapshot, view, active, marked, error)) return false;
    auto record = *active;
    auto& scalar = std::get<fic::rollback::UndoRestoreDesktopScalar>(record.undo.payload);
    scalar.phase = "release";
    scalar.owners.clear();
    record.status = fic::rollback::MutationStatus::Prepared;
    fic::rollback::MutationId id = 0;
    if (!journal.prepareMutation(record, id, error)) return false;
    std::string restored = snapshot.content;
    if (marked) {
        const std::string marker = scalarMarker(id);
        restored.replace(view.offset - marker.size(), marker.size() + view.line->size(),
                         scalar.originalLine.value_or(""));
    }
    if (!replaceScalar(options_, snapshot, restored, error)) return false;
    AtomicTargetState finalState;
    FlyScalarView finalView;
    if (!captureScalar(options_, finalState, finalView, error) ||
        finalView.line != scalar.originalLine ||
        finalState.content.find("# FIC-DE ") != std::string::npos) {
        if (error.empty()) error = "FLY released scalar did not match the inverse delta";
        return false;
    }
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            options_.configPath.string(), finalState, &error)) return false;
    return journal.setStatus(id, fic::rollback::MutationStatus::RolledBack, error);
}

bool FlySystemBackend::releaseOwnerJournaled(
    const PolicyRef& owner, fic::rollback::MutationJournal& journal, std::string& error, bool preview) {
    if (owner.moduleName != "OSS" || owner.submoduleName != "DesktopEnvironment" ||
        (owner.policyName != "screenlock_timeout" && owner.policyName != "disable_kde_lock_screen_media_controls")) {
        error = "Unknown FLY release owner"; return false;
    }
    ExclusivePidLock lock(options_.lockPath.string(), "", false);
    if (!lock.acquire()) { error = "Cannot acquire FIC desktop-config lock"; return false; }
    std::optional<fic::rollback::MutationRecord> active;
    if (!activeScalar(journal, active, error)) return false;
    DesktopGlobalConfigRequirements remaining;
    if (active) {
        const auto& scalar = std::get<fic::rollback::UndoRestoreDesktopScalar>(active->undo.payload);
        std::set<PolicyRef> owners(scalar.owners.begin(), scalar.owners.end());
        owners.erase(owner);
        if (!owners.empty()) {
            const auto line = trim(scalar.appliedLine);
            const std::string prefix = "ScreenSaverDelay=";
            if (line.compare(0, prefix.size(), prefix) != 0) {
                error = "FLY release scalar identity conflict"; return false;
            }
            remaining.emplace(GlobalDesktopConfigKey{scalar.setting},
                GlobalDesktopConfigValue{line.substr(prefix.size()), std::move(owners)});
        }
    }
    return preview ? preflightJournaled(remaining, journal, error) : reconcileJournaled(remaining, journal, error);
}

bool FlySystemBackend::reconcileJournaled(
    const DesktopGlobalConfigRequirements& required,
    fic::rollback::MutationJournal& journal, std::string& error) {
    ExclusivePidLock lock(options_.lockPath.string(), "", false);
    if (!lock.acquire()) { error = "Cannot acquire FIC desktop-config lock"; return false; }
    if (!preflightJournaled(required, journal, error)) return false;
    std::optional<fic::rollback::MutationRecord> active;
    if (!activeScalar(journal, active, error)) return false;
    if (required.empty()) {
        if (active) return releaseJournaled(*active, journal, error);
        error.clear(); return true;
    }
    if (active && std::get<fic::rollback::UndoRestoreDesktopScalar>(active->undo.payload).phase == "release") {
        if (!releaseJournaled(*active, journal, error)) return false;
        active.reset();
    }
    AtomicTargetState snapshot;
    FlyScalarView view;
    bool marked = false;
    if (!captureScalar(options_, snapshot, view, error) ||
        !scalarProof(snapshot, view, active, marked, error)) return false;
    const auto& desired = required.begin()->second;
    fic::rollback::MutationRecord record;
    fic::rollback::UndoRestoreDesktopScalar scalar;
    if (active) {
        record = *active;
        scalar = std::get<fic::rollback::UndoRestoreDesktopScalar>(record.undo.payload);
        if (marked) scalar.previousAppliedLine = view.line;
    } else {
        record.policy = flyPolicy;
        record.resource = flyResource;
        scalar.desktop = "FLY";
        scalar.setting = "themerc/Variables/ScreenSaverDelay";
        scalar.originalLine = view.line;
    }
    scalar.appliedLine = "ScreenSaverDelay=" + desired.value + "\n";
    scalar.owners.assign(desired.owners.begin(), desired.owners.end());
    scalar.phase = "ensure";
    record.status = fic::rollback::MutationStatus::Prepared;
    record.undo = {fic::rollback::MutationBackend::Desktop, scalar};
    fic::rollback::MutationId id = 0;
    if (!journal.prepareMutation(record, id, error)) return false;
    std::string installed = snapshot.content;
    const std::string target = scalarMarker(id) + scalar.appliedLine;
    if (marked) {
        const std::string marker = scalarMarker(id);
        installed.replace(view.offset - marker.size(), marker.size() + view.line->size(), target);
    } else if (view.line) {
        installed.replace(view.offset, view.line->size(), target);
    } else {
        if (view.insertion != 0 && installed[view.insertion - 1] != '\n') {
            error = "FLY scalar insertion needs a terminated [Variables] line";
            return false;
        }
        installed.insert(view.insertion, target);
    }
    if (!replaceScalar(options_, snapshot, installed, error)) return false;
    AtomicTargetState finalState;
    FlyScalarView finalView;
    if (!captureScalar(options_, finalState, finalView, error)) return false;
    record.id = id;
    if (!scalarProof(finalState, finalView, record, marked, error) ||
        !marked || finalView.line != scalar.appliedLine) {
        if (error.empty()) error = "FLY installed scalar verification failed";
        return false;
    }
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            options_.configPath.string(), finalState, &error)) return false;
    scalar.hadApplied = true;
    scalar.previousAppliedLine.reset();
    record.undo.payload = scalar;
    if (!journal.prepareMutation(record, id, error)) return false;
    return journal.setStatus(id, fic::rollback::MutationStatus::Applied, error);
}
