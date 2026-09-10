#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamProviderInspector.h"

#include <fic/core/process/ExclusivePidLock.h>
#include <fic/core/fs/TrustedFileReader.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

struct PhysicalLine {
    std::string text;
    std::string ending;
};

struct TargetSnapshot {
    std::string content;
    dev_t device = 0;
    ino_t inode = 0;
};

struct ManagedBlock {
    bool present = false;
    std::size_t begin = 0;
    std::size_t tcb = 0;
    std::size_t end = 0;
};

std::string errnoText() { return std::strerror(errno); }

std::string moduleName(const PamRule& rule) {
    return std::filesystem::path(rule.module).filename().string();
}

bool hasArgument(const PamRule& rule, const std::string& expected) {
    for (const auto& argument : rule.arguments) {
        if (argument == expected)
            return true;
    }
    return false;
}

std::vector<PhysicalLine> splitLines(const std::string& content) {
    std::vector<PhysicalLine> result;
    std::size_t offset = 0;
    while (offset < content.size()) {
        const auto newline = content.find('\n', offset);
        if (newline == std::string::npos) {
            result.push_back({content.substr(offset), {}});
            break;
        }
        std::string text = content.substr(offset, newline - offset);
        std::string ending = "\n";
        if (!text.empty() && text.back() == '\r') {
            text.pop_back();
            ending = "\r\n";
        }
        result.push_back({std::move(text), std::move(ending)});
        offset = newline + 1;
    }
    return result;
}

std::string joinLines(const std::vector<PhysicalLine>& lines) {
    std::string result;
    for (const auto& line : lines)
        result += line.text + line.ending;
    return result;
}

bool inspectSecureTarget(const std::filesystem::path& path,
                         TargetSnapshot& snapshot,
                         std::string& error,
                         const fic::core::TrustedFilePostValidationHook&
                             validationHook = {}) {
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    fic::core::TrustedFileMetadata metadata;
    if (!fic::core::readTrustedFile(
            path, options, snapshot.content, error, &metadata,
            validationHook))
        return false;
    snapshot.device = metadata.device;
    snapshot.inode = metadata.inode;
    return true;
}

AtomicWriteOptions writeOptionsFor(const AtomicWriteOptions& base,
                                   const TargetSnapshot& snapshot) {
    AtomicWriteOptions result = base;
    result.expectedTargetIdentity =
        AtomicTargetIdentity{snapshot.device, snapshot.inode};
    return result;
}

bool parseRules(const std::filesystem::path& path,
                const std::string& content,
                std::vector<PamRule>& rules,
                std::string& error) {
    return PamConfiguration::parseRulesContent(path, content, rules, error);
}

bool inspectBlock(const std::vector<PhysicalLine>& lines,
                  const std::vector<PamRule>& rules,
                  ManagedBlock& block,
                  std::string& error) {
    std::vector<std::size_t> begins;
    std::vector<std::size_t> ends;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (lines[index].text == AltPamPasswordHistoryTopologyManager::BEGIN)
            begins.push_back(index);
        if (lines[index].text == AltPamPasswordHistoryTopologyManager::END)
            ends.push_back(index);
    }
    if (begins.empty() && ends.empty()) {
        block = {};
        return true;
    }
    if (begins.size() != 1 || ends.size() != 1 ||
        ends.front() != begins.front() + 5 ||
        lines[begins.front() + 1].text !=
            AltPamPasswordHistoryTopologyManager::LOCK_RULE ||
        lines[begins.front() + 2].text !=
            AltPamPasswordHistoryTopologyManager::HISTORY_RULE ||
        lines[begins.front() + 4].text !=
            AltPamPasswordHistoryTopologyManager::UNLOCK_RULE) {
        error = "broken FIC pam_pwhistory managed block";
        return false;
    }
    const std::size_t tcbLine = begins.front() + 4;
    const PamRule* tcb = nullptr;
    for (const auto& rule : rules) {
        if (rule.line == tcbLine && rule.group == PamManagementGroup::Password &&
            moduleName(rule) == "pam_tcb.so") {
            tcb = &rule;
            break;
        }
    }
    if (tcb == nullptr || !hasArgument(*tcb, "write_to=tcb")) {
        error = "FIC pam_pwhistory block does not contain its pam_tcb backend";
        return false;
    }
    block.present = true;
    block.begin = begins.front();
    block.tcb = begins.front() + 3;
    block.end = ends.front();
    return true;
}

bool inspectTopology(const std::filesystem::path& path,
                     const std::string& content,
                     std::vector<PhysicalLine>& lines,
                     std::vector<PamRule>& rules,
                     ManagedBlock& block,
                     std::string& error) {
    lines = splitLines(content);
    if (!parseRules(path, content, rules, error) ||
        !inspectBlock(lines, rules, block, error))
        return false;
    std::size_t tcbCount = 0;
    std::size_t historyCount = 0;
    std::size_t transactionCount = 0;
    for (const auto& rule : rules) {
        if (rule.group != PamManagementGroup::Password)
            continue;
        const auto name = moduleName(rule);
        if (name == "pam_tcb.so" && hasArgument(rule, "write_to=tcb"))
            ++tcbCount;
        if (name == "pam_pwhistory.so")
            ++historyCount;
        if (name == "pam_fic_pwtxn.so")
            ++transactionCount;
    }
    if (tcbCount != 1 || historyCount != (block.present ? 1U : 0U) ||
        transactionCount != (block.present ? 2U : 0U)) {
        error = "PAM password stack conflicts with the FIC-managed topology";
        return false;
    }
    return true;
}

bool verifyNoExternalHistory(
    const fic::platform::PamPlatformConfig& platform,
    const fic::platform::PamCapabilityConfig& capability,
    bool managedExpected,
    std::string& error) {
    PamConfiguration configuration(platform);
    std::vector<PamRule> rules;
    const std::string service = capability.topologyTarget.filename().string();
    if (!configuration.collectRules(
            service, PamManagementGroup::Password, rules, error))
        return false;
    std::size_t count = 0;
    for (const auto& rule : rules) {
        if (moduleName(rule) != "pam_pwhistory.so")
            continue;
        ++count;
        if (!managedExpected ||
            rule.source.lexically_normal() !=
                capability.topologyTarget.lexically_normal() ||
            rule.control != "requisite" || !hasArgument(rule, "use_authtok") ||
            !hasArgument(rule, "conf=" + capability.configPath.string())) {
            error = "external pam_pwhistory rule is effective at " +
                rule.source.string() + ":" + std::to_string(rule.line);
            return false;
        }
    }
    if (count != (managedExpected ? 1U : 0U)) {
        error = managedExpected
            ? "the FIC pam_pwhistory rule is not uniquely effective"
            : "an external pam_pwhistory rule is effective";
        return false;
    }
    error.clear();
    return true;
}

bool validateStorageObject(const std::filesystem::path& path, mode_t mode,
                           std::optional<uid_t> owner, gid_t group,
                           bool directory, bool allowMissing,
                           std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (allowMissing && errno == ENOENT) {
            error.clear();
            return true;
        }
        error = "could not inspect password-history storage " + path.string() +
            ": " + errnoText();
        return false;
    }
    const bool correctType = directory ? S_ISDIR(info.st_mode) :
        S_ISREG(info.st_mode);
    if (!correctType || S_ISLNK(info.st_mode) ||
        (owner.has_value() && info.st_uid != *owner) ||
        info.st_gid != group || (info.st_mode & 07777) != mode ||
        (!directory && info.st_nlink != 1)) {
        error = "unsafe password-history storage object: " + path.string();
        return false;
    }
    return true;
}

bool createStorageFile(const std::filesystem::path& path, uid_t owner,
                       gid_t group, bool ownerInvariant,
                       std::string& error) {
    const std::optional<uid_t> expectedOwner =
        ownerInvariant ? std::optional<uid_t>(owner) : std::nullopt;
    int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL |
        O_CLOEXEC | O_NOFOLLOW, 0660);
    if (descriptor < 0) {
        if (errno == EEXIST)
            return validateStorageObject(
                path, 0660, expectedOwner, group, false, false, error);
        error = "could not create password-history storage " + path.string() +
            ": " + errnoText();
        return false;
    }
    bool ok = ::fchown(descriptor, owner, group) == 0 &&
        ::fchmod(descriptor, 0660) == 0 && ::fsync(descriptor) == 0;
    const std::string detail = ok ? std::string() : errnoText();
    if (::close(descriptor) != 0 && ok) {
        ok = false;
    }
    if (!ok) {
        error = "could not initialize password-history storage " +
            path.string() + ": " + detail;
        return false;
    }
    return validateStorageObject(
        path, 0660, expectedOwner, group, false, false, error);
}

enum class TransactionLockResult { Acquired, Busy, Failed };

class TransactionFileLock {
public:
    TransactionFileLock() = default;
    TransactionFileLock(const TransactionFileLock&) = delete;
    TransactionFileLock& operator=(const TransactionFileLock&) = delete;
    ~TransactionFileLock() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }

    TransactionLockResult acquire(
        const AltPamPasswordHistoryTopologyOptions& options,
        std::string& error) {
        descriptor_ = ::open(options.transactionLockFile.c_str(),
            O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
        if (descriptor_ < 0) {
            error = "could not open password transaction lock " +
                options.transactionLockFile.string() + ": " + errnoText();
            return TransactionLockResult::Failed;
        }
        struct stat info {};
        if (::fstat(descriptor_, &info) != 0) {
            error = "could not inspect password transaction lock: " +
                errnoText();
            return TransactionLockResult::Failed;
        }
        if (!S_ISREG(info.st_mode) || info.st_uid != options.storageOwner ||
            info.st_gid != options.storageGroup ||
            (info.st_mode & 07777) != 0660 || info.st_nlink != 1) {
            error = "unsafe password transaction lock: " +
                options.transactionLockFile.string();
            return TransactionLockResult::Failed;
        }

        struct flock lock {};
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        const auto deadline = std::chrono::steady_clock::now() +
            options.transactionLockTimeout;
        for (;;) {
#ifdef F_OFD_SETLK
            if (::fcntl(descriptor_, F_OFD_SETLK, &lock) == 0)
#else
            if (::fcntl(descriptor_, F_SETLK, &lock) == 0)
#endif
                return TransactionLockResult::Acquired;
            if (errno != EACCES && errno != EAGAIN && errno != EINTR) {
                error = "could not acquire password transaction lock: " +
                    errnoText();
                return TransactionLockResult::Failed;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                error = "password transaction lock is busy";
                return TransactionLockResult::Busy;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

private:
    int descriptor_ = -1;
};

bool prepareStorageBeforeTransaction(
    const AltPamPasswordHistoryTopologyOptions& options,
    std::string& error) {
    struct stat info {};
    if (::lstat(options.stateDirectory.c_str(), &info) != 0) {
        if (errno != ENOENT ||
            ::mkdir(options.stateDirectory.c_str(), 02730) != 0) {
            error = "could not create password-history directory " +
                options.stateDirectory.string() + ": " + errnoText();
            return false;
        }
        if (::chown(options.stateDirectory.c_str(), options.storageOwner,
                    options.storageGroup) != 0 ||
            ::chmod(options.stateDirectory.c_str(), 02730) != 0) {
            error = "could not initialize password-history directory: " +
                errnoText();
            return false;
        }
    }
    return validateStorageObject(options.stateDirectory, 02730,
               options.storageOwner, options.storageGroup, true, false,
               error) &&
        createStorageFile(options.transactionLockFile, options.storageOwner,
            options.storageGroup, true, error);
}

bool prepareHistoryFile(
    const AltPamPasswordHistoryTopologyOptions& options,
    std::string& error) {
    return createStorageFile(options.historyFile, options.storageOwner,
        options.storageGroup, false, error);
}

bool validateHistoryFiles(
    const AltPamPasswordHistoryTopologyOptions& options,
    std::string& error) {
    auto historyBackupFile = options.historyFile;
    historyBackupFile += ".old";
    return validateStorageObject(options.historyFile, 0660, std::nullopt,
               options.storageGroup, false, false, error) &&
        validateStorageObject(historyBackupFile, 0660, std::nullopt,
            options.storageGroup, false, true, error);
}

} // namespace

bool verifyAltPamPasswordHistoryTransactionModule(
    const std::vector<std::filesystem::path>& directories,
    std::string& error) {
    for (const auto& directory : directories) {
        const auto path = directory / "pam_fic_pwtxn.so";
        fic::core::TrustedFileReadOptions options;
        options.expectedOwner = ::geteuid();
        options.forbiddenMode = S_IWGRP | S_IWOTH;
        int systemError = 0;
        if (fic::core::inspectTrustedFile(
                path, options, nullptr, error, &systemError))
            return true;
        if (systemError != ENOENT)
            return false;
    }
    error = "pam_fic_pwtxn.so is not installed in a configured PAM module directory";
    return false;
}

namespace {

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r");
    if (first == std::string::npos)
        return {};
    const auto last = value.find_last_not_of(" \t\r");
    return value.substr(first, last - first + 1);
}

} // namespace

bool verifyAltPamPasswordHistoryStorageConfig(
    const std::filesystem::path& configPath,
    const std::filesystem::path& historyPath,
    std::string& error,
    const fic::core::TrustedFilePostValidationHook& validationHook) {
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    std::string content;
    if (!fic::core::readTrustedFile(
            configPath, options, content, error, nullptr, validationHook))
        return false;
    std::istringstream input(content);
    std::size_t fileAssignments = 0;
    std::string line;
    while (std::getline(input, line)) {
        const auto comment = line.find('#');
        if (comment != std::string::npos)
            line.erase(comment);
        const auto equals = line.find('=');
        if (equals == std::string::npos || trim(line.substr(0, equals)) != "file")
            continue;
        ++fileAssignments;
        if (trim(line.substr(equals + 1)) != historyPath.string()) {
            error = "pam_pwhistory configuration uses an unexpected history file";
            return false;
        }
    }
    if (fileAssignments != 1) {
        error = "pam_pwhistory configuration must declare exactly one history file";
        return false;
    }
    error.clear();
    return true;
}

AltPamPasswordHistoryTopologyManager::AltPamPasswordHistoryTopologyManager(
    fic::platform::PamPlatformConfig platformConfig,
    AltPamPasswordHistoryTopologyOptions options)
    : platformConfig_(std::move(platformConfig)), options_(std::move(options)) {
    if (!options_.writer)
        options_.writer = AtomicFileWriter::write;
    options_.writeOptions.createIfMissing = false;
    options_.writeOptions.rejectSymlink = true;
}

bool AltPamPasswordHistoryTopologyManager::prepareStorage(
    std::string& error) const {
    ExclusivePidLock topologyLock(options_.lockFilePath.string(),
        options_.lockDebugLogPath.string(), false);
    if (!topologyLock.acquire()) {
        error = "could not acquire PAM topology lock";
        return false;
    }
    if (!prepareStorageBeforeTransaction(options_, error))
        return false;
    TransactionFileLock transactionLock;
    if (transactionLock.acquire(options_, error) !=
        TransactionLockResult::Acquired)
        return false;
    if (!prepareHistoryFile(options_, error) ||
        !validateHistoryFiles(options_, error))
        return false;
    error.clear();
    return true;
}

bool AltPamPasswordHistoryTopologyManager::verifySemanticEffectiveness(
    std::string& error) const {
    if (options_.semanticVerifier)
        return options_.semanticVerifier(error);
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::PasswordHistory);
    if (capability == nullptr) {
        error = "password-history capability is missing";
        return false;
    }
    if (!verifyAltPamPasswordHistoryTransactionModule(
            platformConfig_.moduleDirectories, error) ||
        !verifyAltPamPasswordHistoryStorageConfig(
            capability->configPath, options_.historyFile, error,
            options_.readValidationHook))
        return false;
    PamConfiguration configuration(platformConfig_);
    PamCapabilityVerification verification;
    if (!PamCapabilityVerifier::verify(configuration, platformConfig_,
            {capability->topologyTarget.filename().string()},
            PamCapability::PasswordHistory, PamProviderKind::PamPwhistory,
            verification, PamCapabilityVerificationMode::Structural)) {
        error = formatPamCapabilityVerification(verification);
        return false;
    }
    return true;
}

bool AltPamPasswordHistoryTopologyManager::canEnable(std::string& error) const {
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::PasswordHistory);
    if (capability == nullptr || capability->topology !=
            fic::platform::PamTopologyStrategyKind::AltTcbManaged ||
        capability->topologyTarget.empty() || options_.lockFilePath.empty()) {
        error = "ALT pam_pwhistory topology is unsupported by this platform profile";
        return false;
    }
    error.clear();
    return true;
}

bool AltPamPasswordHistoryTopologyManager::status(
    AltPamPasswordHistoryTopologyState& state, std::string& error) {
    bool unavailable = false;
    return statusImpl(state, unavailable, error);
}

bool AltPamPasswordHistoryTopologyManager::statusImpl(
    AltPamPasswordHistoryTopologyState& state, bool& unavailable,
    std::string& error) {
    unavailable = false;
    if (!canEnable(error))
        return false;
    ExclusivePidLock lock(options_.lockFilePath.string(),
        options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock";
        return false;
    }
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::PasswordHistory);
    TargetSnapshot snapshot;
    std::vector<PhysicalLine> lines;
    std::vector<PamRule> rules;
    ManagedBlock block;
    if (!inspectSecureTarget(capability->topologyTarget, snapshot, error,
                             options_.readValidationHook) ||
        !inspectTopology(capability->topologyTarget, snapshot.content, lines,
                         rules, block, error))
        return false;
    if (!verifyNoExternalHistory(
            platformConfig_, *capability, block.present, error))
        return false;
    if (!block.present) {
        state = AltPamPasswordHistoryTopologyState::Disabled;
        return true;
    }
    if (!validateStorageObject(options_.stateDirectory, 02730,
            options_.storageOwner, options_.storageGroup, true, false, error))
        return false;
    TransactionFileLock transactionLock;
    const auto lockResult = transactionLock.acquire(options_, error);
    if (lockResult == TransactionLockResult::Busy) {
        unavailable = true;
        return false;
    }
    if (lockResult == TransactionLockResult::Failed ||
        !validateHistoryFiles(options_, error) ||
        !verifySemanticEffectiveness(error))
        return false;
    state = AltPamPasswordHistoryTopologyState::Enabled;
    return true;
}

bool AltPamPasswordHistoryTopologyManager::inspect(PamTopologyStatus& result,
                                                    std::string& error) {
    AltPamPasswordHistoryTopologyState current;
    bool unavailable = false;
    if (!statusImpl(current, unavailable, error)) {
        result = {unavailable ? PamTopologyState::Unavailable
                              : PamTopologyState::Broken,
                  true, error};
        return false;
    }
    result = {current == AltPamPasswordHistoryTopologyState::Enabled
                  ? PamTopologyState::Enabled
                  : PamTopologyState::Disabled,
              true, {}};
    return true;
}

bool AltPamPasswordHistoryTopologyManager::enable(std::string& error) {
    if (!canEnable(error))
        return false;
    ExclusivePidLock topologyLock(options_.lockFilePath.string(),
        options_.lockDebugLogPath.string(), false);
    if (!topologyLock.acquire()) {
        error = "could not acquire PAM topology lock";
        return false;
    }
    if (!prepareStorageBeforeTransaction(options_, error))
        return false;
    TransactionFileLock transactionLock;
    if (transactionLock.acquire(options_, error) !=
            TransactionLockResult::Acquired ||
        !prepareHistoryFile(options_, error) ||
        !validateHistoryFiles(options_, error))
        return false;
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::PasswordHistory);
    TargetSnapshot original;
    std::vector<PhysicalLine> lines;
    std::vector<PamRule> rules;
    ManagedBlock block;
    if (!inspectSecureTarget(capability->topologyTarget, original, error,
                             options_.readValidationHook) ||
        !inspectTopology(capability->topologyTarget, original.content, lines,
                         rules, block, error))
        return false;
    if (!verifyNoExternalHistory(
            platformConfig_, *capability, block.present, error))
        return false;
    if (block.present)
        return verifySemanticEffectiveness(error);

    std::optional<std::size_t> tcbLine;
    for (const auto& rule : rules) {
        if (rule.group == PamManagementGroup::Password &&
            moduleName(rule) == "pam_tcb.so" &&
            hasArgument(rule, "write_to=tcb"))
            tcbLine = rule.line - 1;
    }
    if (!tcbLine.has_value() || *tcbLine >= lines.size()) {
        error = "could not find the unique ALT pam_tcb password backend";
        return false;
    }
    std::vector<PhysicalLine> candidateLines;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (index != *tcbLine) {
            candidateLines.push_back(lines[index]);
            continue;
        }
        candidateLines.push_back({BEGIN, "\n"});
        candidateLines.push_back({LOCK_RULE, "\n"});
        candidateLines.push_back({HISTORY_RULE, "\n"});
        candidateLines.push_back(lines[index]);
        candidateLines.push_back({UNLOCK_RULE, "\n"});
        candidateLines.push_back({END, "\n"});
    }
    const std::string candidate = joinLines(candidateLines);
    std::vector<PhysicalLine> checkedLines;
    std::vector<PamRule> checkedRules;
    ManagedBlock checkedBlock;
    if (!inspectTopology(capability->topologyTarget, candidate, checkedLines,
                         checkedRules, checkedBlock, error) ||
        !checkedBlock.present)
        return false;
    std::string writeError;
    if (!options_.writer(capability->topologyTarget.string(), candidate,
            writeOptionsFor(options_.writeOptions, original), &writeError)) {
        error = "could not atomically enable FIC pam_pwhistory topology: " +
            writeError;
        return false;
    }
    if (!verifySemanticEffectiveness(error)) {
        TargetSnapshot written;
        std::string rollbackError;
        if (!inspectSecureTarget(capability->topologyTarget, written,
                                 rollbackError,
                                 options_.readValidationHook) ||
            !options_.writer(capability->topologyTarget.string(),
                original.content,
                writeOptionsFor(options_.writeOptions, written),
                &rollbackError)) {
            error += "; CRITICAL: rollback failed: " + rollbackError;
            return false;
        }
        error += "; original PAM configuration restored";
        return false;
    }
    error.clear();
    return true;
}

bool AltPamPasswordHistoryTopologyManager::disable(std::string& error) {
    if (!canEnable(error))
        return false;
    ExclusivePidLock lock(options_.lockFilePath.string(),
        options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock";
        return false;
    }
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::PasswordHistory);
    TargetSnapshot original;
    std::vector<PhysicalLine> lines;
    std::vector<PamRule> rules;
    ManagedBlock block;
    if (!inspectSecureTarget(capability->topologyTarget, original, error,
                             options_.readValidationHook) ||
        !inspectTopology(capability->topologyTarget, original.content, lines,
                         rules, block, error))
        return false;
    if (!verifyNoExternalHistory(
            platformConfig_, *capability, block.present, error))
        return false;
    if (!block.present) {
        error.clear();
        return true;
    }
    if (!validateStorageObject(options_.stateDirectory, 02730,
            options_.storageOwner, options_.storageGroup, true, false, error))
        return false;
    TransactionFileLock transactionLock;
    if (transactionLock.acquire(options_, error) !=
        TransactionLockResult::Acquired)
        return false;
    std::vector<PhysicalLine> candidateLines;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (index == block.tcb)
            candidateLines.push_back(lines[index]);
        if (index < block.begin || index > block.end)
            candidateLines.push_back(lines[index]);
    }
    const std::string candidate = joinLines(candidateLines);
    std::vector<PhysicalLine> checkedLines;
    std::vector<PamRule> checkedRules;
    ManagedBlock checkedBlock;
    if (!inspectTopology(capability->topologyTarget, candidate, checkedLines,
                         checkedRules, checkedBlock, error) ||
        checkedBlock.present)
        return false;
    std::string writeError;
    if (!options_.writer(capability->topologyTarget.string(), candidate,
            writeOptionsFor(options_.writeOptions, original), &writeError)) {
        error = "could not atomically disable FIC pam_pwhistory topology: " +
            writeError;
        return false;
    }
    error.clear();
    return true;
}

std::string altPamPasswordHistoryTopologyStateName(
    AltPamPasswordHistoryTopologyState state) {
    return state == AltPamPasswordHistoryTopologyState::Enabled
        ? "enabled" : "disabled";
}

} // namespace fic::identity::pam
