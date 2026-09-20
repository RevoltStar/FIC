#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

constexpr const char* kDefaultStateDirectory = "/var/lib/pam";
constexpr const char* kDefaultConfigDirectory = "/etc/pam.d";

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "pam-auth-update timed out";
    }
    return "pam-auth-update exited with code " +
        std::to_string(result.exitCode) +
        (result.standardError.empty() ? "" : ": " + result.standardError);
}

bool readFileIfPresent(const std::filesystem::path& path,
                       std::string& content) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }
    content.assign(std::istreambuf_iterator<char>(stream),
                   std::istreambuf_iterator<char>());
    return true;
}

bool pamStackContainsModule(const std::vector<PamStackEntry>& entries,
                            const std::string& moduleName) {
    for (const auto& entry : entries) {
        if (std::filesystem::path(entry.rule.module).filename() == moduleName) {
            return true;
        }
        if (pamStackContainsModule(entry.substack, moduleName)) {
            return true;
        }
    }
    return false;
}

bool contains(const std::vector<std::string>& values,
              const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

} // namespace

PamAuthUpdateTopologyManager::PamAuthUpdateTopologyManager(
    fic::platform::PamPlatformConfig platformConfig,
    fic::platform::PamCapabilityConfig capability,
    std::vector<std::string> services,
    const fic::platform::PlatformExecutableResolver& executables,
    PamAuthUpdateTopologyManagerOptions options)
    : platformConfig_(std::move(platformConfig)),
      capability_(std::move(capability)),
      services_(std::move(services)),
      executables_(executables),
      options_(std::move(options)) {
    if (!options_.runner) {
        options_.runner = VerifiedProcessExecutor::execute;
    }
}

bool PamAuthUpdateTopologyManager::resolveExecutable(
    std::filesystem::path& executable,
    std::string& error) const {
    return executables_.resolve(
        fic::platform::ExecutableId::PamAuthUpdate, executable, error);
}

std::filesystem::path PamAuthUpdateTopologyManager::stateDirectory() const {
    return options_.stateDirectory.empty()
        ? std::filesystem::path(kDefaultStateDirectory)
        : options_.stateDirectory;
}

std::filesystem::path PamAuthUpdateTopologyManager::configDirectory() const {
    return options_.configDirectory.empty()
        ? std::filesystem::path(kDefaultConfigDirectory)
        : options_.configDirectory;
}

std::vector<std::filesystem::path>
PamAuthUpdateTopologyManager::transactionPaths() const {
    if (!options_.statePaths.empty()) {
        return options_.statePaths;
    }
    static const std::vector<std::string> kStateFiles = {
        "auth", "account", "password", "session", "session-noninteractive",
        "seen"};
    static const std::vector<std::string> kConfigFiles = {
        "common-auth", "common-account", "common-password",
        "common-session", "common-session-noninteractive"};
    std::vector<std::filesystem::path> paths;
    paths.reserve(kStateFiles.size() + kConfigFiles.size());
    for (const std::string& name : kStateFiles) {
        paths.push_back(stateDirectory() / name);
    }
    for (const std::string& name : kConfigFiles) {
        paths.push_back(configDirectory() / name);
    }
    return paths;
}

bool PamAuthUpdateTopologyManager::enabledStateIdentifiers(
    std::set<std::string>& identifiers,
    std::string& error) const {
    identifiers.clear();
    for (const std::string& type :
         {"auth", "account", "password", "session",
          "session-noninteractive"}) {
        const std::filesystem::path path = stateDirectory() / type;
        std::error_code statusError;
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(path, statusError);
        if (statusError) {
            if (statusError ==
                std::make_error_code(std::errc::no_such_file_or_directory)) {
                continue;
            }
            error = "could not stat pam-auth-update state file " +
                path.string() + ": " + statusError.message();
            return false;
        }
        if (!std::filesystem::exists(status)) {
            continue;
        }
        if (!std::filesystem::is_regular_file(status)) {
            error = "pam-auth-update state path is not a regular file: " +
                path.string();
            return false;
        }
        std::string content;
        if (!readFileIfPresent(path, content)) {
            error = "could not read pam-auth-update state file " +
                path.string();
            return false;
        }
        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            const std::string prefix = "Module: ";
            if (line.compare(0, prefix.size(), prefix) == 0) {
                identifiers.insert(line.substr(prefix.size()));
            }
        }
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::detectOwnership(
    Ownership& ownership,
    std::string& error) const {
    std::set<std::string> enabled;
    if (!enabledStateIdentifiers(enabled, error)) {
        return false;
    }
    std::set<std::string> ficEnabled;
    for (const std::string& identifier : knownActivationIdentifiers()) {
        if (enabled.count(identifier) != 0) {
            ficEnabled.insert(identifier);
        }
    }
    if (ficEnabled.empty()) {
        ownership = Ownership::NoFicProfiles;
        error.clear();
        return true;
    }
    if (capability_.capability ==
            fic::platform::PamCapability::AuthenticationLockout &&
        !capability_.strategyActivations.empty()) {
        // The selected FIC profiles must exactly match one declared
        // strategy recipe. Partial or mixed selections leave the topology
        // unmanageable instead of guessing the active strategy.
        for (const auto& activation : capability_.strategyActivations) {
            const std::set<std::string> recipe(
                activation.activationIdentifiers.begin(),
                activation.activationIdentifiers.end());
            if (ficEnabled == recipe) {
                ownership = Ownership::FicOwned;
                error.clear();
                return true;
            }
        }
        ownership = Ownership::InvalidSelection;
        error.clear();
        return true;
    }
    ownership = Ownership::FicOwned;
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::existingVerificationServices(
    PamConfiguration& configuration,
    std::vector<std::string>& existing,
    std::string& error) const {
    if (!configuration.existingServices(services_, existing, error)) {
        if (error.empty()) {
            error = "could not determine existing PAM services";
        } else {
            error = "could not determine existing PAM services: " + error;
        }
        return false;
    }
    if (existing.empty()) {
        error = "none of the configured PAM services exists";
        return false;
    }
    error.clear();
    return true;
}

PamAuthUpdateTopologyManager::ExternalFaillockGraphState
PamAuthUpdateTopologyManager::externalFaillockGraphState(
    std::string& error) const {
    PamConfiguration configuration(platformConfig_);
    std::vector<std::string> services;
    if (!existingVerificationServices(configuration, services, error)) {
        return ExternalFaillockGraphState::Error;
    }
    for (PamManagementGroup group :
         {PamManagementGroup::Auth, PamManagementGroup::Account}) {
        for (const std::string& service : services) {
            PamEffectiveStack stack;
            if (!configuration.buildEffectiveStack(
                    service, group, stack, error)) {
                error = "could not build effective PAM " +
                    pamManagementGroupName(group) + " stack for service " +
                    service + ": " + error;
                return ExternalFaillockGraphState::Error;
            }
            if (pamStackContainsModule(stack.entries, "pam_faillock.so")) {
                error.clear();
                return ExternalFaillockGraphState::Present;
            }
        }
    }
    error.clear();
    return ExternalFaillockGraphState::Clear;
}

bool PamAuthUpdateTopologyManager::detectUniformStrategy(
    std::optional<fic::platform::PamFaillockStrategy>& strategy,
    std::string& error) const {
    strategy.reset();
    if (services_.empty()) {
        error = "no PAM services are configured for topology verification";
        return false;
    }
    PamConfiguration configuration(platformConfig_);
    std::vector<std::string> services;
    if (!existingVerificationServices(configuration, services, error)) {
        return false;
    }
    for (const std::string& service : services) {
        PamEffectiveStack stack;
        if (!configuration.buildEffectiveStack(
                service, PamManagementGroup::Auth, stack, error)) {
            error = "could not build the effective PAM authentication stack "
                "for service " + service + ": " + error;
            return false;
        }
        std::string detectionError;
        const std::optional<fic::platform::PamFaillockStrategy> detected =
            detectPamFaillockStrategy(stack, detectionError);
        if (!detected.has_value()) {
            error = "cannot prove the active pam_faillock strategy for "
                "service " + service + ": " + detectionError;
            return false;
        }
        if (!strategy.has_value()) {
            strategy = detected;
        } else if (*strategy != *detected) {
            error = "conflicting pam_faillock strategies across PAM "
                "services: " +
                fic::platform::pamFaillockStrategyName(*strategy) + " and " +
                fic::platform::pamFaillockStrategyName(*detected) +
                " (service " + service + ")";
            return false;
        }
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::inspect(PamTopologyStatus& status,
                                            std::string& error) {
    PamConfiguration configuration(platformConfig_);
    PamCapabilityVerification verification;
    if (PamCapabilityVerifier::verify(
            configuration, platformConfig_, services_, capability_.capability,
            capability_.provider, verification,
            PamCapabilityVerificationMode::Structural)) {
        status = {PamTopologyState::Enabled, true, {}, {}};
        if (capability_.capability ==
            fic::platform::PamCapability::AuthenticationLockout) {
            std::optional<fic::platform::PamFaillockStrategy> strategy;
            if (!detectUniformStrategy(strategy, error)) {
                status = {PamTopologyState::Broken, true, {}, error};
                return false;
            }
            status.activeStrategy = strategy;
        }
        // Ownership: a topology whose faillock rules were not selected
        // through FIC pam-auth-update profiles is external. It can be
        // inspected, but FIC must not treat it as its own and must not
        // change its strategy or stack FIC profiles on top of it.
        Ownership ownership = Ownership::NoFicProfiles;
        std::string ownershipError;
        if (!detectOwnership(ownership, ownershipError)) {
            status = {PamTopologyState::Broken, true, {},
                "could not determine pam-auth-update ownership: " +
                    ownershipError};
            error = status.detail;
            return false;
        }
        switch (ownership) {
        case Ownership::FicOwned:
            if (capability_.capability ==
                fic::platform::PamCapability::AuthenticationLockout) {
                const auto* recipe = status.activeStrategy.has_value()
                    ? strategyActivationIdentifiers(*status.activeStrategy,
                                                    error)
                    : nullptr;
                std::set<std::string> selected;
                if (recipe == nullptr ||
                    !enabledStateIdentifiers(selected, error)) {
                    if (error.empty())
                        error = "active pam_faillock strategy has no FIC recipe";
                    status = {PamTopologyState::Broken, true, {}, error};
                    return false;
                }
                std::set<std::string> ficSelected;
                for (const auto& id : knownActivationIdentifiers()) {
                    if (selected.count(id) != 0) ficSelected.insert(id);
                }
                if (ficSelected != std::set<std::string>(
                        recipe->begin(), recipe->end())) {
                    status = {PamTopologyState::Broken, true, {},
                        "FIC profile selection does not match the effective "
                        "pam_faillock strategy"};
                    error = status.detail;
                    return false;
                }
            }
            break;
        case Ownership::NoFicProfiles:
            status.manageable = false;
            status.detail =
                "external " + pamProviderName(capability_.provider) +
                " topology is not selected through FIC pam-auth-update "
                "profiles and is not managed by FIC";
            break;
        case Ownership::InvalidSelection:
            status = {PamTopologyState::Broken, true, {},
                "FIC pam-auth-update profile selection is partial or "
                "mixed and does not match any declared strategy recipe"};
            error = status.detail;
            return false;
        }
        error.clear();
        return true;
    }
    status.manageable = true;
    status.detail = formatPamCapabilityVerification(verification);
    if (verification.state == PamEnforcementState::Missing ||
        verification.state == PamEnforcementState::Inactive) {
        Ownership ownership = Ownership::NoFicProfiles;
        if (!detectOwnership(ownership, error)) {
            status = {PamTopologyState::Broken, true, {}, error};
            return false;
        }
        if (ownership != Ownership::NoFicProfiles) {
            status = {PamTopologyState::Broken, true, {},
                "FIC pam-auth-update selection exists but the capability "
                "topology is not structurally effective"};
            error = status.detail;
            return false;
        }
        status.state = PamTopologyState::Disabled;
        status.activeStrategy.reset();
        error.clear();
        return true;
    }
    status.state = PamTopologyState::Broken;
    status.activeStrategy.reset();
    error = status.detail;
    return false;
}

std::vector<std::string>
PamAuthUpdateTopologyManager::knownActivationIdentifiers() const {
    return activationIdentifiers(capability_);
}

const std::vector<std::string>*
PamAuthUpdateTopologyManager::strategyActivationIdentifiers(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) const {
    for (const auto& activation : capability_.strategyActivations) {
        if (activation.strategy == strategy) {
            return &activation.activationIdentifiers;
        }
    }
    error = "platform profile declares no pam-auth-update activation "
        "recipe for pam_faillock strategy " +
        fic::platform::pamFaillockStrategyName(strategy);
    return nullptr;
}

bool PamAuthUpdateTopologyManager::runPamAuthUpdate(
    const std::vector<std::string>& arguments,
    std::string& error) {
    std::filesystem::path executable;
    if (!resolveExecutable(executable, error)) {
        return false;
    }
    ProcessOptions processOptions;
    processOptions.timeout = std::chrono::seconds(30);
    processOptions.clearEnvironment = true;
    const ProcessResult result = options_.runner(
        executable.string(), arguments, processOptions);
    if (!result.success()) {
        error = "pam-auth-update failed: " + processFailure(result);
        return false;
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::canEnable(std::string& error) const {
    if (capability_.topology !=
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate ||
        (capability_.activationIdentifiers.empty() &&
            capability_.strategyActivations.empty())) {
        error = "PAM capability has no pam-auth-update activation recipe";
        return false;
    }
    std::filesystem::path executable;
    return resolveExecutable(executable, error);
}

bool PamAuthUpdateTopologyManager::enable(std::string& error) {
    if (!capability_.supportedFaillockStrategies.empty()) {
        return enableStrategy(capability_.defaultFaillockStrategy, error);
    }
    if (!canEnable(error)) {
        return false;
    }
    const std::vector<std::string>& identifiers =
        capability_.activationIdentifiers;
    if (identifiers.empty()) {
        error = "PAM capability has no pam-auth-update activation recipe";
        return false;
    }

    PamTopologyStatus current;
    if (!inspect(current, error)) {
        return false;
    }
    if (current.state == PamTopologyState::Enabled) {
        if (current.manageable) {
            error.clear();
            return true;
        }
        error = "external PAM topology is not selected through FIC "
            "pam-auth-update profiles and is not managed by FIC";
        return false;
    }

    StateSnapshot snapshot;
    if (!snapshotState(snapshot, error)) {
        return false;
    }
    std::vector<std::string> arguments{"--enable"};
    arguments.insert(arguments.end(), identifiers.begin(), identifiers.end());
    std::string failure;
    if (!runPamAuthUpdate(arguments, failure)) {
        return rollback(snapshot, std::nullopt, failure, error);
    }
    PamTopologyStatus after;
    std::string postconditionError;
    if (!inspect(after, postconditionError) ||
        after.state != PamTopologyState::Enabled ||
        !after.manageable) {
        return rollback(snapshot, std::nullopt,
            "pam-auth-update activation did not produce a managed enabled "
            "topology: " +
                (postconditionError.empty() ? after.detail
                                            : postconditionError),
            error);
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::disable(std::string& error) {
    Ownership ownership = Ownership::NoFicProfiles;
    if (!detectOwnership(ownership, error)) return false;
    if (ownership == Ownership::NoFicProfiles) {
        error.clear();
        return true;
    }
    if (ownership != Ownership::FicOwned) {
        error = "FIC pam-auth-update selection is partial or mixed";
        return false;
    }
    PamTopologyStatus before;
    if (!inspect(before, error) || before.state != PamTopologyState::Enabled ||
        !before.manageable) {
        if (error.empty()) error = "FIC-owned PAM topology is not proven";
        return false;
    }
    std::set<std::string> enabled;
    if (!enabledStateIdentifiers(enabled, error)) return false;
    std::vector<std::string> arguments{"--disable"};
    for (const std::string& identifier : knownActivationIdentifiers()) {
        if (enabled.count(identifier) != 0) arguments.push_back(identifier);
    }
    if (arguments.size() == 1) {
        error = "FIC PAM selections disappeared before disable";
        return false;
    }
    if (!runPamAuthUpdate(arguments, error)) return false;
    Ownership after = Ownership::InvalidSelection;
    if (!detectOwnership(after, error) || after != Ownership::NoFicProfiles) {
        if (error.empty()) error = "FIC selections remain after pam-auth-update";
        return false;
    }
    PamTopologyStatus current;
    // A foreign equivalent topology may remain active; it must not be
    // removed. The required postcondition is absence of FIC selections.
    if (!inspect(current, error) ||
        (current.state != PamTopologyState::Disabled &&
         !(current.state == PamTopologyState::Enabled &&
           !current.manageable))) {
        if (error.empty())
            error = "PAM release did not reach a FIC-selection-free topology";
        return false;
    }
    return confirmDurable(error);
}

bool PamAuthUpdateTopologyManager::confirmDurable(std::string& error) const {
    // pam-auth-update is external and may use either in-place writes or
    // rename. Bind file and parent-directory fsync to each captured current
    // state, then re-prove it; do not infer durability from process exit.
    std::vector<std::pair<std::filesystem::path,
                          std::optional<AtomicTargetState>>> capturedStates;
    for (const auto& path : transactionPaths()) {
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(path, ec);
        if (ec == std::errc::no_such_file_or_directory ||
            (!ec && !std::filesystem::exists(status))) {
            if (!AtomicFileWriter::fsyncParentDirectoryForPath(
                    path.string(), &error)) {
                return false;
            }
            const auto rechecked = std::filesystem::symlink_status(path, ec);
            if (ec != std::errc::no_such_file_or_directory &&
                (ec || std::filesystem::exists(rechecked))) {
                if (error.empty()) error = "PAM state appeared during durability proof";
                return false;
            }
            capturedStates.emplace_back(path, std::nullopt);
            continue;
        }
        if (ec || !std::filesystem::is_regular_file(status)) {
            error = "unsafe PAM state path: " + path.string();
            return false;
        }
        AtomicTargetState captured;
        if (!AtomicFileWriter::captureTargetState(
                path.string(), captured, &error)) return false;
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            error = "could not open PAM state for fsync: " +
                std::string(std::strerror(errno));
            return false;
        }
        struct stat fdState {};
        const bool matched = ::fstat(fd, &fdState) == 0 &&
            fdState.st_dev == captured.identity.device &&
            fdState.st_ino == captured.identity.inode;
        const bool synced = matched && ::fsync(fd) == 0;
        const int savedErrno = errno;
        ::close(fd);
        if (!synced) {
            error = matched
                ? "PAM state fsync failed: " + path.string() + ": " +
                    std::strerror(savedErrno)
                : "PAM state changed before fsync: " + path.string();
            return false;
        }
        if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
                path.string(), captured, &error)) return false;
        capturedStates.emplace_back(path, std::move(captured));
    }
    for (const auto& [path, captured] : capturedStates) {
        if (captured.has_value()) {
            if (!AtomicFileWriter::targetStateMatches(
                    path.string(), *captured, &error)) return false;
        } else {
            std::error_code ec;
            const auto status = std::filesystem::symlink_status(path, ec);
            if (ec != std::errc::no_such_file_or_directory &&
                (ec || std::filesystem::exists(status))) {
                error = "PAM state appeared after durability proof: " +
                    path.string();
                return false;
            }
        }
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::canEnableStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) const {
    if (capability_.capability !=
        fic::platform::PamCapability::AuthenticationLockout) {
        error = "pam_faillock strategies apply only to the authentication "
            "lockout capability";
        return false;
    }
    if (!fic::platform::supportsPamFaillockStrategy(capability_, strategy)) {
        error = "pam_faillock strategy " +
            fic::platform::pamFaillockStrategyName(strategy) +
            " is not supported by this platform profile";
        return false;
    }
    if (strategyActivationIdentifiers(strategy, error) == nullptr) {
        return false;
    }
    std::filesystem::path executable;
    if (!resolveExecutable(executable, error)) {
        return false;
    }
    // An external faillock topology must never be overwritten with FIC
    // profiles: FIC can inspect and analyze it, but not mutate it.
    Ownership ownership = Ownership::NoFicProfiles;
    std::string ownershipError;
    if (!detectOwnership(ownership, ownershipError)) {
        error = "could not determine pam-auth-update ownership; refusing to "
            "change the strategy: " + ownershipError;
        return false;
    }
    switch (ownership) {
    case Ownership::FicOwned:
        break;
    case Ownership::NoFicProfiles: {
        std::string externalError;
        const ExternalFaillockGraphState graph =
            externalFaillockGraphState(externalError);
        if (graph == ExternalFaillockGraphState::Present) {
            error = "external pam_faillock topology already exists and is "
                "not selected through FIC pam-auth-update profiles; FIC "
                "will not take ownership";
            if (!externalError.empty()) {
                error += ": " + externalError;
            }
            return false;
        }
        if (graph == ExternalFaillockGraphState::Error) {
            error = "could not inspect existing PAM topology for external "
                "pam_faillock; refusing to change the strategy: " +
                externalError;
            return false;
        }
        break;
    }
    case Ownership::InvalidSelection:
        error = "FIC pam-auth-update profile selection is partial or mixed "
            "and does not match any declared strategy recipe; refusing to "
            "change the strategy";
        return false;
    }
    return true;
}

bool PamAuthUpdateTopologyManager::enableStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) {
    if (!canEnableStrategy(strategy, error)) {
        return false;
    }
    const std::vector<std::string>* desiredIdentifiers =
        strategyActivationIdentifiers(strategy, error);
    if (desiredIdentifiers == nullptr) {
        return false;
    }

    // Idempotency: the requested strategy is already active.
    PamTopologyStatus current;
    if (!inspect(current, error)) {
        return false;
    }
    if (current.state == PamTopologyState::Enabled && !current.manageable) {
        error = "external pam_faillock topology is not managed by FIC; "
            "refusing to change the strategy";
        return false;
    }
    if (current.state == PamTopologyState::Enabled &&
        current.activeStrategy == strategy) {
        error.clear();
        return true;
    }

    const std::optional<fic::platform::PamFaillockStrategy> priorStrategy =
        current.state == PamTopologyState::Enabled
            ? current.activeStrategy
            : std::nullopt;

    // Transaction: snapshot the pam-auth-update state database and the
    // generated common-* configs, apply the whole transition with a single
    // pam-auth-update invocation (--disable and --enable in one call, so
    // the generated stacks are recomputed once), then re-read and verify
    // the exact requested strategy. Any failure restores the snapshot.
    StateSnapshot snapshot;
    if (!snapshotState(snapshot, error)) {
        return false;
    }

    std::vector<std::string> arguments;
    std::vector<std::string> toDisable;
    for (const std::string& identifier : knownActivationIdentifiers()) {
        if (!contains(*desiredIdentifiers, identifier)) {
            toDisable.push_back(identifier);
        }
    }
    if (!toDisable.empty()) {
        arguments.push_back("--disable");
        arguments.insert(arguments.end(), toDisable.begin(), toDisable.end());
    }
    arguments.push_back("--enable");
    arguments.insert(arguments.end(), desiredIdentifiers->begin(),
                     desiredIdentifiers->end());

    std::string failure;
    if (!runPamAuthUpdate(arguments, failure)) {
        return rollback(snapshot, priorStrategy, failure, error);
    }

    std::string postconditionError;
    if (!verifyPostcondition(strategy, postconditionError)) {
        return rollback(snapshot, priorStrategy,
            "pam-auth-update strategy activation did not produce the "
            "requested strategy " +
                fic::platform::pamFaillockStrategyName(strategy) + ": " +
                postconditionError,
            error);
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::snapshotState(
    StateSnapshot& snapshot,
    std::string& error) const {
    snapshot.clear();
    for (const std::filesystem::path& path : transactionPaths()) {
        std::string content;
        if (readFileIfPresent(path, content)) {
            snapshot[path] = content;
        } else if (!std::filesystem::exists(path)) {
            snapshot[path] = std::nullopt;
        } else {
            error = "could not read the PAM state file " + path.string() +
                " for the transition snapshot";
            return false;
        }
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::restoreState(
    const StateSnapshot& snapshot,
    std::string& error) const {
    for (const auto& [path, content] : snapshot) {
        if (content.has_value()) {
            AtomicWriteOptions writeOptions;
            writeOptions.createIfMissing = true;
            std::string writeError;
            if (!AtomicFileWriter::write(path.string(), *content,
                                         writeOptions, &writeError)) {
                error = "could not restore " + path.string() + ": " +
                    writeError;
                return false;
            }
        } else {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::verifyPostcondition(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) {
    PamTopologyStatus after;
    if (!inspect(after, error)) {
        error = "topology verification failed: " +
            (after.detail.empty() ? error : after.detail);
        return false;
    }
    if (after.state != PamTopologyState::Enabled ||
        after.activeStrategy != strategy) {
        error = "active topology is " +
            std::string(after.state == PamTopologyState::Enabled
                ? "enabled with strategy " +
                    (after.activeStrategy.has_value()
                        ? fic::platform::pamFaillockStrategyName(
                              *after.activeStrategy)
                        : std::string("unknown"))
                : "not enabled") +
            (after.detail.empty() ? "" : ": " + after.detail);
        return false;
    }
    if (!after.manageable) {
        error = "topology is not managed by FIC after the transition";
        return false;
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::rollback(
    const StateSnapshot& snapshot,
    const std::optional<fic::platform::PamFaillockStrategy>& priorStrategy,
    const std::string& failure,
    std::string& error) {
    const auto critical = [&failure](const std::string& reason) {
        return failure +
            "; CRITICAL: PAM configuration may be inconsistent: "
            "rollback failed: " + reason;
    };
    std::string restoreError;
    if (!restoreState(snapshot, restoreError)) {
        error = critical(restoreError);
        return false;
    }
    // Verify the rollback: the restored files must match the snapshot
    // byte-for-byte and the topology must report the prior state again.
    StateSnapshot after;
    std::string verifyError;
    if (!snapshotState(after, verifyError) || after != snapshot) {
        error = critical(verifyError.empty()
            ? "restored files do not match the snapshot"
            : verifyError);
        return false;
    }
    PamTopologyStatus restored;
    std::string inspectError;
    if (!inspect(restored, inspectError) ||
        restored.state != (priorStrategy.has_value()
            ? PamTopologyState::Enabled
            : PamTopologyState::Disabled) ||
        (priorStrategy.has_value() &&
         restored.activeStrategy != priorStrategy)) {
        error = critical(inspectError.empty()
            ? "topology does not report the original state after rollback"
            : inspectError);
        return false;
    }
    error = failure + "; original PAM configuration restored";
    return false;
}

} // namespace fic::identity::pam
