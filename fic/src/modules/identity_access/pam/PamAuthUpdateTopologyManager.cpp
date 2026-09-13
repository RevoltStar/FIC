#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>
#include <utility>

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

std::set<std::string>
PamAuthUpdateTopologyManager::enabledStateIdentifiers() const {
    std::set<std::string> identifiers;
    for (const std::string& type :
         {"auth", "account", "password", "session",
          "session-noninteractive"}) {
        std::string content;
        if (!readFileIfPresent(stateDirectory() / type, content)) {
            continue;
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
    return identifiers;
}

PamAuthUpdateTopologyManager::Ownership
PamAuthUpdateTopologyManager::detectOwnership() const {
    const std::set<std::string> enabled = enabledStateIdentifiers();
    std::set<std::string> ficEnabled;
    for (const std::string& identifier : knownActivationIdentifiers()) {
        if (enabled.count(identifier) != 0) {
            ficEnabled.insert(identifier);
        }
    }
    if (ficEnabled.empty()) {
        return Ownership::NoFicProfiles;
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
                return Ownership::FicOwned;
            }
        }
        return Ownership::InvalidSelection;
    }
    return Ownership::FicOwned;
}

bool PamAuthUpdateTopologyManager::externalFaillockPresent(
    std::string& error) const {
    PamConfiguration configuration(platformConfig_);
    for (PamManagementGroup group :
         {PamManagementGroup::Auth, PamManagementGroup::Account}) {
        for (const std::string& service : services_) {
            PamEffectiveStack stack;
            if (!configuration.buildEffectiveStack(
                    service, group, stack, error)) {
                return false;
            }
            for (const auto& entry : stack.entries) {
                if (std::filesystem::path(entry.rule.module).filename() ==
                    "pam_faillock.so") {
                    error.clear();
                    return true;
                }
            }
        }
    }
    error.clear();
    return false;
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
    for (const std::string& service : services_) {
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
        switch (detectOwnership()) {
        case Ownership::FicOwned:
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
    std::vector<std::string> identifiers;
    for (const auto& activation : capability_.strategyActivations) {
        for (const std::string& identifier :
             activation.activationIdentifiers) {
            if (!contains(identifiers, identifier)) {
                identifiers.push_back(identifier);
            }
        }
    }
    for (const std::string& identifier : capability_.activationIdentifiers) {
        if (!contains(identifiers, identifier)) {
            identifiers.push_back(identifier);
        }
    }
    return identifiers;
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
    error = "automatic PAM topology deactivation is not supported";
    return false;
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
    switch (detectOwnership()) {
    case Ownership::FicOwned:
        break;
    case Ownership::NoFicProfiles: {
        std::string externalError;
        if (externalFaillockPresent(externalError)) {
            error = "external pam_faillock topology already exists and is "
                "not selected through FIC pam-auth-update profiles; FIC "
                "will not take ownership: " + externalError;
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
    if (current.state == PamTopologyState::Enabled &&
        current.activeStrategy == strategy) {
        if (!current.manageable) {
            error = "external pam_faillock topology is not managed by FIC; "
                "refusing to change the strategy";
            return false;
        }
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
