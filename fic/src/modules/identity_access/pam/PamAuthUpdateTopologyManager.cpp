#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfigFileTransaction.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <array>
#include <charconv>
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


enum class ManagedFaillockSlotRole {
    Preauth,
    Authfail,
    Authsucc,
    Account
};

struct ManagedFaillockSlotSpec {
    ManagedFaillockSlotRole role;
    const char* name;
};

constexpr std::array<ManagedFaillockSlotSpec, 4> kManagedFaillockSlots{{
    {ManagedFaillockSlotRole::Preauth, "preauth"},
    {ManagedFaillockSlotRole::Authfail, "authfail"},
    {ManagedFaillockSlotRole::Authsucc, "authsucc"},
    {ManagedFaillockSlotRole::Account, "account"}
}};

constexpr std::array<const char*, 4> kManagedFaillockHookIds{{
    "fic-faillock-hook-preauth",
    "fic-faillock-hook-authfail",
    "fic-faillock-hook-authsucc",
    "fic-faillock-hook-account"
}};

enum class ManagedSlotState {
    Neutral,
    Active,
    Broken
};

struct ManagedSlotInspection {
    ManagedSlotState state = ManagedSlotState::Broken;
    std::uint64_t mutationId = 0;
    std::optional<fic::platform::PamFaillockStrategy> strategy;
};

std::string neutralManagedSlot(const ManagedFaillockSlotSpec& slot) {
    const bool account = slot.role == ManagedFaillockSlotRole::Account;
    return "#@FIC_PAM_SLOT_NEUTRAL version=1 "
           "capability=enable_authentication_lockout slot=" +
        std::string(slot.name) + "\n" +
        // Keep one stack element so pam-auth-update numeric jumps retain the
        // shape proven by the Docker diagnostic, but make the degenerate
        // "hook is the only module" case fail closed instead of authorizing.
        (account ? "account" : "auth") + " optional pam_deny.so\n";
}

bool strategyUsesSlot(
    ManagedFaillockSlotRole role,
    fic::platform::PamFaillockStrategy strategy) {
    switch (role) {
    case ManagedFaillockSlotRole::Preauth:
    case ManagedFaillockSlotRole::Account:
        return strategy != fic::platform::PamFaillockStrategy::Authsucc;
    case ManagedFaillockSlotRole::Authfail:
        return true;
    case ManagedFaillockSlotRole::Authsucc:
        return strategy == fic::platform::PamFaillockStrategy::Authsucc;
    }
    return false;
}

std::string managedSlotRule(
    ManagedFaillockSlotRole role,
    fic::platform::PamFaillockStrategy strategy) {
    switch (role) {
    case ManagedFaillockSlotRole::Preauth:
        return std::string("auth ") +
            (strategy == fic::platform::PamFaillockStrategy::PreauthRequisite
                ? "requisite" : "required") +
            " pam_faillock.so preauth";
    case ManagedFaillockSlotRole::Authfail:
        return "auth [default=die] pam_faillock.so authfail";
    case ManagedFaillockSlotRole::Authsucc:
        return "auth required pam_faillock.so authsucc";
    case ManagedFaillockSlotRole::Account:
        return "account required pam_faillock.so";
    }
    return {};
}

std::string activeManagedSlot(
    const ManagedFaillockSlotSpec& slot,
    fic::platform::PamFaillockStrategy strategy,
    std::uint64_t mutationId) {
    const std::string strategyName =
        fic::platform::pamFaillockStrategyName(strategy);
    return "#@FIC_PAM_SLOT_BEGIN version=1 "
           "capability=enable_authentication_lockout mutation=" +
        std::to_string(mutationId) + " slot=" + slot.name +
        " strategy=" + strategyName + "\n" +
        managedSlotRule(slot.role, strategy) + "\n" +
        "#@FIC_PAM_SLOT_END capability=enable_authentication_lockout mutation=" +
        std::to_string(mutationId) + " slot=" + slot.name + "\n";
}

bool parseMutationId(const std::string& text, std::uint64_t& value) {
    if (text.empty()) return false;
    const char* first = text.data();
    const char* last = first + text.size();
    const auto result = std::from_chars(first, last, value);
    return result.ec == std::errc{} && result.ptr == last && value != 0;
}

bool inspectManagedSlot(
    const ManagedFaillockSlotSpec& slot,
    const std::string& content,
    ManagedSlotInspection& inspection,
    std::string& error) {
    inspection = ManagedSlotInspection{};
    if (content == neutralManagedSlot(slot)) {
        inspection.state = ManagedSlotState::Neutral;
        error.clear();
        return true;
    }

    const std::string prefix =
        "#@FIC_PAM_SLOT_BEGIN version=1 "
        "capability=enable_authentication_lockout mutation=";
    const std::size_t firstNewline = content.find('\n');
    if (firstNewline == std::string::npos ||
        content.compare(0, prefix.size(), prefix) != 0) {
        error = "malformed FIC PAM managed slot " + std::string(slot.name);
        return false;
    }
    const std::string firstLine = content.substr(0, firstNewline);
    const std::size_t slotPos = firstLine.find(" slot=", prefix.size());
    const std::size_t strategyPos =
        slotPos == std::string::npos
            ? std::string::npos
            : firstLine.find(" strategy=", slotPos + 6);
    if (slotPos == std::string::npos ||
        strategyPos == std::string::npos) {
        error = "malformed FIC PAM managed slot marker " +
            std::string(slot.name);
        return false;
    }
    std::uint64_t mutationId = 0;
    if (!parseMutationId(
            firstLine.substr(prefix.size(), slotPos - prefix.size()),
            mutationId)) {
        error = "invalid FIC PAM managed slot mutation id";
        return false;
    }
    const std::string markerSlot = firstLine.substr(
        slotPos + 6, strategyPos - (slotPos + 6));
    if (markerSlot != slot.name) {
        error = "FIC PAM managed slot marker names another slot";
        return false;
    }
    const auto strategy = fic::platform::parsePamFaillockStrategy(
        firstLine.substr(strategyPos + 10));
    if (!strategy.has_value() ||
        !strategyUsesSlot(slot.role, *strategy)) {
        error = "FIC PAM managed slot declares an incompatible strategy";
        return false;
    }
    const std::string expected =
        activeManagedSlot(slot, *strategy, mutationId);
    if (content != expected) {
        error = "modified FIC PAM managed slot body: " +
            std::string(slot.name);
        return false;
    }
    inspection.state = ManagedSlotState::Active;
    inspection.mutationId = mutationId;
    inspection.strategy = strategy;
    error.clear();
    return true;
}

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
    paths.reserve(kStateFiles.size() + kConfigFiles.size() +
                  kManagedFaillockSlots.size());
    for (const std::string& name : kStateFiles) {
        paths.push_back(stateDirectory() / name);
    }
    for (const std::string& name : kConfigFiles) {
        paths.push_back(configDirectory() / name);
    }
    if (usesManagedFaillockSlots()) {
        const auto slots = managedFaillockSlotPaths();
        paths.insert(paths.end(), slots.begin(), slots.end());
    }
    return paths;
}

bool PamAuthUpdateTopologyManager::usesManagedFaillockSlots() const {
    if (capability_.capability !=
            fic::platform::PamCapability::AuthenticationLockout ||
        capability_.strategyActivations.empty()) {
        return false;
    }
    const std::set<std::string> expected(
        kManagedFaillockHookIds.begin(), kManagedFaillockHookIds.end());
    const std::vector<std::string> domain = knownActivationIdentifiers();
    if (std::set<std::string>(domain.begin(), domain.end()) != expected) {
        return false;
    }
    return std::all_of(
        capability_.strategyActivations.begin(),
        capability_.strategyActivations.end(),
        [&](const auto& activation) {
            return std::set<std::string>(
                       activation.activationIdentifiers.begin(),
                       activation.activationIdentifiers.end()) == expected;
        });
}

std::vector<std::filesystem::path>
PamAuthUpdateTopologyManager::managedFaillockSlotPaths() const {
    std::vector<std::filesystem::path> paths;
    paths.reserve(kManagedFaillockSlots.size());
    for (const auto& slot : kManagedFaillockSlots) {
        paths.push_back(
            configDirectory() / ("fic-faillock-" + std::string(slot.name)));
    }
    return paths;
}

bool PamAuthUpdateTopologyManager::journalBindsPhysicalOwnership() const {
    return usesManagedFaillockSlots();
}

bool PamAuthUpdateTopologyManager::bindJournalMutationId(
    std::uint64_t mutationId, std::string& error) {
    if (mutationId == 0) {
        error = "PAM managed-slot ownership requires a non-zero mutation id";
        return false;
    }
    boundMutationId_ = mutationId;
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::inspectManagedFaillockSlots(
    PamTopologyStatus& status, std::string& error) const {
    status = {};
    std::optional<std::uint64_t> mutationId;
    std::optional<fic::platform::PamFaillockStrategy> strategy;
    std::array<ManagedSlotInspection, 4> inspections{};

    for (std::size_t index = 0; index < kManagedFaillockSlots.size(); ++index) {
        PamConfigFileSnapshot snapshot;
        const auto path =
            configDirectory() /
            ("fic-faillock-" +
             std::string(kManagedFaillockSlots[index].name));
        if (!PamConfigFileTransaction::capture(path, snapshot, error) ||
            !snapshot.existed) {
            status.state = PamTopologyState::Unavailable;
            status.detail = error.empty()
                ? "FIC PAM managed slot is missing: " + path.string()
                : error;
            error = status.detail;
            return false;
        }
        if (!inspectManagedSlot(
                kManagedFaillockSlots[index], snapshot.content,
                inspections[index], error)) {
            status.state = PamTopologyState::Broken;
            status.manageable = true;
            status.detail = error;
            return false;
        }
        if (inspections[index].state == ManagedSlotState::Active) {
            if (!mutationId.has_value()) {
                mutationId = inspections[index].mutationId;
                strategy = inspections[index].strategy;
            } else if (*mutationId != inspections[index].mutationId ||
                       strategy != inspections[index].strategy) {
                status.state = PamTopologyState::Broken;
                status.manageable = true;
                status.detail =
                    "FIC PAM managed slots contain mixed mutation ids or "
                    "strategies";
                error = status.detail;
                return false;
            }
        }
    }

    if (!mutationId.has_value()) {
        std::string graphError;
        const ExternalFaillockGraphState graph =
            externalFaillockGraphState(graphError);
        if (graph == ExternalFaillockGraphState::Error) {
            status.state = PamTopologyState::Broken;
            status.manageable = false;
            status.detail = graphError;
            error = graphError;
            return false;
        }
        if (graph == ExternalFaillockGraphState::Present) {
            status.state = PamTopologyState::Enabled;
            status.manageable = false;
            status.detail =
                "external pam_faillock topology exists while all FIC "
                "managed slots are neutral";
        } else {
            status.state = PamTopologyState::Disabled;
            status.manageable = false;
        }
        error.clear();
        return true;
    }

    for (std::size_t index = 0; index < kManagedFaillockSlots.size(); ++index) {
        const bool expectedActive = strategyUsesSlot(
            kManagedFaillockSlots[index].role, *strategy);
        const bool active =
            inspections[index].state == ManagedSlotState::Active;
        if (active != expectedActive) {
            status.state = PamTopologyState::Broken;
            status.manageable = true;
            status.detail =
                "FIC PAM managed slots form a partial strategy topology";
            error = status.detail;
            return false;
        }
    }

    status.state = PamTopologyState::Enabled;
    status.manageable = true;
    status.activeStrategy = strategy;
    status.ownershipMutationId = mutationId;
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::canEnableManagedFaillockStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) const {
    if (!fic::platform::supportsPamFaillockStrategy(capability_, strategy)) {
        error = "pam_faillock strategy is not supported by this platform";
        return false;
    }
    std::filesystem::path executable;
    if (!resolveExecutable(executable, error)) return false;

    PamTopologyStatus status;
    if (!inspectManagedFaillockSlots(status, error)) return false;
    if (status.state == PamTopologyState::Enabled && !status.manageable) {
        error =
            "external pam_faillock topology exists; FIC will not take "
            "ownership";
        return false;
    }
    if (status.ownershipMutationId.has_value() &&
        boundMutationId_.has_value() &&
        *status.ownershipMutationId != *boundMutationId_) {
        error =
            "FIC PAM managed slots belong to another journal mutation";
        return false;
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::ensureManagedFaillockInfrastructure(
    std::string& error) {
    std::vector<std::string> arguments{"--enable"};
    const std::vector<std::string> identifiers =
        knownActivationIdentifiers();
    arguments.insert(
        arguments.end(), identifiers.begin(), identifiers.end());
    if (!runPamAuthUpdate(arguments, error)) return false;

    std::set<std::string> enabled;
    if (!enabledStateIdentifiers(enabled, error)) return false;
    for (const auto& identifier : identifiers) {
        if (enabled.count(identifier) == 0) {
            error =
                "permanent FIC PAM hook was not selected by pam-auth-update: " +
                identifier;
            return false;
        }
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::writeManagedFaillockSlots(
    std::optional<fic::platform::PamFaillockStrategy> strategy,
    std::string& error) {
    if (!boundMutationId_.has_value()) {
        error =
            "FIC PAM managed-slot mutation has no bound journal mutation id";
        return false;
    }

    std::array<PamConfigFileSnapshot, 4> snapshots{};
    std::array<std::string, 4> desired{};
    for (std::size_t index = 0; index < kManagedFaillockSlots.size(); ++index) {
        const auto& slot = kManagedFaillockSlots[index];
        const auto path =
            configDirectory() /
            ("fic-faillock-" + std::string(slot.name));
        if (!PamConfigFileTransaction::capture(
                path, snapshots[index], error) ||
            !snapshots[index].existed) {
            if (error.empty()) {
                error = "FIC PAM managed slot is missing: " + path.string();
            }
            return false;
        }

        ManagedSlotInspection inspection;
        if (!inspectManagedSlot(
                slot, snapshots[index].content, inspection, error)) {
            return false;
        }
        if (inspection.state == ManagedSlotState::Active &&
            inspection.mutationId != *boundMutationId_) {
            error =
                "refusing to overwrite FIC PAM slot owned by journal "
                "mutation " +
                std::to_string(inspection.mutationId);
            return false;
        }

        desired[index] =
            strategy.has_value() && strategyUsesSlot(slot.role, *strategy)
            ? activeManagedSlot(
                  slot, *strategy, *boundMutationId_)
            : neutralManagedSlot(slot);
    }

    std::size_t committed = 0;
    for (; committed < snapshots.size(); ++committed) {
        if (!PamConfigFileTransaction::mutate(
                snapshots[committed],
                [&](const PamConfigFileTransaction::Writer& writer,
                    std::string& mutationError) {
                    AtomicWriteOptions options;
                    options.createIfMissing = false;
                    options.rejectSymlink = true;
                    options.metadataPolicy =
                        FileMetadataPolicy::PreserveExisting;
                    return writer(
                        snapshots[committed].path.string(),
                        desired[committed], options, &mutationError);
                },
                error)) {
            std::string rollbackError;
            // mutate() may return false after the atomic rename was installed
            // (for example a durability/post-install failure) while marking
            // the current snapshot MutationCommitted. Always include the
            // failing snapshot in compensation; rollback() is a no-op when it
            // never committed.
            for (std::size_t index = committed + 1; index > 0; --index) {
                std::string oneError;
                if (!PamConfigFileTransaction::rollback(
                        snapshots[index - 1], oneError)) {
                    if (!rollbackError.empty()) rollbackError += "; ";
                    rollbackError += oneError;
                }
            }
            if (!rollbackError.empty()) {
                error +=
                    "; CRITICAL: PAM managed-slot rollback failed: " +
                    rollbackError;
            }
            return false;
        }
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::enableManagedFaillockStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) {
    if (!boundMutationId_.has_value()) {
        error =
            "FIC PAM managed-slot activation has no bound journal mutation id";
        return false;
    }
    if (!canEnableManagedFaillockStrategy(strategy, error) ||
        !ensureManagedFaillockInfrastructure(error) ||
        !writeManagedFaillockSlots(strategy, error)) {
        return false;
    }

    PamTopologyStatus after;
    if (!inspectManagedFaillockSlots(after, error) ||
        after.state != PamTopologyState::Enabled ||
        !after.manageable ||
        after.activeStrategy != strategy ||
        after.ownershipMutationId != boundMutationId_) {
        if (error.empty()) {
            error =
                "FIC PAM managed-slot activation postcondition failed";
        }
        return false;
    }
    error.clear();
    return true;
}

bool PamAuthUpdateTopologyManager::releaseManagedFaillockSlots(
    std::string& error) {
    if (!boundMutationId_.has_value()) {
        error =
            "FIC PAM managed-slot release has no bound journal mutation id";
        return false;
    }
    // This deliberately accepts a crash-partial subset of exact markers with
    // the bound id.  Malformed markers or another mutation id fail closed.
    return writeManagedFaillockSlots(std::nullopt, error);
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
    if (usesManagedFaillockSlots()) {
        return inspectManagedFaillockSlots(status, error);
    }

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

bool PamAuthUpdateTopologyManager::releaseSelectedIdentifiers(
    const std::vector<std::string>& identifiers,
    std::string& error) {
    std::set<std::string> enabled;
    if (!enabledStateIdentifiers(enabled, error)) return false;

    std::vector<std::string> arguments{"--disable"};
    for (const std::string& identifier : identifiers) {
        if (enabled.count(identifier) != 0) {
            arguments.push_back(identifier);
        }
    }
    if (arguments.size() == 1) {
        error.clear();
        return true;
    }
    if (!runPamAuthUpdate(arguments, error)) return false;

    std::set<std::string> after;
    if (!enabledStateIdentifiers(after, error)) return false;
    for (const std::string& identifier : identifiers) {
        if (after.count(identifier) != 0) {
            error = "FIC PAM selection remains after pam-auth-update disable: " +
                identifier;
            return false;
        }
    }
    return confirmDurable(error);
}

bool PamAuthUpdateTopologyManager::failWithActivationCompensation(
    const std::vector<std::string>& identifiers,
    const std::string& failure,
    std::string& error) {
    std::string cleanupError;
    if (!releaseSelectedIdentifiers(identifiers, cleanupError)) {
        error = failure +
            "; CRITICAL: exact FIC PAM activation cleanup failed: " +
            cleanupError;
        return false;
    }
    error = failure +
        "; FIC activation identifiers removed without restoring foreign "
        "pam-auth-update state";
    return false;
}

bool PamAuthUpdateTopologyManager::canEnable(std::string& error) const {
    if (capability_.topology !=
            fic::platform::PamTopologyStrategyKind::PamAuthUpdate ||
        (capability_.activationIdentifiers.empty() &&
            capability_.strategyActivations.empty())) {
        error = "PAM capability has no pam-auth-update activation recipe";
        return false;
    }
    if (capability_.capability !=
        fic::platform::PamCapability::AuthenticationLockout) {
        error =
            "legacy pam-auth-update profile activation is observation-only: "
            "profile selection does not prove causal FIC ownership";
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

    std::vector<std::string> arguments{"--enable"};
    arguments.insert(arguments.end(), identifiers.begin(), identifiers.end());
    std::string failure;
    if (!runPamAuthUpdate(arguments, failure)) {
        return failWithActivationCompensation(
            identifiers, failure, error);
    }
    PamTopologyStatus after;
    std::string postconditionError;
    if (!inspect(after, postconditionError) ||
        after.state != PamTopologyState::Enabled ||
        !after.manageable) {
        return failWithActivationCompensation(identifiers,
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
    if (usesManagedFaillockSlots()) {
        return releaseManagedFaillockSlots(error);
    }

    Ownership ownership = Ownership::NoFicProfiles;
    if (!detectOwnership(ownership, error)) return false;

    if (capability_.capability !=
        fic::platform::PamCapability::AuthenticationLockout) {
        if (ownership == Ownership::NoFicProfiles) {
            error.clear();
            return true;
        }
        error =
            "legacy pam-auth-update profile release is disabled: profile "
            "selection does not prove causal FIC ownership";
        return false;
    }

    switch (ownership) {
    case Ownership::NoFicProfiles:
        error.clear();
        return true;
    case Ownership::FicOwned:
        return releaseSelectedIdentifiers(
            knownActivationIdentifiers(), error);
    case Ownership::InvalidSelection:
        // Selection in the reserved FIC namespace is not causal ownership:
        // an administrator can select one of these profiles after FIC has
        // persisted Prepared but before the native writer executes.  Never
        // delete a partial/mixed selection merely because its id starts with
        // fic-*.
        error =
            "FIC pam-auth-update selection is partial/mixed; causal "
            "ownership is not proven, refusing release";
        return false;
    }

    error = "unknown pam-auth-update ownership state";
    return false;
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
    if (usesManagedFaillockSlots()) {
        return canEnableManagedFaillockStrategy(strategy, error);
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
    if (usesManagedFaillockSlots()) {
        return enableManagedFaillockStrategy(strategy, error);
    }
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
