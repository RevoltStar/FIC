#include "modules/dac/sudo/SudoersGlobalDefaultsTransaction.h"
#include "modules/dac/sudo/SudoersDisabledWrapper.h"
#include "modules/dac/sudo/SudoersManagedInclude.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>

#include <map>
#include <optional>
#include <sstream>
#include <sys/stat.h>
#include <utility>

namespace fic::sudoers {
namespace {
using namespace rollback;
using Owners = std::map<std::string, MutationRecord>;

bool safeParent(const std::filesystem::path& target, bool enforceOwnership, std::string& error) {
    if (!target.is_absolute() || target != target.lexically_normal()) {
        error = "SUDO target path is not absolute and canonical";
        return false;
    }
    std::filesystem::path current;
    for (const auto& component : target.parent_path()) {
        current /= component;
        struct stat info {};
        if (::lstat(current.c_str(), &info) || !S_ISDIR(info.st_mode) ||
            (enforceOwnership && (info.st_uid != 0 || (info.st_mode & 0022)))) {
            error = "Unsafe SUDO parent directory: " + current.string();
            return false;
        }
    }
    return true;
}

std::string header(const std::string& id) {
    return "# Managed by FIC\n# FIC container=" + id + "\n";
}

bool capture(const std::filesystem::path& path, bool allowMissing,
             bool enforceOwnership, std::optional<AtomicTargetState>& state,
             std::string& error) {
    if (!safeParent(path, enforceOwnership, error)) return false;
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (status.type() == std::filesystem::file_type::not_found && allowMissing) {
        state.reset();
        return true;
    }
    AtomicTargetState captured;
    if (!AtomicFileWriter::captureTargetState(path.string(), captured, &error))
        return false;
    if (enforceOwnership && (captured.owner != 0 || captured.group != 0 ||
                            (captured.mode & 0022))) {
        error = "Unsafe sudoers ownership or permissions: " + path.string();
        return false;
    }
    state = std::move(captured);
    return true;
}

bool inventory(MutationJournal& journal, Owners& owners, std::string& id,
               bool& separator, std::string& error) {
    if (!journal.usable()) {
        error = "SUDO mutation journal is not usable";
        return false;
    }
    unsigned prepared = 0;
    for (const auto& record : journal.records()) {
        if (!record.isActive() || record.undo.backend != MutationBackend::Sudo)
            continue;
        const auto* global = std::get_if<UndoReleaseSudoGlobalDefault>(&record.undo.payload);
        if (!global) {
            if (std::holds_alternative<UndoRemoveManagedSetting>(record.undo.payload)) {
                error = "Legacy active SUDO global provenance requires explicit resolution";
                return false;
            }
            continue;
        }
        if (record.policy.moduleName != "DAC" || record.policy.submoduleName != "SudoEdit" ||
            global->key != record.resource ||
            !isCanonicalSudoWrapperId(global->containerId) ||
            (!id.empty() && (id != global->containerId || separator != global->addedSeparator)) ||
            (!owners.empty() && global->separatorPrefixDigest !=
                std::get<UndoReleaseSudoGlobalDefault>(owners.begin()->second.undo.payload).separatorPrefixDigest) ||
            !owners.emplace(global->key, record).second) {
            error = "Conflicting SUDO global ownership records";
            return false;
        }
        id = global->containerId;
        separator = global->addedSeparator;
        if (record.status == MutationStatus::Prepared) ++prepared;
    }
    if (prepared > 1) { error = "Multiple unresolved SUDO global transitions"; return false; }
    return true;
}

bool proveFile(const AtomicTargetState& state, const Owners& owners,
               const std::string& id, std::map<std::string, std::string>& lines,
               std::string& error, unsigned expectedMode) {
    if (state.mode != expectedMode) {
        error = "Managed sudoers metadata drift";
        return false;
    }
    const auto prefix = header(id);
    if (state.content.compare(0, prefix.size(), prefix) != 0 ||
        state.content.empty() || state.content.back() != '\n') {
        error = "Foreign or drifted managed sudoers container";
        return false;
    }
    std::istringstream input(state.content.substr(prefix.size()));
    std::string line;
    while (std::getline(input, line)) {
        bool found = false;
        for (const auto& [key, record] : owners) {
            const auto& payload = std::get<UndoReleaseSudoGlobalDefault>(record.undo.payload);
            if (line != payload.appliedLine &&
                !((record.status == MutationStatus::Prepared || record.status == MutationStatus::RollbackFailed) &&
                  !payload.previousLine.empty() && line == payload.previousLine))
                continue;
            if (!lines.emplace(key, line).second) {
                error = "Duplicate owned sudoers setting";
                return false;
            }
            found = true;
            break;
        }
        if (!found) {
            error = "Unproven content in managed sudoers container";
            return false;
        }
    }
    return true;
}

std::string render(const std::string& id, const std::map<std::string, std::string>& lines) {
    std::string result = header(id);
    for (const auto& [key, line] : lines) {
        (void)key;
        result += line + "\n";
    }
    return result;
}

using GraphCapture = std::vector<std::pair<std::filesystem::path, AtomicTargetState>>;
bool captureGraph(SudoersConfiguration& configuration, bool enforceOwnership,
                  GraphCapture& captures, std::string& error) {
    for (const auto& document : configuration.graphDocuments()) {
        std::optional<AtomicTargetState> state;
        if (!capture(document.path, false, enforceOwnership, state, error) ||
            state->content != document.content) {
            if (error.empty()) error = "SUDO graph document changed during capture";
            return false;
        }
        captures.emplace_back(document.path, *state);
    }
    return true;
}
bool proveGraphDurable(const GraphCapture& captures, std::string& error) {
    for (const auto& [path, state] : captures)
        if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(path.string(), state, &error)) return false;
    return true;
}

bool install(const std::filesystem::path& path, const std::string& content,
             const std::optional<AtomicTargetState>& before, bool managed,
             bool enforceOwnership, std::string& error, unsigned mode = 0440,
             bool* conflict = nullptr) {
    AtomicWriteOptions options;
    options.rejectSymlink = true;
    options.expectedTargetState = before;
    options.createIfMissing = !before;
    options.exclusiveCreate = !before;
    if (managed) {
        options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
        options.fileMode = mode;
        if (enforceOwnership) { options.fileOwner = 0; options.fileGroup = 0; }
    }
    if (before && before->content == content)
        return AtomicFileWriter::ensureTargetDurableIfCurrentState(path.string(), *before, &error);
    AtomicWriteResult result;
    const bool ok = AtomicFileWriter::writeWithResult(path.string(), content, options, &error, &result);
    if (conflict && result.preconditionFailed) *conflict = true;
    return ok;
}
}

GlobalDefaultsTransaction::GlobalDefaultsTransaction(
    SudoersConfigurationOptions options, rollback::MutationJournal& journal,
    GlobalDefaultsPhaseHook hook)
    : options_(std::move(options)), journal_(journal), hook_(std::move(hook)) {}

bool GlobalDefaultsTransaction::verifyNoOwnedSetting(const std::string& key, std::string& error,
                                                   bool allowProvenFailedOwners) {
    if (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error)) return false;
    Owners owners;
    std::string container;
    bool separator = false;
    if (!inventory(journal_, owners, container, separator, error)) return false;
    if (owners.count(key)) { error = "SUDO setting still has active ownership"; return false; }
    std::optional<AtomicTargetState> main;
    if (!capture(options_.mainPath, false, options_.enforceOwnership, main, error)) return false;
    const auto include = inspectManagedInclude(main->content, options_.managedPath);
    if (include.state == ManagedIncludeState::Conflict ||
        (owners.empty() && include.state != ManagedIncludeState::Absent) ||
        (!owners.empty() && include.state != ManagedIncludeState::Present)) {
        error = include.message.empty() ? "SUDO include has inconsistent journal provenance" : include.message;
        return false;
    }
    SudoersConfiguration configuration(options_);
    if (!configuration.load(error) || !configuration.validateConfiguration(error)) return false;
    std::optional<AtomicTargetState> managed;
    if (!capture(options_.managedPath, true, options_.enforceOwnership, managed, error)) return false;
    if (!managed) {
        if (!owners.empty()) { error = "Other owned SUDO settings disappeared"; return false; }
        return true;
    }
    if (owners.empty()) {
        if (managed->content.find("# FIC container=") != std::string::npos ||
            managed->content.find("#@FIC_") != std::string::npos) {
            error = "SUDO container markers have no journal provenance";
            return false;
        }
        // A foreign file is irrelevant to a provider construction guarantee;
        // it remains foreign and is never adopted or modified.
        return true;
    }
    std::map<std::string, std::string> lines;
    if (!proveFile(*managed, owners, container, lines, error, options_.managedFileMode)) return false;
    for (const auto& [ownedKey, record] : owners) {
        const auto& payload = std::get<UndoReleaseSudoGlobalDefault>(record.undo.payload);
        const bool provenFailed = allowProvenFailedOwners && record.status == MutationStatus::RollbackFailed &&
                                  lines.count(ownedKey) && lines.at(ownedKey) == payload.appliedLine;
        if ((record.status != MutationStatus::Applied && !provenFailed) || !lines.count(ownedKey)) {
            error = "Unresolved SUDO ownership cannot be ignored by construction";
            return false;
        }
    }
    return AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.managedPath.string(), *managed, &error);
}

SudoersOperationResult GlobalDefaultsTransaction::reconcile(
    const PolicyRef& policy, const std::string& key, const std::string& line,
    const std::string& expected) {
    SudoersOperationResult result;
    std::string& error = result.message;
    Owners owners;
    std::string container;
    bool separator = false;
    std::string separatorDigest;
    if (!inventory(journal_, owners, container, separator, error)) return result;
    for (const auto& [ownedKey, record] : owners) {
        const auto& pending = std::get<UndoReleaseSudoGlobalDefault>(record.undo.payload);
        if (record.status != MutationStatus::Prepared ||
            (ownedKey == key && pending.appliedLine == line && record.policy == policy)) continue;
        const auto prefix = "Defaults " + ownedKey + "=";
        std::string pendingValue;
        if (ownedKey == "env_reset" || ownedKey == "exempt_group")
            pendingValue = pending.appliedLine == "Defaults !" + ownedKey ? "DISABLE" : "ENABLE";
        else {
            pendingValue = pending.appliedLine.substr(prefix.size());
            if (pendingValue.size() >= 2 && pendingValue.front() == '"' && pendingValue.back() == '"')
                pendingValue = pendingValue.substr(1, pendingValue.size() - 2);
        }
        const auto recovered = GlobalDefaultsTransaction(options_, journal_).reconcile(
            record.policy, ownedKey, pending.appliedLine, pendingValue);
        if (!recovered.ok) return recovered;
        return reconcile(policy, key, line, expected);
    }
    if (!owners.empty())
        separatorDigest = std::get<UndoReleaseSudoGlobalDefault>(owners.begin()->second.undo.payload).separatorPrefixDigest;
    std::optional<AtomicTargetState> main, managed;
    if (!capture(options_.mainPath, false, options_.enforceOwnership, main, error) ||
        !capture(options_.managedPath, true, options_.enforceOwnership, managed, error))
        return result;
    auto include = inspectManagedInclude(main->content, options_.managedPath);
    if (include.state == ManagedIncludeState::Conflict) {
        error = include.message;
        result.conflict = true;
        return result;
    }
    std::map<std::string, std::string> lines;
    if (owners.empty()) {
        if (managed || include.state != ManagedIncludeState::Absent) {
            error = "Managed SUDO artifacts have no journal provenance";
            result.conflict = true;
            return result;
        }
        container = generateSudoWrapperMutationId(0);
        separator = !main->content.empty() && main->content.back() != '\n';
        if (separator) separatorDigest = fic::core::ContentDigest::sha256Hex(main->content);
    } else if (managed) {
        if (!proveFile(*managed, owners, container, lines, error, options_.managedFileMode)) {
            result.conflict = true;
            return result;
        }
    } else {
        // A fresh Prepared before exclusive creation is the only missing-file
        // state which can be completed without recreating released ownership.
        for (const auto& [ownedKey, record] : owners) {
            (void)ownedKey;
            const auto& payload = std::get<UndoReleaseSudoGlobalDefault>(record.undo.payload);
            if (record.status != MutationStatus::Prepared || !payload.previousLine.empty()) {
                error = "Owned SUDO container disappeared";
                result.conflict = true;
                return result;
            }
        }
    }
    SudoersConfiguration configuration(options_);
    GraphCapture beforeCaptures;
    if (!configuration.load(error) ||
        !captureGraph(configuration, options_.enforceOwnership, beforeCaptures, error) ||
        !configuration.validateConfiguration(error) || !proveGraphDurable(beforeCaptures, error) ||
        !configuration.verifyIncludedDirectoryTopologyUnchanged(error)) return result;
    for (const auto& [ownedKey, record] : owners) {
        if (ownedKey != key && record.status != MutationStatus::Applied) {
            error = "Recover the unresolved SUDO owner before starting another transition";
            return result;
        }
        if (ownedKey != key && !lines.count(ownedKey)) {
            error = "A different SUDO setting lost its physical ownership";
            result.conflict = true;
            return result;
        }
    }
    const auto failedOwner = owners.find(key);
    if (failedOwner != owners.end() && failedOwner->second.status == MutationStatus::RollbackFailed) {
        const auto& failed = std::get<UndoReleaseSudoGlobalDefault>(failedOwner->second.undo.payload);
        if (!lines.count(key)) {
            const auto released = release(failedOwner->second);
            if (!released.ok) return released;
            if (!journal_.setStatus(failedOwner->second.id, MutationStatus::RolledBack, error)) return result;
            return reconcile(policy, key, line, expected);
        }
        if (!failed.previousLine.empty()) {
            if (!journal_.setStatus(failedOwner->second.id, MutationStatus::Prepared, error)) return result;
            return reconcile(policy, key, line, expected);
        }
    }
    MutationId mutation = 0;
    phase(GlobalDefaultsPhase::BeforePrepared);
    const auto existing = owners.find(key);
    if (existing != owners.end() && existing->second.status == MutationStatus::Prepared) {
        const auto& payload = std::get<UndoReleaseSudoGlobalDefault>(existing->second.undo.payload);
        if (payload.appliedLine != line || !(existing->second.policy == policy)) {
            error = "Unresolved SUDO transition has a different target";
            return result;
        }
        mutation = existing->second.id;
    } else {
        MutationRecord record;
        record.policy = policy;
        record.resource = key;
        record.undo = {MutationBackend::Sudo, UndoReleaseSudoGlobalDefault{
            key, line, lines.count(key) ? lines.at(key) : "", container, separator, separatorDigest}};
        if (!journal_.prepareMutation(record, mutation, error)) return result;
    }
    phase(GlobalDefaultsPhase::Prepared);
    lines[key] = line;
    // Errors after Prepared deliberately preserve provenance. A retry uses
    // the same ID and can complete the durable two-file protocol.
    if (!configuration.verifyIncludedDirectoryTopologyUnchanged(error) ||
        !install(options_.managedPath, render(container, lines), managed, true,
                 options_.enforceOwnership, error, options_.managedFileMode, &result.conflict)) return result;
    phase(GlobalDefaultsPhase::OwnedFileInstalled);
    std::optional<AtomicTargetState> installedManaged;
    if (!capture(options_.managedPath, false, options_.enforceOwnership, installedManaged, error)) return result;
    if (installedManaged->content != render(container, lines) ||
        installedManaged->mode != options_.managedFileMode) {
        error = "Owned SUDO file changed before include installation";
        result.conflict = true;
        return result;
    }
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.managedPath.string(), *installedManaged, &error)) return result;
    if (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error)) return result;
    std::string mainTarget = main->content;
    if (include.state == ManagedIncludeState::Absent) {
        if (separator) mainTarget += '\n';
        mainTarget += managedIncludeBlock(options_.managedPath);
    }
    if (!install(options_.mainPath, mainTarget, main, false, options_.enforceOwnership, error, 0440, &result.conflict))
        return result;
    phase(GlobalDefaultsPhase::IncludeInstalled);
    if (!configuration.load(error)) return result;
    GraphCapture captures;
    if (!captureGraph(configuration, options_.enforceOwnership, captures, error) ||
        !configuration.validateConfiguration(error)) return result;
    const auto observed = configuration.inspectGlobalDefault(key);
    std::optional<AtomicTargetState> finalMain, finalManaged;
    if (!observed.found || observed.value != expected ||
        observed.source.path != options_.managedPath ||
        !capture(options_.mainPath, false, options_.enforceOwnership, finalMain, error) ||
        !capture(options_.managedPath, false, options_.enforceOwnership, finalManaged, error)) {
        if (error.empty()) error = "Owned SUDO global setting is not effective";
        return result;
    }
    phase(GlobalDefaultsPhase::PostconditionVerified);
    if (finalMain->content != mainTarget || finalManaged->content != render(container, lines)) {
        error = "SUDO artifacts drifted before journal commit";
        result.conflict = true;
        return result;
    }
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.managedPath.string(), *finalManaged, &error) ||
        !AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.mainPath.string(), *finalMain, &error) ||
        !proveGraphDurable(captures, error) ||
        !configuration.verifyIncludedDirectoryTopologyUnchanged(error) ||
        (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error)) ||
        !journal_.setStatus(mutation, MutationStatus::Applied, error)) return result;
    result.ok = true;
    result.changed = !managed || managed->content != finalManaged->content || main->content != mainTarget;
    error = "Owned global Defaults verified";
    return result;
}

SudoersOperationResult GlobalDefaultsTransaction::release(const rollback::MutationRecord& record) {
    SudoersOperationResult result;
    std::string& error = result.message;
    const auto* payload = std::get_if<UndoReleaseSudoGlobalDefault>(&record.undo.payload);
    if (!payload) { error = "Wrong SUDO undo payload"; return result; }
    Owners owners;
    std::string container;
    bool separator = false;
    if (!inventory(journal_, owners, container, separator, error)) return result;
    const auto owner = owners.find(payload->key);
    if (owner == owners.end() || owner->second.id != record.id) {
        error = "SUDO rollback lacks active ownership";
        result.conflict = true;
        return result;
    }
    std::optional<AtomicTargetState> main, managed;
    if (!capture(options_.mainPath, false, options_.enforceOwnership, main, error) ||
        !capture(options_.managedPath, true, options_.enforceOwnership, managed, error))
        return result;
    const auto include = inspectManagedInclude(main->content, options_.managedPath);
    if (include.state == ManagedIncludeState::Conflict) {
        result.conflict = true;
        error = include.message;
        return result;
    }
    if (!managed) {
        if (include.state != ManagedIncludeState::Absent) {
            error = "Dangling owned SUDO include";
            result.conflict = true;
            return result;
        }
        SudoersConfiguration configuration(options_);
        GraphCapture captures;
        if (!configuration.load(error) ||
            !captureGraph(configuration, options_.enforceOwnership, captures, error) ||
            !configuration.validateConfiguration(error) || !proveGraphDurable(captures, error) ||
            !configuration.verifyIncludedDirectoryTopologyUnchanged(error)) return result;
        if (!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(options_.managedPath.string(), &error))
            return result;
        result.ok = true;
        result.targetMissing = true;
        error = "SUDO artifacts already released";
        return result;
    }
    std::map<std::string, std::string> lines;
    if (!proveFile(*managed, owners, container, lines, error, options_.managedFileMode)) {
        result.conflict = true;
        return result;
    }
    for (const auto& [key, other] : owners) {
        if (key == payload->key) continue;
        if (other.status != MutationStatus::Applied || !lines.count(key)) {
            error = "Another SUDO owner is unresolved or drifted";
            result.conflict = true;
            return result;
        }
    }
    SudoersConfiguration configuration(options_);
    if (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error)) return result;
    if (!configuration.load(error) ||
        (!(options_.releaseOwnedUnsupportedSetting && payload->key == "exempt_group") &&
         !configuration.validateConfiguration(error))) return result;
    result.targetMissing = !lines.count(payload->key);
    lines.erase(payload->key);
    if (lines.empty() && separator && include.state == ManagedIncludeState::Present) {
        auto prefix = main->content.substr(0, include.offset);
        if (prefix.empty() || prefix.back() != '\n') {
            error = "Managed SUDO include separator drift";
            result.conflict = true;
            return result;
        }
        prefix.pop_back();
        if (fic::core::ContentDigest::sha256Hex(prefix) != payload->separatorPrefixDigest) {
            error = "Managed include separator source drift";
            result.conflict = true;
            return result;
        }
    }
    if (!configuration.verifyIncludedDirectoryTopologyUnchanged(error) ||
        !install(options_.managedPath, render(container, lines), managed, true,
                 options_.enforceOwnership, error, options_.managedFileMode, &result.conflict)) return result;
    phase(GlobalDefaultsPhase::OwnedFileInstalled);
    if (lines.empty()) phase(GlobalDefaultsPhase::InertFileInstalled);
    std::optional<AtomicTargetState> installedManaged;
    if (!capture(options_.managedPath, false, options_.enforceOwnership, installedManaged, error)) return result;
    if (installedManaged->content != render(container, lines) ||
        installedManaged->mode != options_.managedFileMode) {
        error = "Owned SUDO file changed during release";
        result.conflict = true;
        return result;
    }
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.managedPath.string(), *installedManaged, &error)) return result;
    if (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error)) return result;
    result.changed = !result.targetMissing;
    if (!lines.empty()) {
        if (!configuration.load(error)) return result;
        GraphCapture captures;
        if (!captureGraph(configuration, options_.enforceOwnership, captures, error) ||
            !configuration.validateConfiguration(error) || !proveGraphDurable(captures, error) ||
            !configuration.verifyIncludedDirectoryTopologyUnchanged(error)) return result;
        std::optional<AtomicTargetState> after;
        if (!capture(options_.managedPath, false, options_.enforceOwnership, after, error) ||
            after->content != render(container, lines) ||
            !AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.managedPath.string(), *after, &error))
            return result;
        result.ok = true;
        error = "Released one owned global Defaults entry";
        return result;
    }
    // Keep an inert, valid file connected until the managed include removal
    // is durable. This closes the dangling-include crash window.
    std::string mainTarget = main->content;
    if (include.state == ManagedIncludeState::Present) {
        mainTarget.resize(include.offset);
        if (separator) {
            if (mainTarget.empty() || mainTarget.back() != '\n') {
                error = "Managed SUDO include separator drift";
                result.conflict = true;
                return result;
            }
            mainTarget.pop_back();
            if (fic::core::ContentDigest::sha256Hex(mainTarget) != payload->separatorPrefixDigest) {
                error = "Managed include separator source drift";
                result.conflict = true;
                return result;
            }
        }
        if (!install(options_.mainPath, mainTarget, main, false,
                     options_.enforceOwnership, error, 0440, &result.conflict)) return result;
        result.changed = true;
    }
    phase(GlobalDefaultsPhase::IncludeReleased);
    if (!configuration.load(error)) return result;
    GraphCapture captures;
    if (!captureGraph(configuration, options_.enforceOwnership, captures, error) ||
        !configuration.validateConfiguration(error)) return result;
    for (const auto& document : configuration.graphDocuments()) {
        if (document.path == options_.managedPath) {
            error = "A foreign include still connects the inert owned SUDO container";
            result.conflict = true;
            return result;
        }
    }
    std::optional<AtomicTargetState> inert, detachedMain;
    if (!capture(options_.managedPath, false, options_.enforceOwnership, inert, error) ||
        !capture(options_.mainPath, false, options_.enforceOwnership, detachedMain, error) ||
        inert->content != header(container) || detachedMain->content != mainTarget ||
        !configuration.verifyIncludedDirectoryTopologyUnchanged(error) ||
        !proveGraphDurable(captures, error) ||
        !AtomicFileWriter::ensureTargetDurableIfCurrentState(options_.mainPath.string(), *detachedMain, &error))
        return result;
    AtomicRemoveResult removed;
    const bool deleteOk = AtomicFileWriter::removeIfCurrentState(options_.managedPath.string(), *inert, &error, &removed);
    if (removed.preconditionFailed) result.conflict = true;
    if (!deleteOk || !removed.removed || !removed.durabilityConfirmed)
        return result;
    result.changed = true;
    phase(GlobalDefaultsPhase::FileReleased);
    if (!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(options_.managedPath.string(), &error) ||
        !proveGraphDurable(captures, error) ||
        !configuration.verifyIncludedDirectoryTopologyUnchanged(error) ||
        (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error))) return result;
    result.ok = true;
    error = "Released the last global Defaults owner and shared SUDO artifacts";
    return result;
}

} // namespace fic::sudoers
