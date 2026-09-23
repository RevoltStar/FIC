#include "modules/identity_access/pam/PamSlotAttachValidator.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"
#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamPwhistoryArguments.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

namespace fic::identity::pam {
namespace {

using fic::rollback::MutationBackend;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::UndoDisablePamCapability;

// Complete active-FIC-owned-state proof for the attach decision: the journal
// must carry an ACTIVE record whose payload proves the exact managed-slot
// ownership domain for this capability. No semantic equality and no
// profile-name inference is used as a substitute for this physical proof.
//
// The journal is accessed through the read-only witness-aware persistent
// state validation: the pre-attach proof is accepted only from a persistent
// (journal, witness) state that the normal daemon lifecycle would also
// accept, and the validation itself never creates, bootstraps, migrates or
// repairs anything on disk.
bool proveJournalOwnership(
    std::uint64_t mutationId,
    const std::optional<fic::platform::PamFaillockStrategy>& activeStrategy,
    const fic::platform::PamCapabilityConfig& capability,
    const std::filesystem::path& mutationJournalFile,
    PamSlotAttachVerdict& verdict) {
    // Witness-aware READ-ONLY persistent-state proof: virgin state, lost
    // journal, corrupted witness and the pending-migration state (existing
    // journal without witness) all fail closed instead of being healed.
    MutationJournal journal(mutationJournalFile);
    std::string journalError;
    if (!journal.validatePersistentStateReadOnly(journalError)) {
        verdict.detail =
            "mutation journal persistent state is not proven (fail closed): " +
            journalError;
        return true;
    }

    const MutationRecord* match = nullptr;
    for (const MutationRecord& record : journal.records()) {
        if (record.id == mutationId) {
            match = &record;
            break;
        }
    }
    if (match == nullptr) {
        verdict.detail =
            "active FIC PAM slots reference journal mutation " +
            std::to_string(mutationId) +
            " with no matching journal record";
        return true;
    }
    if (!match->isActive()) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " is not active (status " +
            fic::rollback::mutationStatusToString(match->status) +
            "); it cannot prove the active slot state";
        return true;
    }
    // Exact journal identity: the record must be the PAM capability mutation
    // itself, not a foreign-policy record reusing the same id.
    if (match->policy.moduleName != "IDENTITY_ACCESS" ||
        match->policy.submoduleName != "PAM" ||
        match->policy.policyName != "enable_authentication_lockout") {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " proves a different policy identity (expected "
            "IDENTITY_ACCESS/PAM/enable_authentication_lockout)";
        return true;
    }
    if (match->resource != "capability/enable_authentication_lockout") {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " proves a different resource (expected "
            "capability/enable_authentication_lockout)";
        return true;
    }
    if (match->undo.backend != MutationBackend::Pam) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " does not belong to the PAM backend";
        return true;
    }
    const auto* payload =
        std::get_if<UndoDisablePamCapability>(&match->undo.payload);
    if (payload == nullptr) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " carries no PAM capability ownership payload";
        return true;
    }
    if (payload->capability != "enable_authentication_lockout" ||
        payload->topology != fic::rollback::PamTopologyKind::PamAuthUpdate) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " proves a different PAM capability or topology";
        return true;
    }
    // The recorded ownership domain must exactly match the managed-slot
    // activation domain of the CURRENT platform profile: a partial, extended
    // or legacy domain is not a provenance for this topology.
    const std::vector<std::string> domain =
        activationIdentifiers(capability);
    const std::set<std::string> recorded(
        payload->activationIdentifiers.begin(),
        payload->activationIdentifiers.end());
    const std::set<std::string> expected(domain.begin(), domain.end());
    if (domain.empty() || recorded != expected) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " proves a different FIC PAM activation domain";
        return true;
    }
    // Physical strategy binding: the recorded target strategy must be the
    // exact physical strategy carried by the active slots themselves.
    if (!activeStrategy.has_value()) {
        verdict.detail =
            "active FIC PAM slots report no physical faillock strategy; "
            "journal provenance cannot be bound to the slot state";
        return true;
    }
    if (!payload->targetStrategy.has_value() ||
        *payload->targetStrategy !=
            fic::platform::pamFaillockStrategyName(*activeStrategy)) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " proves a different physical faillock strategy than the "
            "active slots";
        return true;
    }
    verdict.safeToAttach = true;
    verdict.detail =
        "active FIC PAM slots are bound to active journal mutation " +
        std::to_string(mutationId);
    return true;
}

// ---------------------------------------------------------------------------
// Step 4: password slot attach validation helpers.
// ---------------------------------------------------------------------------

using fic::rollback::MutationJournal;

constexpr const char* kDefaultPasswordStateDirectory = "/var/lib/pam";
constexpr const char* kDefaultPasswordConfigDirectory = "/etc/pam.d";

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

// Rule I external-provider detection, part 1: identifiers of the profiles
// selected in the pam-auth-update password state database (exact
// "Module: <profile>" lines, same grammar as the topology manager).
bool selectedPasswordStateIdentifiers(
    const std::filesystem::path& stateDirectory,
    std::set<std::string>& identifiers,
    std::string& error) {
    identifiers.clear();
    const std::filesystem::path path = stateDirectory / "password";
    std::error_code statusError;
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path, statusError);
    if (statusError) {
        if (statusError ==
            std::make_error_code(std::errc::no_such_file_or_directory)) {
            error.clear();
            return true;
        }
        error = "could not stat pam-auth-update state file " +
            path.string() + ": " + statusError.message();
        return false;
    }
    if (!std::filesystem::exists(status)) {
        error.clear();
        return true;
    }
    if (!std::filesystem::is_regular_file(status)) {
        error = "pam-auth-update state path is not a regular file: " +
            path.string();
        return false;
    }
    std::string content;
    if (!readFileIfPresent(path, content)) {
        error = "could not read pam-auth-update state file " + path.string();
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
    error.clear();
    return true;
}

// Flattens an effective stack into one ordered rule sequence. Substacks
// are expanded in place so ordering guarantees (Rule G token-producer
// position relative to the FIC history include) can be checked across
// include boundaries.
void flattenStackRules(const std::vector<PamStackEntry>& entries,
                       std::vector<PamRule>& rules) {
    for (const PamStackEntry& entry : entries) {
        rules.push_back(entry.rule);
        flattenStackRules(entry.substack, rules);
    }
}

bool stackContainsModule(const std::vector<PamStackEntry>& entries,
                         const std::string& moduleName) {
    for (const PamStackEntry& entry : entries) {
        if (entry.rule.includeKind == PamIncludeKind::None &&
            std::filesystem::path(entry.rule.module).filename() ==
                moduleName) {
            return true;
        }
        if (stackContainsModule(entry.substack, moduleName)) {
            return true;
        }
    }
    return false;
}

bool stackCountsModule(const std::vector<PamStackEntry>& entries,
                       const std::string& moduleName,
                       std::size_t& count) {
    for (const PamStackEntry& entry : entries) {
        if (entry.rule.includeKind == PamIncludeKind::None &&
            std::filesystem::path(entry.rule.module).filename() ==
                moduleName) {
            ++count;
        }
        if (!stackCountsModule(entry.substack, moduleName, count)) {
            return false;
        }
    }
    return true;
}

bool isHistorySlotInclude(const PamRule& rule) {
    if (rule.includeKind == PamIncludeKind::None) {
        return false;
    }
    const std::string target =
        std::filesystem::path(rule.includeTarget).filename().string();
    return target == PamManagedPasswordSlots::historyNormalSlot().fileName ||
        target == PamManagedPasswordSlots::historyInitialSlot().fileName;
}

} // namespace

bool validatePamSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamSlotAttachVerdict& verdict,
    std::string& error) {
    verdict = {};
    if (capability.capability !=
        fic::platform::PamCapability::AuthenticationLockout) {
        error =
            "FIC PAM slot attach validation is specific to "
            "enable_authentication_lockout";
        return false;
    }

    // Reuse the daemon classification: the managed-slot grammar, the strict
    // neutral/active/broken states and the full-strategy topology check are
    // owned by the topology manager, never re-implemented here.
    PamAuthUpdateTopologyManager manager(
        platformConfig, capability, services, executables, options);
    PamTopologyStatus status;
    std::string inspectError;
    if (!manager.inspect(status, inspectError)) {
        verdict.detail =
            "FIC PAM slot state cannot be proven safe (fail closed): " +
            inspectError;
        error.clear();
        return true;
    }

    if (status.state == PamTopologyState::Disabled ||
        (status.state == PamTopologyState::Enabled && !status.manageable)) {
        // Disabled means every slot carries the exact canonical neutral
        // content. Enabled without manageability is reported by inspect()
        // ONLY when all FIC slots are canonical neutral while an external
        // pam_faillock topology exists; attaching the permanent hooks adds
        // only inert neutral pam_deny slots there.
        verdict.safeToAttach = true;
        verdict.detail =
            "all FIC PAM slots carry the canonical neutral content";
        error.clear();
        return true;
    }

    if (status.state == PamTopologyState::Enabled) {
        if (!status.ownershipMutationId.has_value()) {
            verdict.detail =
                "FIC PAM slot topology is active without a mutation id";
            error.clear();
            return true;
        }
        error.clear();
        return proveJournalOwnership(
            *status.ownershipMutationId, status.activeStrategy, capability,
            mutationJournalFile, verdict);
    }

    // Broken (malformed marker, modified body, partial or mixed strategy
    // topology) or unavailable (missing slot): fail closed. The package
    // never repairs, neutralizes or deletes such state.
    verdict.detail = status.detail.empty()
        ? "FIC PAM slot topology is broken or indeterminate"
        : "FIC PAM slot topology is not proven safe: " + status.detail;
    error.clear();
    return true;
}

namespace {

// Read-only slot state classification (the writer proofs only separate
// owned from not-owned; the canonical-neutral decision needs the direct
// strict inspection). A missing slot file stays Unavailable (never
// Neutral) and fails closed downstream.
bool readSlotInspection(
    const std::filesystem::path& configDirectory,
    const ManagedPasswordSlotSpec& spec,
    ManagedPasswordSlotInspection& inspection,
    std::string& error) {
    const std::filesystem::path path = configDirectory / spec.fileName;
    std::optional<std::string> content;
    std::error_code statusError;
    if (std::filesystem::is_regular_file(path, statusError)) {
        std::string fileContent;
        if (!readFileIfPresent(path, fileContent)) {
            error = "cannot read managed password slot " + path.string();
            return false;
        }
        content = fileContent;
    } else {
        content.reset();
    }
    return PamManagedPasswordSlots::inspectContent(
        spec, content, inspection, error);
}

// Rule J semantic checks for an FIC-owned active history pair in
// module-arguments mode (Debian 12): the options are physical fields of
// the slot bodies; the semantic effectiveness of the resulting
// enforcement is verified here (fail closed).
bool verifyHistorySlotOptions(
    const PamManagedPasswordSlotOwnership& ownership,
    const fic::platform::PamCapabilityConfig& historyCapability,
    PamSlotAttachVerdict& verdict) {
    if (!ownership.historyOptions.has_value()) {
        verdict.detail =
            "FIC-owned active history pair carries no logical pwhistory "
            "options (fail closed)";
        return false;
    }
    const ManagedPwhistorySlotOptions& slotOptions =
        *ownership.historyOptions;
    if (slotOptions.remember.value_or(
            kLegacyPamPwhistoryDefaultRemember) == 0) {
        verdict.detail =
            "FIC pwhistory slots enforce remember=0 (no history "
            "enforcement; fail closed)";
        return false;
    }
    if (!slotOptions.enforceForRoot &&
        historyCapability.subjectScope ==
            fic::platform::PamIdentitySubjectScope::AllPamSubjects) {
        verdict.detail =
            "FIC pwhistory slots omit enforce_for_root while the "
            "capability scope is AllPamSubjects (root bypasses history "
            "enforcement; fail closed)";
        return false;
    }
    return true;
}

} // namespace
bool validatePamPasswordSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamSlotAttachVerdict& verdict,
    std::string& error) {
    (void)executables;
    verdict = {};

    const fic::platform::PamCapabilityConfig* qualityCapability =
        capabilityConfig(
            platformConfig, fic::platform::PamCapability::PasswordQuality);
    const fic::platform::PamCapabilityConfig* historyCapability =
        capabilityConfig(
            platformConfig, fic::platform::PamCapability::PasswordHistory);
    if (qualityCapability == nullptr || historyCapability == nullptr) {
        error =
            "password slot attach validation requires both PasswordQuality "
            "and PasswordHistory capability configs";
        return false;
    }

    // Directory contract (mirrors PamAuthUpdateTopologyManager defaults).
    const std::filesystem::path configDirectory =
        options.configDirectory.empty()
            ? std::filesystem::path(kDefaultPasswordConfigDirectory)
            : options.configDirectory;
    const std::filesystem::path stateDirectory =
        options.stateDirectory.empty()
            ? std::filesystem::path(kDefaultPasswordStateDirectory)
            : options.stateDirectory;

    // Witness-aware read-only journal context. No bootstrap, no witness
    // write, no repair (P1-1 read-only gate inside the writers).
    MutationJournal journal(mutationJournalFile);

    // 1. Read-only ownership proofs for both password domains. The proofs
    // fail closed on any divergence (missing slot, broken marker, foreign
    // or unbound journal, Prepared record, wrong metadata/payload).
    PamManagedPasswordSlotOwnership qualityOwnership;
    std::string proofError;
    const bool qualityOwned =
        PamManagedPasswordSlotWriter(
            configDirectory, journal, PamManagedPasswordDomain::Quality)
            .proveOwnedQuality(qualityOwnership, proofError);
    PamManagedPasswordSlotOwnership historyOwnership;
    std::string historyProofError;
    const bool historyOwned =
        PamManagedPasswordSlotWriter(
            configDirectory, journal, PamManagedPasswordDomain::History)
            .proveOwnedHistory(historyOwnership, historyProofError);

    // 2. Strict physical slot state classification (missing slot =
    // Unavailable = fail closed; packaging must provide the files).
    ManagedPasswordSlotInspection qualityInspection;
    if (!readSlotInspection(
            configDirectory, PamManagedPasswordSlots::qualitySlot(),
            qualityInspection, proofError)) {
        verdict.detail =
            "managed password quality slot state cannot be proven safe "
            "(fail closed): " +
            proofError;
        error.clear();
        return true;
    }
    ManagedPasswordSlotInspection historyNormalInspection;
    ManagedPasswordSlotInspection historyInitialInspection;
    ManagedHistoryPairInspection historyPair;
    if (!readSlotInspection(
            configDirectory, PamManagedPasswordSlots::historyNormalSlot(),
            historyNormalInspection, proofError) ||
        !readSlotInspection(
            configDirectory, PamManagedPasswordSlots::historyInitialSlot(),
            historyInitialInspection, proofError) ||
        !PamManagedPasswordSlots::inspectHistoryPair(
            historyNormalInspection, historyInitialInspection,
            historyPair, proofError)) {
        verdict.detail =
            "managed password history slot state cannot be proven safe "
            "(fail closed): " +
            proofError;
        error.clear();
        return true;
    }

    // 3. Ownership consistency: an active slot MUST be owned; a neutral
    // slot MUST NOT be owned (a matching Prepared record is compensation,
    // never ownership). Everything else fails closed with the proof
    // diagnostic.
    const bool qualityActive =
        qualityInspection.state == ManagedPasswordSlotState::Active;
    const bool historyActive =
        historyPair.state == ManagedHistoryPairState::Active;
    if (qualityActive != qualityOwned) {
        verdict.detail = qualityActive
            ? "FIC password quality slot is active without proven journal "
              "ownership (fail closed): " +
                qualityOwnership.error
            : "FIC password quality slot is neutral but its ownership "
              "proof failed (fail closed): " +
                qualityOwnership.error;
        error.clear();
        return true;
    }
    if (historyActive != historyOwned) {
        verdict.detail = historyActive
            ? "FIC password history pair is active without proven journal "
              "ownership (fail closed): " +
                historyOwnership.error
            : "FIC password history pair is neutral but its ownership "
              "proof failed (fail closed): " +
                historyOwnership.error;
        error.clear();
        return true;
    }

    // 4. Rule J semantic checks on the FIC-owned active history options.
    if (historyActive &&
        !verifyHistorySlotOptions(historyOwnership, *historyCapability,
                                  verdict)) {
        error.clear();
        return true;
    }

    // 5. Effective Primary password stacks across all configured services.
    PamConfiguration configuration(platformConfig);
    for (const std::string& service : services) {
        PamEffectiveStack stack;
        std::string stackError;
        if (!configuration.buildEffectiveStack(
                service, PamManagementGroup::Password, stack, stackError)) {
            verdict.detail =
                "cannot build effective Primary password stack for "
                "service " +
                service + " (fail closed): " + stackError;
            error.clear();
            return true;
        }

        // Rule I: at most one pam_pwquality.so in the Primary stack.
        std::size_t pwqualityCount = 0;
        stackCountsModule(stack.entries, "pam_pwquality.so",
                          pwqualityCount);
        if (pwqualityCount > 1) {
            verdict.detail =
                "more than one pam_pwquality.so in the Primary password "
                "stack of service " +
                service + " (Rule I; fail closed)";
            error.clear();
            return true;
        }

        // Rule I external detection: distro `pwquality` profile selected
        // in the state database AND pam_pwquality.so in the parsed stack.
        if (pwqualityCount == 1) {
            std::set<std::string> identifiers;
            std::string stateError;
            if (!selectedPasswordStateIdentifiers(
                    stateDirectory, identifiers, stateError)) {
                verdict.detail =
                    "cannot read pam-auth-update password selection state "
                    "(fail closed): " +
                    stateError;
                error.clear();
                return true;
            }
            if (identifiers.count("pwquality") != 0 && qualityActive) {
                verdict.detail =
                    "external distro pwquality is present while the FIC "
                    "password quality slot is active (Rule I ownership "
                    "conflict; fail closed)";
                error.clear();
                return true;
            }
        }

        // Rule G: an active FIC history pair requires a token producer
        // (pam_pwquality.so) in the Primary stack BEFORE the FIC history
        // include point; history-only is Unsupported (fail closed).
        //
        // The effective stack expands slot includes IN PLACE (the slot
        // bodies are canonical and are proven separately above), so the
        // FIC history include point is identified by its first history
        // rule (pam_pwhistory.so) inside the flattened rule sequence.
        if (historyActive) {
            std::vector<PamRule> flat;
            flattenStackRules(stack.entries, flat);
            std::size_t historyPosition = flat.size();
            std::size_t producerPosition = flat.size();
            bool producerFound = false;
            for (std::size_t index = 0; index < flat.size(); ++index) {
                const bool isHistoryRule =
                    flat[index].includeKind == PamIncludeKind::None &&
                    std::filesystem::path(flat[index].module).filename() ==
                        "pam_pwhistory.so";
                if (isHistoryRule) {
                    historyPosition = index;
                    break;
                }
                if (!producerFound &&
                    flat[index].includeKind == PamIncludeKind::None &&
                    std::filesystem::path(flat[index].module).filename() ==
                        "pam_pwquality.so") {
                    producerPosition = index;
                    producerFound = true;
                }
            }
            if (!producerFound) {
                verdict.detail =
                    "FIC password history is active with no pam_pwquality "
                    "token producer in the Primary password stack of "
                    "service " +
                    service + " (Rule G history-only; fail closed)";
                error.clear();
                return true;
            }
            // The ordering requirement applies only when the FIC history
            // entry is already present in the parsed graph (attached
            // hook); pre-attach the history include is not in the graph
            // yet and the producer presence alone is the decision input.
            if (historyPosition != flat.size() &&
                producerPosition >= historyPosition) {
                verdict.detail =
                    "pam_pwquality token producer does not precede the FIC "
                    "history include in the Primary password stack of "
                    "service " +
                    service + " (Rule G ordering; fail closed)";
                error.clear();
                return true;
            }
        }

        // Conf-mode semantic check (Rule J): remember=0 in the
        // authoritative pwhistory.conf fails closed (Debian 13 / Ubuntu
        // conf storage). A missing option or any other value is safe
        // (the module default remember applies).
        if (historyCapability->configurationMode ==
                fic::platform::PamCapabilityConfigurationMode::
                    ProviderConfigFile &&
            !historyCapability->configPath.empty()) {
            std::string confError;
            if (PamOptionFile::hasOnlyValue(
                    historyCapability->configPath, "remember", "0",
                    confError)) {
                verdict.detail =
                    historyCapability->configPath.string() +
                    " enforces remember=0 (no history enforcement; fail "
                    "closed)";
                error.clear();
                return true;
            }
        }
    }

    verdict.safeToAttach = true;
    verdict.detail = "FIC password slots are proven safe to attach";
    error.clear();
    return true;
}

} // namespace fic::identity::pam
