#include "modules/identity_access/pam/PamSlotAttachValidator.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"
#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "modules/identity_access/pam/PamPwhistoryArguments.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <algorithm>
#include <cctype>
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

std::string trimSpaces(const std::string& value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char c) {
            return std::isspace(c) != 0;
        });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char c) {
            return std::isspace(c) != 0;
        }).base();
    return std::string(first, last);
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

bool isQualitySlotInclude(const PamRule& rule) {
    if (rule.includeKind != PamIncludeKind::Include) {
        return false;
    }
    const std::string target =
        std::filesystem::path(rule.includeTarget).filename().string();
    return target == PamManagedPasswordSlots::qualitySlot().fileName;
}

// Typed pwhistory.conf "remember" classification (P2-1): replaces the
// inverted-boolean hasOnlyValue("remember", "0") test, which conflated
// remember=0, option missing, unreadable file and parse ambiguity into one
// "not remember=0" outcome. pam_pwhistory's documented default remember is
// NONZERO (the module enforces history by default), so:
//   DefaultNonZero   — no explicit directive; the documented module default
//                      applies (nonzero enforcement);
//   ExplicitNonZero  — remember=<N>, N > 0;
//   Zero             — remember=0 (no history enforcement);
//   Broken           — unreadable file, malformed values, or ambiguous
//                      duplicate directives (fail closed, never guessed).
// Duplicate remember directives follow the actual underlying semantics:
// they are NOT resolved by last-wins guessing here — an ambiguous config
// is Broken and fails closed.
enum class PwhistoryRememberState {
    DefaultNonZero,
    ExplicitNonZero,
    Zero,
    Broken
};

PwhistoryRememberState readPwhistoryConfRememberState(
    const std::filesystem::path& path) {
    bool existed = false;
    std::string content;
    std::string error;
    // Reuses the validator's own file reader; the TrustedFileReader-backed
    // PamOptionFile read is used for the write path, this is the strict
    // read-only classification path. Missing file = documented default.
    std::error_code statusError;
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path, statusError);
    if (statusError) {
        if (statusError ==
            std::make_error_code(std::errc::no_such_file_or_directory)) {
            return PwhistoryRememberState::DefaultNonZero;
        }
        return PwhistoryRememberState::Broken;
    }
    if (!std::filesystem::exists(status)) {
        return PwhistoryRememberState::DefaultNonZero;
    }
    if (!std::filesystem::is_regular_file(status)) {
        return PwhistoryRememberState::Broken;
    }
    if (!readFileIfPresent(path, content)) {
        return PwhistoryRememberState::Broken;
    }
    std::istringstream stream(content);
    std::string line;
    bool found = false;
    bool sawZero = false;
    bool sawNonZero = false;
    while (std::getline(stream, line)) {
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) {
            line.erase(comment);
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        const std::string key = trimSpaces(line.substr(0, equals));
        const std::string value = trimSpaces(line.substr(equals + 1));
        if (key != "remember") {
            continue;
        }
        unsigned parsed = 0;
        if (value.empty() ||
            std::any_of(value.begin(), value.end(), [](unsigned char c) {
                return std::isdigit(c) == 0;
            })) {
            return PwhistoryRememberState::Broken;
        }
        try {
            parsed = static_cast<unsigned>(std::stoul(value));
        } catch (...) {
            return PwhistoryRememberState::Broken;
        }
        found = true;
        if (parsed == 0) {
            sawZero = true;
        } else {
            sawNonZero = true;
        }
    }
    if (!found) {
        return PwhistoryRememberState::DefaultNonZero;
    }
    // Ambiguous/conflicting duplicate directives are never silently
    // resolved (no last-wins guessing): fail closed.
    if (sawZero && sawNonZero) {
        return PwhistoryRememberState::Broken;
    }
    return sawZero ? PwhistoryRememberState::Zero
                   : PwhistoryRememberState::ExplicitNonZero;
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

    // 3.5. Neutral ⇔ Unbound journal provenance (P1-4 hardening): a
    // Neutral physical slot is provenance-safe only when the journal
    // carries NO active record of that canonical domain. Stale Applied or
    // Prepared provenance behind a Neutral slot is exactly the state this
    // check rejects; the validator never discards, completes or repairs
    // such records (that is the runtime/Step 3 recovery responsibility).
    if (!qualityActive) {
        std::uint64_t domainMutationId = 0;
        std::string domainError;
        const PasswordDomainJournalState domainState =
            PamManagedPasswordSlotWriter(
                configDirectory, journal, PamManagedPasswordDomain::Quality)
                .inspectJournalBindingForDomain(
                    domainMutationId, domainError);
        switch (domainState) {
        case PasswordDomainJournalState::Unbound:
            break;
        case PasswordDomainJournalState::Applied:
            verdict.detail =
                "FIC password quality slot is neutral while an Applied "
                "journal record (mutation " +
                std::to_string(domainMutationId) +
                ") still claims the quality domain: stale provenance (fail "
                "closed)";
            error.clear();
            return true;
        case PasswordDomainJournalState::Prepared:
            verdict.detail =
                "FIC password quality slot is neutral while a Prepared "
                "journal record (mutation " +
                std::to_string(domainMutationId) +
                ") still claims the quality domain: unresolved crash "
                "provenance (fail closed; recovery is the runtime "
                "responsibility)";
            error.clear();
            return true;
        case PasswordDomainJournalState::Conflict:
        case PasswordDomainJournalState::Invalid:
            verdict.detail =
                "FIC password quality journal domain state cannot be "
                "proven Unbound for the neutral slot (fail closed): " +
                domainError;
            error.clear();
            return true;
        }
    }
    if (!historyActive) {
        std::uint64_t domainMutationId = 0;
        std::string domainError;
        const PasswordDomainJournalState domainState =
            PamManagedPasswordSlotWriter(
                configDirectory, journal, PamManagedPasswordDomain::History)
                .inspectJournalBindingForDomain(
                    domainMutationId, domainError);
        switch (domainState) {
        case PasswordDomainJournalState::Unbound:
            break;
        case PasswordDomainJournalState::Applied:
            verdict.detail =
                "FIC password history pair is neutral while an Applied "
                "journal record (mutation " +
                std::to_string(domainMutationId) +
                ") still claims the history domain: stale provenance (fail "
                "closed)";
            error.clear();
            return true;
        case PasswordDomainJournalState::Prepared:
            verdict.detail =
                "FIC password history pair is neutral while a Prepared "
                "journal record (mutation " +
                std::to_string(domainMutationId) +
                ") still claims the history domain: unresolved crash "
                "provenance (fail closed; recovery is the runtime "
                "responsibility)";
            error.clear();
            return true;
        case PasswordDomainJournalState::Conflict:
        case PasswordDomainJournalState::Invalid:
            verdict.detail =
                "FIC password history journal domain state cannot be "
                "proven Unbound for the neutral pair (fail closed): " +
                domainError;
            error.clear();
            return true;
        }
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

        // Rule I (P1-3): external distro pwquality classification. The
        // SELECTION state (`Module: pwquality` in the pam-auth-update
        // password state database) is read INDEPENDENTLY of the provider
        // count in the current graph — a temporarily missing provider must
        // not hide a requested distro provider, because a later graph
        // regeneration can reintroduce it.
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
        const bool externalPwqualitySelected =
            identifiers.count("pwquality") != 0;
        // EFFECTIVE external provider: selected AND exactly one
        // pam_pwquality.so in the parsed Primary stack. (The >1 count is
        // already rejected above.) A selected profile without a provider
        // in the current graph is NOT effective — and vice versa.
        const bool externalPwqualityEffective =
            externalPwqualitySelected && pwqualityCount == 1;

        // Ownership conflict: FIC quality Active + external selection
        // always fails closed, EVEN IF the current generated graph
        // temporarily lacks the distro provider — the selection state
        // already requests the distro provider and a future regeneration
        // can reintroduce it as a duplicate token producer.
        if (externalPwqualitySelected && qualityActive) {
            verdict.detail =
                "external distro pwquality is selected in the "
                "pam-auth-update password state while the FIC password "
                "quality slot is active (Rule I ownership conflict; fail "
                "closed even though the current graph carries " +
                std::to_string(pwqualityCount) + " distro provider)";
            error.clear();
            return true;
        }

        // Topology consistency for attach decisions (fail closed):
        //   * selected without provider — broken/inconsistent selection
        //     topology (the selection requests a provider that the graph
        //     does not deliver); never treated as a silently safe external
        //     state;
        //   * provider without selection — an unmanaged/manual topology
        //     ONLY when the provider is NOT the FIC-owned active one.
        //     A single pam_pwquality.so delivered through the FIC-owned
        //     active quality slot is the FIC-owned topology (the slot body
        //     is proven canonical Active + MatchingApplied above), not a
        //     distro provider, and must not fail here.
        // Both unmanaged branches fail closed when the validator
        // classifies live/attach topology with a non-FIC provider.
        if (externalPwqualitySelected != (pwqualityCount == 1) &&
            !(pwqualityCount == 1 && qualityActive)) {
            verdict.detail =
                externalPwqualitySelected
                ? "distro pwquality is selected in the pam-auth-update "
                  "password state but the Primary password stack of "
                  "service " +
                      service +
                      " contains no pam_pwquality.so provider (Rule I "
                      "inconsistent external topology; fail closed)"
                : "the Primary password stack of service " + service +
                      " contains pam_pwquality.so but no distro pwquality "
                      "profile is selected in the pam-auth-update password "
                      "state (Rule I unmanaged topology; fail closed)";
            error.clear();
            return true;
        }
        // When an external provider is effective it must actually enforce
        // quality: its flow semantics are proven by the control-flow
        // analysis below (the effective verdict is consumed there).

        // Rule G (P1-2): control-flow proof, not textual ordering. The
        // previous flattened index comparison (producerPosition <
        // historyPosition) proved only textual order; a success-action
        // jump can bypass either the producer or the history consumer
        // while their textual order stays "correct". The analyzer's
        // symbolic execution models the real Linux-PAM control flow over
        // the parsed effective stack (substack boundaries respected,
        // unknown control syntax / unrepresentable jumps / budget
        // exhaustion fail closed) and answers exactly the three security
        // questions:
        //   qualityNonBypassable       — no successful password-change
        //                                path skips pam_pwquality.so;
        //   historyNonBypassable       — no successful path reaches the
        //                                installation consumer without
        //                                passing pam_pwhistory.so use_authtok;
        //   historyAlwaysHasTokenProducer — no successful path reaches
        //                                the history rule without a
        //                                producer success earlier on the
        //                                SAME path (token-state
        //                                symbolic execution).
        if (historyActive || pwqualityCount == 1) {
            PamPasswordFlowAnalysis flow;
            std::string flowError;
            if (!analyzePasswordFlow(stack, platformConfig, flow, flowError)) {
                verdict.detail =
                    "Rule G password control flow of service " + service +
                    " cannot be analyzed (fail closed): " + flowError;
                error.clear();
                return true;
            }
            // Any unsupported/unrepresentable control flow fails closed.
            if (!flow.violations.empty()) {
                verdict.detail =
                    "Rule G password control flow of service " + service +
                    " is not proven safe (fail closed): " +
                    flow.violations.front().message;
                error.clear();
                return true;
            }
            if (pwqualityCount == 1 && !flow.qualityNonBypassable) {
                verdict.detail =
                    "Rule G: a successful password-change path of service " +
                    service + " bypasses pam_pwquality.so (quality "
                    "enforcement not proven; fail closed)";
                error.clear();
                return true;
            }
            if (historyActive) {
                if (!flow.historyAlwaysHasTokenProducer) {
                    verdict.detail =
                        "Rule G: a successful password-change path of "
                        "service " +
                        service +
                        " reaches pam_pwhistory.so without a proven token "
                        "producer success on the same path "
                        "(PasswordTokenProducerBypass; fail closed)";
                    error.clear();
                    return true;
                }
                if (!flow.historyNonBypassable) {
                    verdict.detail =
                        "Rule G: a successful password-change path of "
                        "service " +
                        service +
                        " bypasses pam_pwhistory.so use_authtok (history "
                        "enforcement not proven; fail closed)";
                    error.clear();
                    return true;
                }
            }
        }

        // Conf-mode semantic check (Rule J, P2-1): typed/effective
        // semantics of the authoritative pwhistory.conf, never an inverted
        // boolean. Zero remember and any broken/ambiguous/unreadable state
        // fail closed; the documented nonzero module default (no explicit
        // directive) is the only implicit-safe state.
        if (historyCapability->configurationMode ==
                fic::platform::PamCapabilityConfigurationMode::
                    ProviderConfigFile &&
            !historyCapability->configPath.empty()) {
            const PwhistoryRememberState rememberState =
                readPwhistoryConfRememberState(
                    historyCapability->configPath);
            switch (rememberState) {
            case PwhistoryRememberState::Zero:
                verdict.detail =
                    historyCapability->configPath.string() +
                    " enforces remember=0 (no history enforcement; fail "
                    "closed)";
                error.clear();
                return true;
            case PwhistoryRememberState::Broken:
                verdict.detail =
                    historyCapability->configPath.string() +
                    " cannot be safely parsed for an effective remember "
                    "state (unreadable, malformed or ambiguous; fail "
                    "closed)";
                error.clear();
                return true;
            case PwhistoryRememberState::DefaultNonZero:
            case PwhistoryRememberState::ExplicitNonZero:
                break;
            }
        }
    }

    verdict.safeToAttach = true;
    verdict.detail = "FIC password slots are proven safe to attach";
    error.clear();
    return true;
}

} // namespace fic::identity::pam
