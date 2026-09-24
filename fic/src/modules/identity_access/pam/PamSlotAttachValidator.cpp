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
#include <charconv>
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

// Observe the expanded provider sources independently from physical include
// attachment. Includes disappear during expansion; substacks retain scope.
struct ManagedPasswordAttachmentObservation {
    std::size_t providerCount = 0;
    std::size_t providerRulesFromSlot = 0;
    std::size_t exactIncludeCount = 0;
    bool wrongIncludeKind = false;
};

void observeProviders(const std::vector<PamStackEntry>& entries,
                      const std::filesystem::path& slot,
                      const std::string& module,
                      ManagedPasswordAttachmentObservation& observation) {
    for (const auto& entry : entries) {
        if (entry.rule.includeKind == PamIncludeKind::None &&
            std::filesystem::path(entry.rule.module).filename() == module) {
            ++observation.providerCount;
            if (entry.rule.source.lexically_normal() == slot.lexically_normal()) {
                ++observation.providerRulesFromSlot;
            }
        }
        observeProviders(entry.substack, slot, module, observation);
    }
}

bool observeAttachment(const PamEffectiveStack& stack,
                       const std::filesystem::path& slot,
                       const std::string& module,
                       ManagedPasswordAttachmentObservation& observation,
                       std::string& error) {
    observation = {};
    observeProviders(stack.entries, slot, module, observation);
    for (const auto& source : stack.sourceFiles) {
        PamConfigFileSnapshot snapshot;
        std::vector<PamRule> rules;
        if (!PamConfigFileTransaction::capture(source, snapshot, error) ||
            !snapshot.existed ||
            !PamConfiguration::parseRulesContent(
                source, snapshot.content, rules, error)) {
            if (error.empty()) error = "PAM graph source disappeared: " + source.string();
            return false;
        }
        for (const auto& rule : rules) {
            if (rule.includeKind == PamIncludeKind::None ||
                std::filesystem::path(rule.includeTarget).filename() != slot.filename() ||
                (rule.includeKind != PamIncludeKind::IncludeAll &&
                 rule.group != PamManagementGroup::Password)) {
                continue;
            }
            if (rule.group == PamManagementGroup::Password &&
                rule.includeKind == PamIncludeKind::Include) {
                ++observation.exactIncludeCount;
            } else {
                observation.wrongIncludeKind = true;
            }
        }
    }
    return true;
}

bool verifyActiveAttachment(
    const ManagedPasswordAttachmentObservation& observation,
    const std::set<std::string>& selected,
    const std::string& slot,
    const std::string& module,
    std::string& error) {
    const std::string hook = slot + "-hook";
    if (selected.count(hook) == 0) {
        error = slot + " is Active+Applied but " + hook + " is not selected";
    } else if (observation.wrongIncludeKind) {
        error = slot + " requires password include, not substack or @include";
    } else if (observation.exactIncludeCount != 1) {
        error = hook + " requires exactly one password include " + slot +
            "; observed " + std::to_string(observation.exactIncludeCount);
    } else if (observation.providerCount != 1) {
        error = slot + " requires exactly one " + module + " provider";
    } else if (observation.providerRulesFromSlot != 1) {
        error = module + " source is not the FIC-owned " + slot + " slot";
    } else {
        error.clear();
        return true;
    }
    error += " (fail closed)";
    return false;
}

// The generic provider semantic verifier checks input topology/overrides,
// not effective pwhistory config values. Keep this read-only typed reader
// local to the attach validator. Linux-PAM defaults: remember=10 (also
// encoded by PamPwhistoryArguments), enforce_for_root disabled.
enum class PwhistoryRememberState { DefaultNonZero, ExplicitNonZero, Zero };
enum class PwhistoryFlagState { DefaultDisabled, Enabled };
struct PwhistoryConfigState {
    PwhistoryRememberState remember = PwhistoryRememberState::DefaultNonZero;
    PwhistoryFlagState enforceForRoot = PwhistoryFlagState::DefaultDisabled;
    bool broken = false;
};

PwhistoryConfigState readPwhistoryConfigState(const std::filesystem::path& path) {
    PwhistoryConfigState state;
    PamConfigFileSnapshot snapshot;
    std::string error;
    // Reject non-regular objects before capture (in particular a FIFO must
    // not block a read-only validation waiting for a writer).
    std::error_code statusError;
    const auto status = std::filesystem::symlink_status(path, statusError);
    if (path.empty() ||
        (statusError && statusError != std::errc::no_such_file_or_directory) ||
        (status.type() != std::filesystem::file_type::not_found &&
         !std::filesystem::is_regular_file(status)) ||
        !PamConfigFileTransaction::capture(path, snapshot, error)) {
        state.broken = true;
        return state;
    }
    if (!snapshot.existed) return state;
    std::istringstream stream(snapshot.content);
    std::string line;
    std::set<std::string> managedKeys;
    while (std::getline(stream, line)) {
        if (line.find('\0') != std::string::npos) {
            state.broken = true;
            break;
        }
        line = trimSpaces(line.substr(0, line.find('#')));
        if (line.empty()) continue;
        const auto equals = line.find('=');
        const auto key = trimSpaces(line.substr(0, equals));
        const auto value = equals == std::string::npos
            ? std::string{} : trimSpaces(line.substr(equals + 1));
        if (key.empty() || !std::all_of(key.begin(), key.end(), [](unsigned char c) {
                return std::isalnum(c) || c == '_' || c == '-';
            }) || (equals != std::string::npos && value.empty())) {
            state.broken = true;
            break;
        }
        if (key != "remember" && key != "enforce_for_root") continue;
        if (!managedKeys.insert(key).second) {
            state.broken = true; // No duplicate/last-wins assumptions.
            break;
        }
        if (key == "enforce_for_root") {
            // Canonical native flag grammar; assignments are not booleans.
            if (equals != std::string::npos) {
                state.broken = true;
                break;
            }
            state.enforceForRoot = PwhistoryFlagState::Enabled;
        } else {
            unsigned remember = 0;
            const auto parsed = std::from_chars(
                value.data(), value.data() + value.size(), remember);
            if (value.empty() || parsed.ec != std::errc{} ||
                parsed.ptr != value.data() + value.size()) {
                state.broken = true;
                break;
            }
            state.remember = remember == 0 ? PwhistoryRememberState::Zero
                : PwhistoryRememberState::ExplicitNonZero;
        }
    }
    return state;
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
    PamConfigFileSnapshot snapshot;
    if (!PamConfigFileTransaction::capture(
            configDirectory / spec.fileName, snapshot, error)) {
        return false;
    }
    const std::optional<std::string> content = snapshot.existed
        ? std::optional<std::string>(snapshot.content) : std::nullopt;
    return PamManagedPasswordSlots::inspectContent(
        spec, content, inspection, error);
}

// Rule J semantic checks for an FIC-owned active history pair in
// module-arguments mode (Debian 12): the options are physical fields of
// the slot bodies; the semantic effectiveness of the resulting
// enforcement is verified here (fail closed).
bool verifyHistorySlotOptions(
    const PamManagedPasswordSlotOwnership& ownership,
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
    // Root enforcement is an independent option-policy state.
    return true;
}

} // namespace
bool verifyAttachedTopology(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    const std::filesystem::path& stateDirectory,
    const std::filesystem::path& configDirectory,
    const ManagedPasswordSlotInspection& qualityInspection,
    const ManagedHistoryPairInspection& historyPair,
    const PamManagedPasswordSlotOwnership& historyOwnership,
    PamSlotAttachVerdict& verdict,
    std::string& error);

bool validatePamPasswordSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamSlotAttachVerdict& verdict,
    std::string& error) {
    return validatePamPasswordSlotAttach(
        platformConfig, services, executables, mutationJournalFile, options,
        PamAttachmentValidationPhase::PreAttach, verdict, error);
}

bool validatePamPasswordSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamAttachmentValidationPhase phase,
    PamSlotAttachVerdict& verdict,
    std::string& error) {
    (void)executables;
    verdict = {};

    // Phase-agnostic services invariant (P2): the per-service loop is the
    // ONLY place the live password topology is examined in either phase,
    // so an empty service list would make every per-service check
    // vacuously true and could turn an unknown topology into an unproven
    // PASS. Fail closed in BOTH phases: a pam-auth-update platform
    // profile without configured password services is a
    // configuration/profile error, never a safe attach state.
    if (services.empty()) {
        verdict.detail =
            "no configured password services on the pam-auth-update "
            "platform profile (empty service list; fail closed)";
        error.clear();
        return true;
    }

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
        case PasswordDomainJournalState::VirginUnbound:
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
        case PasswordDomainJournalState::VirginUnbound:
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
        historyCapability->configurationMode ==
            fic::platform::PamCapabilityConfigurationMode::ModuleArguments &&
        !verifyHistorySlotOptions(historyOwnership, verdict)) {
        error.clear();
        return true;
    }

    // Rule J physical pwhistory.conf state is part of the pre-attach
    // contract: the slot body itself must be well-formed regardless of the
    // attach phase.
    if (historyActive) {
        const auto pwhistoryState =
            readPwhistoryConfigState(historyCapability->configPath);
        if (pwhistoryState.broken) {
            verdict.detail = "pwhistory.conf is unreadable, non-regular, malformed or "
                "has duplicate managed keys (Rule J; fail closed)";
            error.clear();
            return true;
        }
        if (pwhistoryState.remember == PwhistoryRememberState::Zero) {
            verdict.detail = "pwhistory.conf enforces remember=0 (Rule J; fail closed)";
            error.clear();
            return true;
        }
    }

    // Phase-agnostic live-graph sanity (cheap, always on): duplicate
    // managed includes and Rule I provider-count overflows are topology
    // defects regardless of the attach phase and must never pass.
    if (phase == PamAttachmentValidationPhase::PreAttach) {
        std::set<std::string> preSelected;
        std::string preSelectError;
        if (!selectedPasswordStateIdentifiers(
                stateDirectory, preSelected, preSelectError)) {
            verdict.detail =
                "cannot read pam-auth-update password state (fail closed): " +
                preSelectError;
            error.clear();
            return true;
        }
        PamConfiguration preConfiguration(platformConfig);
        for (const std::string& service : services) {
            PamEffectiveStack preStack;
            std::string preStackError;
            if (!preConfiguration.buildEffectiveStack(
                    service, PamManagementGroup::Password, preStack,
                    preStackError)) {
                verdict.detail =
                    "cannot build effective Primary password stack for "
                    "service " + service + " (fail closed): " + preStackError;
                error.clear();
                return true;
            }
            ManagedPasswordAttachmentObservation preQuality;
            ManagedPasswordAttachmentObservation preHistory;
            ManagedPasswordAttachmentObservation preInitial;
            if (!observeAttachment(preStack, configDirectory / "fic-password-quality",
                                   "pam_pwquality.so", preQuality, preStackError) ||
                !observeAttachment(preStack, configDirectory / "fic-password-history",
                                   "pam_pwhistory.so", preHistory, preStackError) ||
                !observeAttachment(preStack, configDirectory / "fic-password-history-initial",
                                   "pam_pwhistory.so", preInitial, preStackError)) {
                verdict.detail = "cannot prove password attachment: " + preStackError;
                error.clear();
                return true;
            }
            if (preQuality.providerCount > 1) {
                verdict.detail =
                    "more than one pam_pwquality.so in the Primary password "
                    "stack of service " + service + " (Rule I; fail closed)";
                error.clear();
                return true;
            }
            if (preQuality.exactIncludeCount > 1 ||
                preHistory.exactIncludeCount > 1 ||
                preInitial.exactIncludeCount > 1) {
                verdict.detail =
                    "exactly one password include per managed slot is "
                    "supported; duplicate managed password include "
                    "(fail closed)";
                error.clear();
                return true;
            }
            if (preQuality.wrongIncludeKind || preHistory.wrongIncludeKind ||
                preInitial.wrongIncludeKind) {
                verdict.detail =
                    "managed password slot requires password include, not "
                    "substack or @include (fail closed)";
                error.clear();
                return true;
            }
            if (historyActive && (preInitial.exactIncludeCount != 0 ||
                                  preInitial.providerRulesFromSlot != 0)) {
                verdict.detail =
                    "FIC history-initial is the live history branch; only "
                    "the normal managed history slot is supported (fail closed)";
                error.clear();
                return true;
            }
            const bool qualityHookSelected =
                preSelected.count("fic-password-quality-hook") != 0;
            const bool historyHookSelected =
                preSelected.count("fic-password-history-hook") != 0;
            if ((qualityActive && qualityHookSelected &&
                 preQuality.exactIncludeCount == 0 &&
                 preQuality.providerCount != 0) ||
                (historyActive && historyHookSelected &&
                 preHistory.exactIncludeCount == 0 &&
                 preHistory.providerCount != 0) ||
                (qualityActive && preQuality.exactIncludeCount == 1 &&
                 preQuality.providerRulesFromSlot != 1) ||
                (historyActive && preHistory.exactIncludeCount == 1 &&
                 preHistory.providerRulesFromSlot != 1)) {
                verdict.detail =
                    "FIC password hook requires exactly one password include "
                    "of the FIC-owned managed slot; pam_pwquality.so/"
                    "pam_pwhistory.so source is not the managed slot "
                    "(fail closed)";
                error.clear();
                return true;
            }
            const bool externalPwqualitySelected =
                preSelected.count("pwquality") != 0;
            if (externalPwqualitySelected && qualityActive) {
                verdict.detail =
                    "external distro pwquality is selected in the "
                    "pam-auth-update password state while the FIC password "
                    "quality slot is active (Rule I ownership conflict; "
                    "fail closed)";
                error.clear();
                return true;
            }
            if (externalPwqualitySelected !=
                    (preQuality.providerCount == 1) &&
                !(preQuality.providerCount == 1 && qualityActive)) {
                verdict.detail =
                    externalPwqualitySelected
                    ? "distro pwquality is selected in the pam-auth-update "
                      "password state but the Primary password stack of "
                      "service " + service +
                          " contains no pam_pwquality.so provider (Rule I "
                          "inconsistent external topology; fail closed)"
                    : "the Primary password stack of service " + service +
                          " contains pam_pwquality.so but no distro pwquality "
                          "profile is selected in the pam-auth-update password "
                          "state (Rule I unmanaged topology; fail closed)";
                error.clear();
                return true;
            }
            // Rule G (P1-2): control-flow proof over the live graph is
            // read-only analysis and applies in both attach phases.
            const std::size_t prePwqualityCount = preQuality.providerCount;
            if (historyActive || prePwqualityCount == 1) {
                PamPasswordFlowAnalysis preFlow;
                std::string preFlowError;
                if (!analyzePasswordFlow(preStack, platformConfig,
                                         {prePwqualityCount == 1, historyActive},
                                         preFlow, preFlowError)) {
                    verdict.detail =
                        "Rule G password control flow of service " + service +
                        " cannot be analyzed (fail closed): " + preFlowError;
                    error.clear();
                    return true;
                }
                if (!preFlow.violations.empty()) {
                    verdict.detail =
                        "Rule G password control flow of service " + service +
                        " is not proven safe (fail closed): " +
                        preFlow.violations.front().message;
                    error.clear();
                    return true;
                }
                if (prePwqualityCount == 1 && !preFlow.qualityNonBypassable) {
                    verdict.detail =
                        "Rule G: a successful password-change path of service " +
                        service + " bypasses pam_pwquality.so (quality "
                        "enforcement not proven; fail closed)";
                    error.clear();
                    return true;
                }
                if (historyActive) {
                    if (!preFlow.historyAlwaysHasTokenProducer) {
                        verdict.detail =
                            "Rule G: a successful password-change path of " +
                            service + " reaches pam_pwhistory.so without a "
                            "preceding token producer on the same path "
                            "(fail closed)";
                        error.clear();
                        return true;
                    }
                    if (!preFlow.historyNonBypassable) {
                        verdict.detail =
                            "Rule G: a successful password-change path of " +
                            service + " bypasses pam_pwhistory.so use_authtok "
                            "(history recording not proven; fail closed)";
                        error.clear();
                        return true;
                    }
                }
            }
            if (historyActive && preQuality.providerCount == 0) {
                verdict.detail =
                    "Rule G: history-only is unsupported: no quality token "
                    "producer";
                error.clear();
                return true;
            }
            if (!historyActive && preHistory.providerCount != 0) {
                verdict.detail =
                    "foreign history provider: pam_pwhistory.so source is "
                    "not the FIC-owned fic-password-history slot (fail closed)";
                error.clear();
                return true;
            }
            if (historyActive && preHistory.exactIncludeCount != 0 &&
                preHistory.providerCount != preHistory.providerRulesFromSlot) {
                verdict.detail =
                    "exactly one pam_pwhistory.so sourced from the FIC-owned "
                    "fic-password-history slot is supported (fail closed)";
                error.clear();
                return true;
            }
        }
    }

    // Step 5B pre-attach phase: the physical/journal proof above is the
    // pre-attach contract. When the caller explicitly requested the later
    // ATTACHED phase, the live-graph attachment proof (selected permanent
    // hooks, exact includes, providers sourced from the managed slots and
    // the Rule G/J topology) additionally applies.
    if (phase == PamAttachmentValidationPhase::Attached) {
        // The helper owns the Attached-phase verdict completely: it returns
        // true for BOTH safe and unsafe verdicts (an unsafe verdict is not
        // an error), so its result must never be overwritten here.
        if (!verifyAttachedTopology(
                platformConfig, services, stateDirectory, configDirectory,
                qualityInspection, historyPair, historyOwnership, verdict,
                error)) {
            return false;
        }
        return true;
    }
    verdict.safeToAttach = true;
    verdict.detail =
        "FIC password slots are proven safe for the subsequent attach "
        "(PreAttach phase)";
    return true;
}

// Step 5B Attached-phase topology proof (extracted verbatim from the former
// monolithic Step 5 block; body identical, only the signature changed). The
// caller has already proven the physical slots and journal provenance.
bool verifyAttachedTopology(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    const std::filesystem::path& stateDirectory,
    const std::filesystem::path& configDirectory,
    const ManagedPasswordSlotInspection& qualityInspection,
    const ManagedHistoryPairInspection& historyPair,
    const PamManagedPasswordSlotOwnership& historyOwnership,
    PamSlotAttachVerdict& verdict,
    std::string& error) {
    const bool qualityActive =
        qualityInspection.state == ManagedPasswordSlotState::Active;
    const bool historyActive =
        historyPair.state == ManagedHistoryPairState::Active;
    const fic::platform::PamCapabilityConfig* historyCapability =
        capabilityConfig(
            platformConfig, fic::platform::PamCapability::PasswordHistory);
    if (historyCapability == nullptr) {
        error =
            "password slot attach validation requires the PasswordHistory "
            "capability config";
        return false;
    }
    std::set<std::string> identifiers;
    std::string stateError;
    if (!selectedPasswordStateIdentifiers(
            stateDirectory, identifiers, stateError)) {
        verdict.detail =
            "cannot read pam-auth-update password selection state "
            "(fail closed): " + stateError;
        error.clear();
        return true;
    }

    // 5. Effective Primary password stacks across all configured services.
    // (The empty-services invariant is enforced phase-agnostically at the
    // top of validatePamPasswordSlotAttach; see the comment there.)
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
        ManagedPasswordAttachmentObservation qualityAttachment;
        ManagedPasswordAttachmentObservation historyAttachment;
        ManagedPasswordAttachmentObservation initialAttachment;
        if (!observeAttachment(stack, configDirectory / "fic-password-quality",
                               "pam_pwquality.so", qualityAttachment, stackError) ||
            !observeAttachment(stack, configDirectory / "fic-password-history",
                               "pam_pwhistory.so", historyAttachment, stackError) ||
            !observeAttachment(stack, configDirectory / "fic-password-history-initial",
                               "pam_pwhistory.so", initialAttachment, stackError)) {
            verdict.detail = "cannot prove password attachment: " + stackError;
            error.clear();
            return true;
        }
        if ((!qualityActive && qualityAttachment.exactIncludeCount > 1) ||
            (!historyActive && historyAttachment.exactIncludeCount > 1) ||
            initialAttachment.exactIncludeCount > 1) {
            verdict.detail = "duplicate managed password include (fail closed)";
            error.clear();
            return true;
        }
        const auto pwqualityCount = qualityAttachment.providerCount;
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

        if (historyActive && (initialAttachment.exactIncludeCount != 0 ||
                              initialAttachment.wrongIncludeKind ||
                              initialAttachment.providerRulesFromSlot != 0)) {
            verdict.detail = "FIC history-initial is the live history branch; "
                "only the normal managed history slot is supported (fail closed)";
            error.clear();
            return true;
        }
        std::string attachedError;
        if ((qualityActive && !verifyActiveAttachment(
                 qualityAttachment, identifiers, "fic-password-quality",
                 "pam_pwquality.so", attachedError)) ||
            (historyActive && !verifyActiveAttachment(
                 historyAttachment, identifiers, "fic-password-history",
                 "pam_pwhistory.so", attachedError))) {
            verdict.detail = attachedError;
            error.clear();
            return true;
        }
        if ((!historyActive && historyAttachment.providerCount != 0) ||
            (externalPwqualityEffective && qualityAttachment.providerRulesFromSlot != 0)) {
            verdict.detail = "foreign history provider or inconsistent external quality source "
                "(fail closed; external history adoption is unsupported)";
            error.clear();
            return true;
        }
        if (historyActive && pwqualityCount == 0) {
            verdict.detail = "Rule G: history-only is unsupported: no quality token producer";
            error.clear();
            return true;
        }

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
            if (!analyzePasswordFlow(stack, platformConfig,
                                     {pwqualityCount == 1, historyActive},
                                     flow, flowError)) {
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
    }

    // Rule J: config-file mode has a single authoritative option source.
    if (historyActive && historyCapability->configurationMode ==
            fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile) {
        const auto& slotOptions = *historyOwnership.historyOptions;
        if (slotOptions.remember.has_value() || slotOptions.enforceForRoot) {
            verdict.detail = "ProviderConfigFile history slots contain option overrides "
                "instead of canonical no-option bodies (Rule J; fail closed)";
            error.clear();
            return true;
        }
        const auto state = readPwhistoryConfigState(historyCapability->configPath);
        if (state.broken) {
            verdict.detail = "pwhistory.conf is unreadable, non-regular, malformed or "
                "has duplicate managed keys (Rule J; fail closed)";
            error.clear();
            return true;
        } else if (state.remember == PwhistoryRememberState::Zero) {
            verdict.detail = "pwhistory.conf enforces remember=0 (Rule J; fail closed)";
            error.clear();
            return true;
        }
    }

    verdict.safeToAttach = true;
    verdict.detail = "FIC password slots are proven safe to attach";
    error.clear();
    return true;
}

} // namespace fic::identity::pam