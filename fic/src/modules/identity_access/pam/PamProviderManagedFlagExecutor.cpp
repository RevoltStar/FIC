#include "modules/identity_access/pam/PamProviderManagedFlagExecutor.h"

#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"
#include "rollback/MutationRecord.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace fic::identity::pam {
namespace {

using fic::rollback::MutationId;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoAction;
using fic::rollback::UndoOwnPamProviderContainer;
using fic::rollback::UndoRemovePamProviderManagedFlag;
using fic::rollback::PamProviderBlockPlacementContract;

constexpr const char* kFlagModule = "IDENTITY_ACCESS";
constexpr const char* kFlagSubmodule = "PAM";
constexpr const char* kContainerSubmodule = "PAM_CONTAINER";

PolicyRef flagPolicyRef(const std::string& policyName) {
    return {kFlagModule, kFlagSubmodule, policyName};
}

const UndoRemovePamProviderManagedFlag* flagPayload(
    const MutationRecord& record) {
    return std::get_if<UndoRemovePamProviderManagedFlag>(
        &record.undo.payload);
}

PamProviderBlockPlacementRequest contractToPlacement(
    PamProviderBlockPlacementContract contract) {
    return contract == PamProviderBlockPlacementContract::Beginning
        ? PamProviderBlockPlacementRequest::Beginning
        : PamProviderBlockPlacementRequest::End;
}

PamProviderBlockPlacementContract placementToContract(
    PamProviderBlockPlacementRequest request) {
    return request == PamProviderBlockPlacementRequest::Beginning
        ? PamProviderBlockPlacementContract::Beginning
        : PamProviderBlockPlacementContract::End;
}

PamProviderManagedEntryKind kindForState(bool enabled) {
    return enabled ? PamProviderManagedEntryKind::FlagEnabled
                   : PamProviderManagedEntryKind::FlagDisabled;
}

MutationRecord buildFlagRecord(
    const PamProviderManagedFlagRequest& request,
    bool targetEnabled,
    const std::optional<bool>& previousEnabled,
    std::vector<std::string> targetSuppressionIds,
    std::vector<std::string> previousSuppressionIds) {
    MutationRecord record;
    record.policy = flagPolicyRef(request.policyName);
    record.resource = request.configPath.string();
    record.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoRemovePamProviderManagedFlag{
            request.policyName, request.providerName,
            request.configPath.string(), request.managedKey,
            targetEnabled, previousEnabled,
            placementToContract(request.placement),
            std::move(targetSuppressionIds),
            std::move(previousSuppressionIds)}};
    return record;
}

// Forward declarations: the refresh/recovery phases reference each other.
struct FlagPhysicalInspection;
bool finishRefreshProvenAppliedFlag(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const FlagPhysicalInspection& inspection, const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload,
    PamProviderManagedEntryOutcome& outcome, std::string& error);
bool reconcileDesiredAfterRecovery(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload, std::string& error);
bool continuePreparedPreviousState(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const FlagPhysicalInspection& inspection, const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload,
    PamProviderManagedEntryOutcome& outcome, bool targetEntryPresent,
    bool previousEntryPresent, std::string& error);

std::string entryProofName(PamProviderEntryProof proof) {
    switch (proof) {
    case PamProviderEntryProof::Owned: return "Owned";
    case PamProviderEntryProof::Absent: return "Absent";
    case PamProviderEntryProof::Lookalike: return "Lookalike";
    case PamProviderEntryProof::Drifted: return "Drifted";
    case PamProviderEntryProof::ForeignProvider: return "ForeignProvider";
    case PamProviderEntryProof::MalformedState: return "MalformedState";
    }
    return "Unknown";
}

bool containsId(const std::vector<std::string>& ids,
                const std::string& value) {
    return std::find(ids.begin(), ids.end(), value) != ids.end();
}

// Same-id set equality independent of order.
bool sameIdSet(const std::vector<std::string>& left,
               const std::vector<std::string>& right) {
    if (left.size() != right.size()) {
        return false;
    }
    for (const std::string& id : left) {
        if (!containsId(right, id)) {
            return false;
        }
    }
    return true;
}

// Local physical-line splitter (mirrors the managed-block primitive: the
// final line may lack a newline; the terminator stays part of the line).
std::vector<std::string> splitPhysicalLines(const std::string& content) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < content.size()) {
        const std::size_t newline = content.find('\n', start);
        if (newline == std::string::npos) {
            lines.push_back(content.substr(start));
            return lines;
        }
        lines.push_back(content.substr(start, newline - start + 1));
        start = newline + 1;
    }
    return lines;
}

// Local marker scan of an already strict-validated content (unambiguous
// after a successful strict parse).
void findBlockSpan(const std::string& content, std::size_t& beginIndex,
                   std::size_t& endIndex) {
    beginIndex = std::string::npos;
    endIndex = std::string::npos;
    const std::vector<std::string> lines = splitPhysicalLines(content);
    for (std::size_t index = 0; index < lines.size(); ++index) {
        std::string line = lines[index];
        while (!line.empty() &&
               (line.back() == '\n' || line.back() == '\r' ||
                line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }
        if (line == kPamProviderBlockEndMarker) {
            endIndex = index;
        } else if (line.compare(
                       0, std::strlen(kPamProviderBlockBeginMarkerPrefix),
                       kPamProviderBlockBeginMarkerPrefix) == 0) {
            beginIndex = index;
        }
    }
}

const PamProviderManagedEntry* findFlagEntry(
    const std::vector<PamProviderManagedEntry>& entries,
    const std::string& policy, const std::string& managedKey) {
    for (const PamProviderManagedEntry& entry : entries) {
        if (entry.policy == policy && entry.managedKey == managedKey) {
            return &entry;
        }
    }
    return nullptr;
}

// Typed physical inspection of ONE provider primary against a set-only
// flag identity. Produced ONLY from a strict parse of a trusted read —
// never from a permissive regex scan (Step 7E §10). expectedMutationId
// refines the entry/wrapper mutation-id match (0 disables the refinement).
struct FlagPhysicalInspection {
    bool ok = false;
    PamProviderBlockParseResult parse;
    // The (policy, key) managed entry: present / kind / mutation-id match.
    bool entryPresent = false;
    bool entryMutationMatches = false;
    PamProviderManagedEntryKind entryKind =
        PamProviderManagedEntryKind::Assignment;
    std::uint64_t entryMutationId = 0;
    // Canonical wrappers of THIS record (provider/policy/key/mutation id),
    // in physical order.
    std::vector<std::string> ownedWrapperIds;
    // A wrapper of this provider+policy+key carrying ANOTHER mutation id —
    // unproven provenance conflict (Step 7E §41).
    bool foreignMutationWrapper = false;
    // Active unsuppressed occurrences of the managed key (outside the
    // block, outside wrappers; comments never count).
    std::size_t activeOccurrenceCount = 0;
    // All suppression ids present in the file (id generation namespace).
    std::vector<std::string> allSuppressionIds;
    std::string error;
};

FlagPhysicalInspection inspectFlagPhysicalState(
    const PamProviderManagedFlagRequest& request,
    MutationId expectedMutationId,
    const std::string& content) {
    FlagPhysicalInspection inspection;
    inspection.parse = parsePamProviderManagedBlock(content);
    if (!inspection.parse.ok) {
        inspection.error = inspection.parse.error;
        return inspection;
    }
    if (inspection.parse.view.present &&
        inspection.parse.view.provider != request.providerName) {
        inspection.error = "FIC PAM provider block принадлежит другому "
                           "provider: " +
            inspection.parse.view.provider;
        return inspection;
    }
    if (inspection.parse.view.present) {
        if (const PamProviderManagedEntry* entry =
                findFlagEntry(inspection.parse.view.entries, request.policyName,
                          request.managedKey)) {
            inspection.entryPresent = true;
            inspection.entryKind = entry->kind;
            inspection.entryMutationId = entry->mutationId;
            inspection.entryMutationMatches =
                expectedMutationId != 0 &&
                entry->mutationId == expectedMutationId;
        }
    }
    for (const PamProviderSuppressedLine& wrapper :
         inspection.parse.view.suppressions) {
        inspection.allSuppressionIds.push_back(wrapper.suppressionId);
        if (wrapper.provider == request.providerName &&
            wrapper.policy == request.policyName &&
            wrapper.managedKey == request.managedKey &&
            expectedMutationId != 0 &&
            wrapper.mutationId != expectedMutationId) {
            inspection.foreignMutationWrapper = true;
        }
        if (wrapper.provider == request.providerName &&
            wrapper.policy == request.policyName &&
            wrapper.managedKey == request.managedKey &&
            expectedMutationId != 0 &&
            wrapper.mutationId == expectedMutationId) {
            inspection.ownedWrapperIds.push_back(wrapper.suppressionId);
        }
    }
    // Active occurrences: lines outside the block span and outside any
    // canonical wrapper (the strict parser already validated every
    // wrapper's canonical form and embedded raw line).
    std::size_t beginIndex = std::string::npos;
    std::size_t endIndex = std::string::npos;
    findBlockSpan(content, beginIndex, endIndex);
    std::set<std::size_t> wrapperLines;
    for (const auto& wrapper : inspection.parse.view.suppressions) {
        wrapperLines.insert(wrapper.lineIndex);
    }
    const std::vector<std::string> lines = splitPhysicalLines(content);
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (beginIndex != std::string::npos && index >= beginIndex &&
            index <= endIndex) {
            continue;
        }
        if (wrapperLines.count(index) != 0) {
            continue;
        }
        std::string text = lines[index];
        if (!text.empty() && text.back() == '\n') {
            text.pop_back();
            if (!text.empty() && text.back() == '\r') {
                text.pop_back();
            }
        }
        if (pamProviderFlagLineIsActiveOccurrence(
                request.providerName, text, request.managedKey)) {
            ++inspection.activeOccurrenceCount;
        }
    }
    inspection.ok = true;
    return inspection;
}

// Physical flag transition (entry + wrappers in ONE content transform) +
// snapshot-bound atomic install. A failure leaves the durable journal
// transaction recoverable (Prepared provenance is never discarded).
bool performFlagTransition(
    const PamProviderManagedFlagRequest& request, bool targetEnabled,
    const std::vector<std::string>& keepSuppressionIds,
    const std::vector<std::string>& createSuppressionIds,
    const std::string& currentContent, const AtomicTargetState& snapshot,
    MutationId mutationId, bool& committed, std::string& error) {
    PamProviderFlagSpec spec;
    spec.provider = request.providerName;
    spec.policy = request.policyName;
    spec.managedKey = request.managedKey;
    spec.enabled = targetEnabled;
    spec.mutationId = mutationId;
    spec.keepSuppressionIds = keepSuppressionIds;
    spec.createSuppressionIds = createSuppressionIds;
    auto mutation = setPamProviderManagedFlagTransition(
        currentContent, spec, request.placement);
    if (!mutation.ok) {
        error = "managed flag transition refused (fail closed): " +
            mutation.error;
        return false;
    }
    if (mutation.outcome ==
        PamProviderFlagMutationResult::Outcome::NoOp) {
        committed = false;
        return true;
    }
    auto write = PamProviderManagedBlockFile::writeMutation(
        request.configPath, /*containerWasAbsent=*/false, snapshot,
        mutation.content, error);
    if (!write.ok) {
        error = "physical managed flag write failed (durable journal "
                "transaction kept for recovery): " +
            error;
        return false;
    }
    committed = true;
    return true;
}

// Fresh trusted re-read → strict parse → exact physical proof of the flag
// target (Step 7E §38): entry kind/body + mutation id + placement +
// wrapper provenance set + (disabled) zero active unsuppressed occurrences.
bool proveFlagTarget(
    const PamProviderManagedFlagRequest& request, bool expectedEnabled,
    MutationId mutationId,
    const std::vector<std::string>& expectedWrapperIds, std::string& error) {
    auto read = PamProviderManagedBlockFile::readForMutation(
        request.configPath, PamProviderAbsentContainerDecision::FailClosed,
        error);
    if (!read.ok) {
        error = "fresh trusted re-read failed: " + error;
        return false;
    }
    auto inspection = inspectFlagPhysicalState(
        request, static_cast<std::uint64_t>(mutationId), read.content);
    if (!inspection.ok) {
        error = "strict parse of the mutated container failed (fail "
                "closed): " +
            inspection.error;
        return false;
    }
    if (!inspection.entryPresent ||
        !inspection.entryMutationMatches ||
        inspection.entryKind != kindForState(expectedEnabled)) {
        error = "physical flag entry proof failed after mutation (" +
            std::string(inspection.entryPresent
                            ? "mutation id or body kind mismatch"
                            : entryProofName(
                                  PamProviderEntryProof::Absent)) +
            ") (fail closed)";
        return false;
    }
    if (!inspection.parse.view.satisfiesPlacement(request.placement)) {
        error = "managed block placement postcondition failed: block is "
                "not at the requested placement (fail closed)";
        return false;
    }
    if (expectedEnabled) {
        if (!inspection.ownedWrapperIds.empty()) {
            error = "enabled flag target must not own suppression "
                    "wrappers (fail closed)";
            return false;
        }
    } else {
        if (!sameIdSet(inspection.ownedWrapperIds, expectedWrapperIds)) {
            error = "disabled flag target wrapper provenance mismatch "
                    "(fail closed)";
            return false;
        }
        if (inspection.activeOccurrenceCount != 0) {
            error = "disabled flag target still has active unsuppressed "
                    "occurrences of the managed key (fail closed)";
            return false;
        }
    }
    return true;
}

// Active record of the flag transaction for this policy. Any OTHER active
// flag payload for the same policy ref (different provider/config path/
// managed key) fails closed — the journal identity contract is strict.
std::optional<MutationRecord> findActiveFlagRecord(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request, std::string& error) {
    for (const auto& record :
         journal.activeRecords(flagPolicyRef(request.policyName))) {
        const auto* payload = flagPayload(record);
        if (payload == nullptr) {
            continue; // other PAM payload kinds are unrelated here
        }
        const std::string configPath = request.configPath.string();
        if (payload->providerName != request.providerName ||
            payload->configPath != configPath ||
            payload->managedKey != request.managedKey ||
            record.resource != configPath) {
            error = "active journal record " +
                std::to_string(record.id) + " for policy " +
                request.policyName +
                " has a conflicting PAM provider flag identity: provider='" +
                payload->providerName + "' configPath='" +
                payload->configPath + "' key='" + payload->managedKey +
                "' (fail closed)";
            return std::nullopt;
        }
        return record;
    }
    return std::nullopt;
}

// Fresh flag transaction inside an EXISTING (pre-existing) primary.
bool applyFreshFlag(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const FlagPhysicalInspection& inspection, std::string& error) {
    // A physically present (policy, key) entry is never adopted by a fresh
    // transaction: with no journal provenance it is foreign or orphaned
    // state (ABA protection, Step 7E §67).
    if (inspection.entryPresent) {
        error = "FIC PAM entry (policy, key) уже существует с physical "
                "mutation id " +
            std::to_string(inspection.entryMutationId) +
            ": fresh flag transaction never adopts an unproven entry (fail "
            "closed)";
        return false;
    }
    // A canonical wrapper claiming THIS policy identity is unproven
    // provenance without an active record (wrong mutation id or no record).
    if (inspection.foreignMutationWrapper || !inspection.ownedWrapperIds.empty()) {
        error = "canonical FIC PAM suppression wrapper of this policy exists "
                "without a proven journal transaction (fail closed)";
        return false;
    }
    // Target suppression ids are generated BEFORE the journal prepare: the
    // durable payload must already carry the exact target provenance set
    // (Step 7E §30/§31).
    std::vector<std::string> createIds;
    if (!request.expectedEnabled) {
        std::vector<std::string> used = inspection.allSuppressionIds;
        for (std::size_t index = 0; index < inspection.activeOccurrenceCount;
             ++index) {
            const std::string id = nextPamProviderSuppressionId(used);
            used.push_back(id);
            createIds.push_back(id);
        }
    }
    MutationId flagId = 0;
    if (!journal.prepareMutation(
            buildFlagRecord(request, request.expectedEnabled,
                            /*previousEnabled=*/std::nullopt, createIds, {}),
            flagId, error)) {
        return false;
    }
    bool committed = false;
    if (!performFlagTransition(request, request.expectedEnabled, {},
            createIds, read.content, read.snapshot, flagId, committed,
            error)) {
        return false;
    }
    if (!proveFlagTarget(request, request.expectedEnabled, flagId,
                         createIds, error)) {
        return false;
    }
    if (!semantic(request.expectedEnabled, error)) {
        error = "semantic postcondition failed: " + error;
        return false;
    }
    if (!journal.setStatus(flagId, MutationStatus::Applied, error)) {
        error = "flag Applied transition failed after physical mutation " +
            std::string("(Prepared kept; crash recovery adopts the exact "
                        "physical state): ") +
            error;
        return false;
    }
    return true;
}

// Shared refresh path for a PROVEN Applied/RollbackFailed flag record:
// prepares the next same-id transition (previous = the currently owned
// state), performs the physical transition, proves it and completes the
// record as Applied. `read` MUST be a FRESH trusted read (never a stale
// snapshot captured before an earlier mutation of the same logical
// transaction).
bool refreshProvenAppliedFlag(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const FlagPhysicalInspection& inspection, const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload,
    PamProviderManagedEntryOutcome& outcome, std::string& error) {
    const MutationId id = record.id;
    // Ownership proof of the CURRENT physical state: the entry must carry
    // the record id and the payload-applied kind (drift is never silently
    // corrected, Step 7E §67), wrappers of this policy with a foreign
    // mutation id are a conflict (§41), and every physically present owned
    // wrapper must be permitted by the payload suppression set (§12).
    if (!inspection.entryPresent || !inspection.entryMutationMatches ||
        inspection.entryKind != kindForState(payload.appliedEnabled)) {
        error = "AppliedDrifted: journal record " + std::to_string(id) +
            " proves a " +
            (payload.appliedEnabled ? "enabled" : "disabled") +
            " flag state, but the physical entry does not match (never "
            "rewritten, never re-id'd — fail closed)";
        return false;
    }
    if (inspection.foreignMutationWrapper) {
        error = "canonical FIC PAM suppression wrapper of this policy "
                "carries a foreign mutation id (fail closed)";
        return false;
    }
    for (const std::string& ownedId : inspection.ownedWrapperIds) {
        if (!containsId(payload.suppressionIds, ownedId)) {
            error = "unknown FIC PAM suppression wrapper id '" + ownedId +
                "' for record " + std::to_string(id) +
                " (fail closed): wrapper provenance is never guessed";
            return false;
        }
    }
    if (payload.appliedEnabled && !payload.suppressionIds.empty()) {
        error = "journal record " + std::to_string(id) +
            " claims wrappers for an enabled flag state (corrupt "
            "provenance, fail closed)";
        return false;
    }

    const bool desired = request.expectedEnabled;
    if (payload.appliedEnabled == desired && desired) {
        // Enabled target, no wrappers permitted: exact state.
        outcome = PamProviderManagedEntryOutcome::AppliedNoOp;
        return true;
    }
    return finishRefreshProvenAppliedFlag(journal, request, semantic, read,
        inspection, record, payload, outcome, error);
}

// Continuation of refreshProvenAppliedFlag: the disabled-target cases and
// the true↔false state transitions (same record id).
bool finishRefreshProvenAppliedFlag(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const FlagPhysicalInspection& inspection, const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload,
    PamProviderManagedEntryOutcome& outcome, std::string& error) {
    const MutationId id = record.id;
    const bool desired = request.expectedEnabled;
    if (payload.appliedEnabled == desired && !desired) {
        // Disabled target.
        if (inspection.activeOccurrenceCount != 0) {
            // New foreign active occurrence(s) appeared while disabled:
            // wrap ONLY the new lines under NEW suppression ids; the
            // existing wrappers and their ids stay stable
            // (Step 7E §39/§72/§74). This is a false→false refresh.
            std::vector<std::string> createIds;
            // The id namespace spans the FILE and the JOURNAL: ids of
            // externally released wrappers stay reserved by the journal
            // provenance and are never reused (§11).
            std::vector<std::string> used = inspection.allSuppressionIds;
            used.insert(used.end(), payload.suppressionIds.begin(),
                payload.suppressionIds.end());
            for (std::size_t index = 0;
                 index < inspection.activeOccurrenceCount; ++index) {
                const std::string newId = nextPamProviderSuppressionId(used);
                used.push_back(newId);
                createIds.push_back(newId);
            }
            // The proven target set = the SURVIVING physically proven
            // wrappers ∪ the newly created ids. Externally released ids are
            // canonicalized OUT of the provenance (they stay only in the
            // previous set) and are never reconstructed from the journal.
            std::vector<std::string> targetIds = inspection.ownedWrapperIds;
            targetIds.insert(targetIds.end(), createIds.begin(),
                             createIds.end());
            MutationId refreshedId = 0;
            if (!journal.prepareMutation(
                    buildFlagRecord(request, /*targetEnabled=*/false,
                                    /*previousEnabled=*/false, targetIds,
                                    payload.suppressionIds),
                    refreshedId, error)) {
                return false;
            }
            if (refreshedId != id) {
                error = "journal refresh unexpectedly produced record id " +
                    std::to_string(refreshedId) + " instead of " +
                    std::to_string(id) + " (fail closed)";
                return false;
            }
            bool committed = false;
            if (!performFlagTransition(request, /*targetEnabled=*/false,
                    /*keep=*/inspection.ownedWrapperIds, createIds,
                    read.content, read.snapshot, id, committed, error)) {
                return false;
            }
            if (!proveFlagTarget(request, /*expectedEnabled=*/false, id,
                                 targetIds, error)) {
                return false;
            }
            if (!semantic(false, error)) {
                error = "semantic postcondition failed: " + error;
                return false;
            }
            if (!journal.setStatus(id, MutationStatus::Applied, error)) {
                error = "flag Applied transition failed after suppression "
                        "refresh (Prepared kept): " +
                    error;
                return false;
            }
            outcome = PamProviderManagedEntryOutcome::Applied;
            return true;
        }
        if (sameIdSet(inspection.ownedWrapperIds, payload.suppressionIds)) {
            outcome = PamProviderManagedEntryOutcome::AppliedNoOp;
            return true;
        }
        // Canonicalize the provenance to the current physically proven
        // subset: missing wrappers are externally released and are NEVER
        // reconstructed from the journal (it never stored them).
        MutationId refreshedId = 0;
        if (!journal.prepareMutation(
                buildFlagRecord(request, /*targetEnabled=*/false,
                                /*previousEnabled=*/false,
                                inspection.ownedWrapperIds,
                                payload.suppressionIds),
                refreshedId, error)) {
            return false;
        }
        if (refreshedId != id) {
            error = "journal refresh unexpectedly produced record id " +
                std::to_string(refreshedId) + " instead of " +
                std::to_string(id) + " (fail closed)";
            return false;
        }
        bool committed = false;
        if (!performFlagTransition(request, /*targetEnabled=*/false,
                inspection.ownedWrapperIds, {}, read.content, read.snapshot,
                id, committed, error)) {
            return false;
        }
        if (!proveFlagTarget(request, /*expectedEnabled=*/false, id,
                             inspection.ownedWrapperIds, error)) {
            return false;
        }
        if (!semantic(false, error)) {
            error = "semantic postcondition failed: " + error;
            return false;
        }
        if (!journal.setStatus(id, MutationStatus::Applied, error)) {
            error = "flag Applied transition failed after provenance "
                    "refresh (Prepared kept): " +
                error;
            return false;
        }
        outcome = PamProviderManagedEntryOutcome::Applied;
        return true;
    }

    // State transition (true→false or false→true) under the SAME record id.
    std::vector<std::string> targetIds;
    std::vector<std::string> createIds;
    if (!desired) {
        // The id namespace spans the FILE and the JOURNAL (§11): ids of
        // wrappers that no longer exist physically stay reserved by the
        // journal provenance and are never reused.
        std::vector<std::string> used = inspection.allSuppressionIds;
        used.insert(used.end(), payload.suppressionIds.begin(),
            payload.suppressionIds.end());
        for (std::size_t index = 0;
             index < inspection.activeOccurrenceCount; ++index) {
            const std::string newId = nextPamProviderSuppressionId(used);
            used.push_back(newId);
            createIds.push_back(newId);
        }
        targetIds = createIds;
    }
    MutationId refreshedId = 0;
    if (!journal.prepareMutation(
            buildFlagRecord(request, desired,
                            /*previousEnabled=*/payload.appliedEnabled,
                            targetIds, payload.suppressionIds),
            refreshedId, error)) {
        return false;
    }
    if (refreshedId != id) {
        error = "journal refresh unexpectedly produced record id " +
            std::to_string(refreshedId) + " instead of " +
            std::to_string(id) + " (fail closed)";
        return false;
    }
    // For a disabled target keep every currently proven wrapper; for an
    // enabled target release everything (keep is empty).
    bool committed = false;
    if (!performFlagTransition(request, desired,
            /*keep=*/desired ? std::vector<std::string>{}
                             : inspection.ownedWrapperIds,
            createIds, read.content, read.snapshot, id, committed, error)) {
        return false;
    }
    if (!proveFlagTarget(request, desired, id, targetIds, error)) {
        return false;
    }
    if (!semantic(desired, error)) {
        error = "semantic postcondition failed: " + error;
        return false;
    }
    if (!journal.setStatus(id, MutationStatus::Applied, error)) {
        error = "flag Applied transition failed after state transition " +
            std::string("(Prepared kept; crash recovery adopts the exact "
                        "physical state): ") +
            error;
        return false;
    }
    outcome = PamProviderManagedEntryOutcome::Applied;
    return true;
}

// Durable-target-first recovery of an unresolved Prepared flag transaction
// (Step 7E §44/§45): complete the DURABLE journal target (never the
// current desired value), mark Applied, and only then — when the current
// desired value differs — reconcile through a FRESH trusted re-read and
// the normal same-id refresh path.
bool recoverPreparedFlag(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const FlagPhysicalInspection& inspection, const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload,
    PamProviderManagedEntryOutcome& outcome, std::string& error) {
    const MutationId id = record.id;
    if (inspection.foreignMutationWrapper) {
        error = "canonical FIC PAM suppression wrapper of this policy "
                "carries a foreign mutation id (fail closed)";
        return false;
    }
    // Target-present proof: the exact durable target state (entry kind +
    // record id + wrapper set) is already physical (crash after the write).
    const bool targetEntryPresent =
        inspection.entryPresent && inspection.entryMutationMatches &&
        inspection.entryKind == kindForState(payload.appliedEnabled);
    const bool targetWrappersProven =
        payload.appliedEnabled
            ? inspection.ownedWrapperIds.empty()
            : sameIdSet(inspection.ownedWrapperIds, payload.suppressionIds);
    const bool previousEntryPresent =
        payload.previousAppliedEnabled.has_value() &&
        inspection.entryPresent && inspection.entryMutationMatches &&
        inspection.entryKind == kindForState(*payload.previousAppliedEnabled);
    if (targetEntryPresent && targetWrappersProven &&
        (payload.appliedEnabled || inspection.activeOccurrenceCount == 0)) {
        // Adopt: no second physical rewrite. Semantic proof of the DURABLE
        // target gates the Applied transition (Step 7E §46).
        if (!proveFlagTarget(request, payload.appliedEnabled, id,
                             payload.suppressionIds, error)) {
            return false;
        }
        if (!semantic(payload.appliedEnabled, error)) {
            error = "semantic postcondition failed for the durable "
                    "transaction target: " +
                error;
            return false;
        }
        if (!journal.setStatus(id, MutationStatus::Applied, error)) {
            error = "flag Applied transition failed after recovery ("
                    "Prepared kept): " +
                error;
            return false;
        }
        outcome = PamProviderManagedEntryOutcome::Applied;
        if (payload.appliedEnabled == request.expectedEnabled) {
            return true;
        }
        return reconcileDesiredAfterRecovery(journal, request, semantic,
            record, payload, error);
    }
    return continuePreparedPreviousState(journal, request, semantic, read,
        inspection, record, payload, outcome, targetEntryPresent,
        previousEntryPresent, error);
}

// Second phase of the recovery: the current desired value differs from the
// completed durable target. Mandatory order: fresh trusted read → strict
// parse → exact Applied ownership proof of the recovered target → only
// then the same-id refresh towards the current desired value.
bool reconcileDesiredAfterRecovery(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload, std::string& error) {
    auto freshRead = PamProviderManagedBlockFile::readForMutation(
        request.configPath, PamProviderAbsentContainerDecision::FailClosed,
        error);
    if (!freshRead.ok) {
        error = "fresh trusted re-read after the completed durable "
                "transition failed: " +
            error;
        return false;
    }
    auto freshInspection = inspectFlagPhysicalState(
        request, static_cast<std::uint64_t>(record.id), freshRead.content);
    if (!freshInspection.ok) {
        error = "strict parse after the completed durable transition "
                "failed (fail closed): " +
            freshInspection.error;
        return false;
    }
    PamProviderManagedEntryOutcome refreshedOutcome =
        PamProviderManagedEntryOutcome::Applied;
    return refreshProvenAppliedFlag(journal, request, semantic, freshRead,
        freshInspection, record, payload, refreshedOutcome, error);
}

// Third phase of the recovery: the physical state still carries the
// PREVIOUS durable state — continue the transition towards the DURABLE
// TARGET (same record id). Missing previous wrappers are externally
// released; unwrapped occurrences are wrapped with the unused payload
// target ids (the count must reproduce the durable transition exactly).
bool continuePreparedPreviousState(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedFlagRequest& request,
    const PamProviderManagedFlagExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const FlagPhysicalInspection& inspection, const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& payload,
    PamProviderManagedEntryOutcome& outcome, bool targetEntryPresent,
    bool previousEntryPresent, std::string& error) {
    const MutationId id = record.id;
    if (!previousEntryPresent) {
        error = "PreparedConflict for record " + std::to_string(id) +
            ": physical state matches neither the previous nor the target "
            "FIC-owned flag state" +
            (targetEntryPresent
                 ? " (the target entry exists but its wrapper provenance "
                   "or effective state does not match the durable target)"
                 : "") +
            " — never rewritten, never re-id'd (fail closed)";
        return false;
    }
    if (payload.appliedEnabled) {
        bool committed = false;
        if (!performFlagTransition(request, /*targetEnabled=*/true, {}, {},
                read.content, read.snapshot, id, committed, error)) {
            return false;
        }
    } else {
        std::vector<std::string> keep;
        std::vector<std::string> used = inspection.allSuppressionIds;
        for (const std::string& ownedId : inspection.ownedWrapperIds) {
            if (containsId(payload.previousSuppressionIds, ownedId) ||
                containsId(payload.suppressionIds, ownedId)) {
                keep.push_back(ownedId);
                used.erase(std::remove(used.begin(), used.end(), ownedId),
                    used.end());
            } else {
                error = "unknown FIC PAM suppression wrapper id '" +
                    ownedId + "' for record " + std::to_string(id) +
                    " (fail closed)";
                return false;
            }
        }
        std::vector<std::string> createIds;
        for (const std::string& targetId : payload.suppressionIds) {
            if (!containsId(keep, targetId)) {
                createIds.push_back(targetId);
            }
        }
        if (createIds.size() != inspection.activeOccurrenceCount) {
            error = "durable Prepared transition cannot be reproduced: new "
                    "suppression ids vs active occurrences mismatch (" +
                std::to_string(createIds.size()) + " vs " +
                std::to_string(inspection.activeOccurrenceCount) +
                ") (fail closed)";
            return false;
        }
        bool committed = false;
        if (!performFlagTransition(request, /*targetEnabled=*/false, keep,
                createIds, read.content, read.snapshot, id, committed,
                error)) {
            return false;
        }
    }
    if (!proveFlagTarget(request, payload.appliedEnabled, id,
                         payload.suppressionIds, error)) {
        return false;
    }
    if (!semantic(payload.appliedEnabled, error)) {
        error = "semantic postcondition failed for the durable transaction "
                "target: " +
            error;
        return false;
    }
    if (!journal.setStatus(id, MutationStatus::Applied, error)) {
        error = "flag Applied transition failed after recovery (Prepared "
                "kept): " +
            error;
        return false;
    }
    outcome = PamProviderManagedEntryOutcome::Applied;
    if (payload.appliedEnabled == request.expectedEnabled) {
        return true;
    }
    return reconcileDesiredAfterRecovery(journal, request, semantic, record,
        payload, error);
}

} // namespace

bool PamProviderManagedFlagExecutor::apply(
    const PamProviderManagedFlagRequest& request,
    fic::rollback::MutationJournal& journal,
    const SemanticPostcondition& semantic,
    PamProviderManagedEntryOutcome& outcome,
    std::string& error) {
    outcome = PamProviderManagedEntryOutcome::AppliedNoOp;

    // Request validation — fail closed before any journal/physical action.
    if (!isValidPamProviderIdentityToken(request.policyName) ||
        !isValidPamProviderIdentityToken(request.providerName)) {
        error = "invalid PAM provider identity token: policy='" +
            request.policyName + "' provider='" + request.providerName + "'";
        return false;
    }
    if (!isValidPamProviderManagedKey(request.managedKey)) {
        error = "invalid managed flag key for policy " + request.policyName +
            ": key='" + request.managedKey + "'";
        return false;
    }
    if (request.configPath.empty()) {
        error = "empty PAM provider config path (fail closed)";
        return false;
    }

    // 1. Journal inspect. The flag path never creates provenance-less
    // physical state and never adopts a conflicting active record.
    auto flagRecord = findActiveFlagRecord(journal, request, error);
    if (!flagRecord.has_value() && !error.empty()) {
        return false;
    }

    // Defensive: an active container provenance for this path cannot exist
    // on the Step 7E production routes (all target providers refuse absent
    // container creation); treat it as corrupt journal state.
    for (const auto& record : journal.activeRecords(
             PolicyRef{kFlagModule, kContainerSubmodule,
                       request.providerName})) {
        const auto* container =
            std::get_if<UndoOwnPamProviderContainer>(&record.undo.payload);
        if (container != nullptr &&
            container->configPath == request.configPath.string()) {
            error = "active own_pam_provider_container provenance for " +
                request.configPath.string() +
                " exists on the managed flag path (inconsistent journal "
                "state, fail closed)";
            return false;
        }
    }

    // 2. Trusted container classification read. Production Step 7E works
    // ONLY with a pre-existing primary (Step 7E §36): a proven ENOENT
    // fails closed BEFORE any journal mutation — no flag-triggered
    // container creation (Step 7F owns container release).
    auto read = PamProviderManagedBlockFile::readForMutation(
        request.configPath, PamProviderAbsentContainerDecision::FailClosed,
        error);
    if (!read.ok) {
        error = "trusted container read failed: " + error;
        return false;
    }

    // 3. Physical inspection (strict parse included).
    auto inspection = inspectFlagPhysicalState(
        request,
        flagRecord.has_value()
            ? static_cast<std::uint64_t>(flagRecord->id)
            : 0,
        read.content);
    if (!inspection.ok) {
        error = "strict parse of " + request.configPath.string() +
            " failed (fail closed): " + inspection.error;
        return false;
    }

    if (flagRecord.has_value()) {
        if (flagRecord->status == MutationStatus::Prepared) {
            return recoverPreparedFlag(journal, request, semantic, read,
                inspection, *flagRecord, *flagPayload(*flagRecord),
                outcome, error);
        }
        // Applied or RollbackFailed: the currently owned state must be
        // proven before any refresh; RollbackFailed is refreshed like the
        // assignment executor does (ownership first).
        return refreshProvenAppliedFlag(journal, request, semantic, read,
            inspection, *flagRecord, *flagPayload(*flagRecord), outcome,
            error);
    }
    return applyFreshFlag(journal, request, semantic, read, inspection,
        error);
}

} // namespace fic::identity::pam