#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"

#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "rollback/MutationRecord.h"

#include <optional>
#include <utility>
#include <variant>

namespace fic::identity::pam {
namespace {

using fic::rollback::MutationId;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoAction;
using fic::rollback::UndoOwnPamProviderContainer;
using fic::rollback::UndoRemovePamProviderManagedEntry;
using fic::rollback::PamProviderBlockPlacementContract;

constexpr const char* kIdentityModule = "IDENTITY_ACCESS";
constexpr const char* kEntrySubmodule = "PAM";
constexpr const char* kContainerSubmodule = "PAM_CONTAINER";

PolicyRef entryPolicyRef(const std::string& policyName) {
    return {kIdentityModule, kEntrySubmodule, policyName};
}

PolicyRef containerPolicyRef(const std::string& providerName) {
    return {kIdentityModule, kContainerSubmodule, providerName};
}

const UndoRemovePamProviderManagedEntry* entryPayload(
    const MutationRecord& record) {
    return std::get_if<UndoRemovePamProviderManagedEntry>(
        &record.undo.payload);
}

const UndoOwnPamProviderContainer* containerPayload(
    const MutationRecord& record) {
    return std::get_if<UndoOwnPamProviderContainer>(&record.undo.payload);
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

MutationRecord buildEntryRecord(const PamProviderManagedEntryRequest& request,
                                const std::string& previousBody) {
    MutationRecord record;
    record.policy = entryPolicyRef(request.policyName);
    record.resource = request.configPath.string();
    record.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoRemovePamProviderManagedEntry{
            request.policyName, request.providerName,
            request.configPath.string(), request.managedKey,
            pamProviderEntryBody(request.managedKey, request.nativeValue),
            previousBody, placementToContract(request.placement)}};
    return record;
}

MutationRecord buildContainerRecord(
    const PamProviderManagedEntryRequest& request) {
    MutationRecord record;
    record.policy = containerPolicyRef(request.providerName);
    record.resource = request.configPath.string();
    record.undo = UndoAction{
        fic::rollback::MutationBackend::Pam,
        UndoOwnPamProviderContainer{request.providerName,
                                    request.configPath.string()}};
    return record;
}

// Active journal record of the entry transaction for this policy. Returns
// nullopt when none exists; on any OTHER active entry payload for the same
// policy ref (different provider/config path) fails closed — the journal
// identity contract is strict.
std::optional<MutationRecord> findActiveEntryRecord(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    std::string& error) {
    for (const auto& record :
        journal.activeRecords(entryPolicyRef(request.policyName))) {
        const auto* payload = entryPayload(record);
        if (payload == nullptr) {
            continue; // other PAM payload kinds are unrelated here
        }
        const std::string configPath = request.configPath.string();
        if (payload->providerName != request.providerName ||
            payload->configPath != configPath ||
            record.resource != configPath) {
            error = "active journal record " +
                std::to_string(record.id) + " for policy " +
                request.policyName +
                " has a conflicting PAM provider entry identity: provider='" +
                payload->providerName + "' configPath='" +
                payload->configPath + "' (fail closed)";
            return std::nullopt;
        }
        return record;
    }
    return std::nullopt;
}

// Active durable container provenance for this provider config path.
std::optional<MutationRecord> findActiveContainerRecord(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    std::string& error) {
    std::optional<MutationRecord> found;
    for (const auto& record : journal.activeRecords(
             containerPolicyRef(request.providerName))) {
        const auto* payload = containerPayload(record);
        if (payload == nullptr ||
            payload->configPath != request.configPath.string()) {
            continue; // other config paths are independent containers
        }
        if (found.has_value()) {
            error = "multiple active container provenance records for " +
                request.configPath.string() + " (fail closed)";
            return std::nullopt;
        }
        found = record;
    }
    return found;
}

PamProviderOwnershipExpectation expectationFromRecord(
    const MutationRecord& record,
    const UndoRemovePamProviderManagedEntry& payload) {
    PamProviderOwnershipExpectation expectation;
    expectation.provider = payload.providerName;
    expectation.policy = payload.policyName;
    expectation.managedKey = payload.managedKey;
    expectation.body = payload.appliedBody;
    expectation.previousBody = payload.previousAppliedBody;
    expectation.mutationId = record.id;
    return expectation;
}

std::string bindingStateName(PamProviderJournalBindingState state) {
    switch (state) {
    case PamProviderJournalBindingState::PreparedFreshAbsent:
        return "PreparedFreshAbsent";
    case PamProviderJournalBindingState::PreparedFreshTargetPresent:
        return "PreparedFreshTargetPresent";
    case PamProviderJournalBindingState::PreparedUpdatePreviousPresent:
        return "PreparedUpdatePreviousPresent";
    case PamProviderJournalBindingState::PreparedUpdateTargetPresent:
        return "PreparedUpdateTargetPresent";
    case PamProviderJournalBindingState::PreparedConflict:
        return "PreparedConflict";
    case PamProviderJournalBindingState::AppliedExact:
        return "AppliedExact";
    case PamProviderJournalBindingState::AppliedMissing:
        return "AppliedMissing";
    case PamProviderJournalBindingState::AppliedDrifted:
        return "AppliedDrifted";
    }
    return "Unknown";
}

std::string entryProofName(PamProviderEntryProof proof) {
    switch (proof) {
    case PamProviderEntryProof::Owned:
        return "Owned";
    case PamProviderEntryProof::Absent:
        return "Absent";
    case PamProviderEntryProof::Lookalike:
        return "Lookalike";
    case PamProviderEntryProof::Drifted:
        return "Drifted";
    case PamProviderEntryProof::ForeignProvider:
        return "ForeignProvider";
    case PamProviderEntryProof::MalformedState:
        return "MalformedState";
    }
    return "Unknown";
}

// Physical managed-block mutation + snapshot-bound atomic install. A
// failure here always leaves the durable journal transaction recoverable
// (Prepared provenance is never discarded): the next apply resolves the
// state through the fresh-proof recovery matrix.
bool performPhysicalMutation(
    const PamProviderManagedEntryRequest& request,
    const std::string& currentContent, bool containerWasAbsent,
    const AtomicTargetState& snapshot, MutationId mutationId,
    std::string& newContent, std::string& error) {
    PamProviderEntrySpec spec;
    spec.provider = request.providerName;
    spec.policy = request.policyName;
    spec.managedKey = request.managedKey;
    spec.value = request.nativeValue;
    spec.mutationId = mutationId;
    auto mutation =
        setPamProviderManagedEntry(currentContent, spec, request.placement);
    if (!mutation.ok) {
        error = "managed entry mutation refused (fail closed): " +
            mutation.error;
        return false;
    }
    auto write = PamProviderManagedBlockFile::writeMutation(
        request.configPath, containerWasAbsent, snapshot, mutation.content,
        error);
    if (!write.ok) {
        error = "physical managed block write failed (durable journal "
                "transaction kept for recovery): " +
            error;
        return false;
    }
    newContent = mutation.content;
    return true;
}

// Fresh trusted re-read → strict parse → exact physical ownership of
// `body` under `mutationId` → placement postcondition. Entry ownership
// alone never proves PAM effectiveness — the semantic postcondition runs
// separately before every Applied transition.
bool proveEntryState(const PamProviderManagedEntryRequest& request,
                     const std::string& body, MutationId mutationId,
                     std::string& error) {
    auto read = PamProviderManagedBlockFile::readForMutation(
        request.configPath, PamProviderAbsentContainerDecision::FailClosed,
        error);
    if (!read.ok) {
        error = "fresh trusted re-read failed: " + error;
        return false;
    }
    auto parse = parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        error = "strict parse of the mutated container failed (fail " +
            std::string("closed): ") + parse.error;
        return false;
    }
    PamProviderOwnershipExpectation expectation;
    expectation.provider = request.providerName;
    expectation.policy = request.policyName;
    expectation.managedKey = request.managedKey;
    expectation.body = body;
    expectation.mutationId = mutationId;
    auto proof = provePamProviderEntryOwnership(parse, expectation);
    if (!proof.proven) {
        error = "physical ownership proof failed after mutation (" +
            entryProofName(proof.proof) + "): " + proof.error;
        return false;
    }
    if (!parse.view.satisfiesPlacement(request.placement)) {
        error =
            "managed block placement postcondition failed: block is not at "
            "the requested placement (fail closed)";
        return false;
    }
    return true;
}

// Container provenance lifecycle: a container WITHOUT an active provenance
// record never receives one here (FIC does not prove it created the file);
// a Prepared record is completed ONLY after the caller has proven exact
// FIC entry ownership inside the parsed provider block — never merely
// because the path exists.
bool reconcileContainerProvenance(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const std::optional<MutationRecord>& containerRecord,
    std::string& error) {
    if (!containerRecord.has_value() ||
        containerRecord->status == MutationStatus::Applied) {
        return true;
    }
    if (containerRecord->status != MutationStatus::Prepared) {
        error = "unexpected container provenance status for " +
            request.configPath.string() + " (fail closed)";
        return false;
    }
    if (!journal.setStatus(
            containerRecord->id, MutationStatus::Applied, error)) {
        error = "container provenance Applied transition failed (Prepared " +
            std::string("state kept, recoverable): ") + error;
        return false;
    }
    return true;
}

} // namespace

namespace {

// Fresh FIC-created container flow: entry transaction prepared first,
// container provenance Prepared BEFORE the physical create, exclusive
// create, proof chain, then entry Applied and container Applied.
bool applyFreshCreatedContainer(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const PamProviderManagedEntryExecutor::SemanticPostcondition& semantic,
    const std::optional<MutationRecord>& entryRecord,
    const std::optional<MutationRecord>& containerRecord,
    std::string& error) {
    const std::string desiredBody =
        pamProviderEntryBody(request.managedKey, request.nativeValue);
    MutationId entryId = 0;
    if (entryRecord.has_value()) {
        entryId = entryRecord->id; // recovery: SAME durable record id
    } else if (!journal.prepareMutation(
                   buildEntryRecord(request, ""), entryId, error)) {
        return false;
    }
    MutationId containerId = 0;
    if (containerRecord.has_value()) {
        containerId = containerRecord->id;
    } else if (!journal.prepareMutation(
                   buildContainerRecord(request), containerId, error)) {
        return false; // entry stays Prepared: deterministically recoverable
    }
    std::string newContent;
    if (!performPhysicalMutation(
            request, /*currentContent=*/"", /*containerWasAbsent=*/true,
            AtomicTargetState{}, entryId, newContent, error)) {
        return false;
    }
    if (!proveEntryState(request, desiredBody, entryId, error)) {
        return false;
    }
    if (!semantic(error)) {
        error = "semantic postcondition failed: " + error;
        return false;
    }
    if (!journal.setStatus(entryId, MutationStatus::Applied, error)) {
        error = "entry Applied transition failed after physical create " +
            std::string("(Prepared kept; crash recovery adopts the exact ") +
            "physical state): " + error;
        return false;
    }
    if (!journal.setStatus(containerId, MutationStatus::Applied, error)) {
        error = "container provenance Applied transition failed (Prepared " +
            std::string("kept; crash recovery reconciles against the ") +
            "proven FIC-created state): " + error;
        return false;
    }
    return true;
}

// Fresh entry transaction inside an EXISTING container (pre-existing
// foreign container, or a durably proven FIC-created one). No container
// provenance is created for a pre-existing file.
bool applyFreshEntryExistingContainer(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const PamProviderManagedEntryExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const std::optional<MutationRecord>& containerRecord,
    std::string& error) {
    MutationId entryId = 0;
    if (!journal.prepareMutation(
            buildEntryRecord(request, ""), entryId, error)) {
        return false;
    }
    std::string newContent;
    if (!performPhysicalMutation(request, read.content,
            /*containerWasAbsent=*/false, read.snapshot, entryId, newContent,
            error)) {
        return false;
    }
    const std::string desiredBody =
        pamProviderEntryBody(request.managedKey, request.nativeValue);
    if (!proveEntryState(request, desiredBody, entryId, error)) {
        return false;
    }
    if (!semantic(error)) {
        error = "semantic postcondition failed: " + error;
        return false;
    }
    if (!journal.setStatus(entryId, MutationStatus::Applied, error)) {
        error = "entry Applied transition failed after physical mutation " +
            std::string("(Prepared kept; crash recovery adopts the exact ") +
            "physical state): " + error;
        return false;
    }
    return reconcileContainerProvenance(
        journal, request, containerRecord, error);
}

// Proven-absent primary. Every durable state here has a defined,
// deterministic outcome; a typed FailClosed decision refuses creation
// BEFORE any journal transaction is prepared for a fresh apply.
bool applyAbsentContainer(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const PamProviderManagedEntryExecutor::SemanticPostcondition& semantic,
    const std::optional<MutationRecord>& entryRecord,
    const std::optional<MutationRecord>& containerRecord,
    std::string& error) {
    const std::string configPath = request.configPath.string();
    if (entryRecord.has_value()) {
        const auto* payload = entryPayload(*entryRecord);
        if (entryRecord->status == MutationStatus::Applied) {
            error = "AppliedMissing: journal provenance proves an existing " +
                std::string("FIC-owned artifact for ") + configPath +
                " but the container is absent — drift/externally released " +
                "state is never recreated automatically (fail closed)";
            return false;
        }
        if (entryRecord->status == MutationStatus::RollbackFailed) {
            error = "RollbackFailed record for " + configPath +
                " refers to an absent container — current FIC ownership " +
                "cannot be proven (fail closed)";
            return false;
        }
        // Prepared: the physical mutation has not happened yet. Only a
        // FRESH create (no previous body) on a container-creation flow can
        // continue; an update transition refers to a vanished container.
        if (!payload->previousAppliedBody.empty()) {
            error = "PreparedConflict: update transition for " + configPath +
                " refers to a vanished container (fail closed)";
            return false;
        }
        if (containerRecord.has_value() &&
            containerRecord->status == MutationStatus::Applied) {
            error = "Applied container provenance for " + configPath +
                " with an absent container — provenance loss/drift, never " +
                "recreated under old ownership (fail closed)";
            return false;
        }
        if (request.absentDecision ==
            PamProviderAbsentContainerDecision::FailClosed) {
            error = "durable Prepared entry transaction for absent " +
                configPath +
                " cannot be completed: absent-container decision is " +
                "FailClosed (fail closed; transaction stays recoverable)";
            return false;
        }
        return applyFreshCreatedContainer(
            journal, request, semantic, entryRecord, containerRecord, error);
    }
    if (containerRecord.has_value()) {
        error = "container provenance record for " + configPath +
            " exists without a matching active entry transaction " +
            "(inconsistent journal state, fail closed)";
        return false;
    }
    if (request.absentDecision ==
        PamProviderAbsentContainerDecision::FailClosed) {
        // Refuse BEFORE preparing any journal transaction: a missing
        // primary can activate vendor fallback semantics that FIC cannot
        // prove; no entry/container record must be fabricated.
        error = "primary PAM provider configuration is absent: " +
            configPath +
            "; absent-container decision is FailClosed — refusing to " +
            "create (no journal transaction prepared; creating an " +
            "explicit primary could hide vendor/native fallback state)";
        return false;
    }
    return applyFreshCreatedContainer(
        journal, request, semantic, entryRecord, containerRecord, error);
}

} // namespace

namespace {

// Applied / RollbackFailed record with a proven-or-refused physical state,
// plus the shared value-refresh path (previous = journal appliedBody,
// target = desired, SAME record id).
bool applyProvenOwnedOrFailedRecord(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const PamProviderManagedEntryExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const PamProviderBlockParseResult& parse,
    const MutationRecord& entryRecord,
    const std::optional<MutationRecord>& containerRecord,
    PamProviderManagedEntryOutcome& outcome, std::string& error) {
    const auto* payload = entryPayload(entryRecord);
    const MutationId id = entryRecord.id;
    const std::string desiredBody =
        pamProviderEntryBody(request.managedKey, request.nativeValue);

    if (entryRecord.status == MutationStatus::RollbackFailed) {
        // RollbackFailed is never ignored: prove the CURRENT physical
        // ownership first; anything else is fail closed.
        auto expectation = expectationFromRecord(entryRecord, *payload);
        auto proof = provePamProviderEntryOwnership(parse, expectation);
        if (!proof.proven) {
            error = "RollbackFailed record " + std::to_string(id) +
                " cannot be resolved: current physical ownership proof " +
                "failed (" + entryProofName(proof.proof) +
                ") — entry absent, drifted, lookalike or foreign; fail " +
                "closed";
            return false;
        }
        if (payload->appliedBody == desiredBody) {
            // The exact old FIC-owned target is still the desired state:
            // proven current FIC state, placement + semantic no-op. The
            // record keeps its RollbackFailed status (no fabricated
            // lifecycle transition).
            if (!parse.view.satisfiesPlacement(request.placement)) {
                std::string newContent;
                if (!performPhysicalMutation(request, read.content,
                        /*containerWasAbsent=*/false, read.snapshot, id,
                        newContent, error)) {
                    return false;
                }
                if (!proveEntryState(
                        request, payload->appliedBody, id, error)) {
                    return false;
                }
            }
            if (!semantic(error)) {
                error = "semantic postcondition failed: " + error;
                return false;
            }
            if (!reconcileContainerProvenance(
                    journal, request, containerRecord, error)) {
                return false;
            }
            outcome = PamProviderManagedEntryOutcome::AppliedNoOp;
            return true;
        }
        // Proven current FIC state + new desired value: legitimate refresh
        // (previous = old appliedBody) through the shared path below.
    } else {
        // Applied record.
        auto expectation = expectationFromRecord(entryRecord, *payload);
        auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Applied, parse, expectation);
        if (!binding.ok) {
            error = "journal binding classification failed: " + binding.error;
            return false;
        }
        switch (binding.state) {
        case PamProviderJournalBindingState::AppliedMissing:
            error = "AppliedMissing: journal record " + std::to_string(id) +
                " proves an existing FIC-owned entry that is absent from " +
                "the physical file — drift/externally released state is " +
                "never recreated automatically (fail closed)";
            return false;
        case PamProviderJournalBindingState::AppliedDrifted:
            error = "AppliedDrifted: physical entry does not match the " +
                std::string("journal ownership identity of record ") +
                std::to_string(id) +
                " — manual drift is never overwritten (fail closed)";
            return false;
        case PamProviderJournalBindingState::AppliedExact:
            break;
        default:
            error = "unexpected binding state " +
                bindingStateName(binding.state) +
                " for an Applied record (fail closed)";
            return false;
        }
        if (payload->appliedBody == desiredBody) {
            // Full no-op proof chain: journal Applied exact + physical
            // entry exact (same id) + provider exact. Placement and
            // semantic effectiveness are still required below.
            if (!parse.view.satisfiesPlacement(request.placement)) {
                // Displaced owned block: ownership is still valid, but
                // production apply canonically relocates the block to the
                // requested placement AFTER exact ownership proof; foreign
                // bytes survive byte-exact.
                std::string newContent;
                if (!performPhysicalMutation(request, read.content,
                        /*containerWasAbsent=*/false, read.snapshot, id,
                        newContent, error)) {
                    return false;
                }
                if (!proveEntryState(
                        request, payload->appliedBody, id, error)) {
                    return false;
                }
            }
            if (!semantic(error)) {
                error = "semantic postcondition failed: " + error;
                return false;
            }
            if (!reconcileContainerProvenance(
                    journal, request, containerRecord, error)) {
                return false;
            }
            outcome = PamProviderManagedEntryOutcome::AppliedNoOp;
            return true;
        }
    }

    // Value refresh: previous = journal appliedBody, target = desired,
    // SAME record id (legitimate transition for Applied and RollbackFailed
    // with proven current ownership; also reached after Prepared recovery
    // when the desired value changed during recovery).
    MutationId refreshedId = 0;
    if (!journal.prepareMutation(
            buildEntryRecord(request, payload->appliedBody), refreshedId,
            error)) {
        return false;
    }
    if (refreshedId != id) {
        error = "journal refresh unexpectedly produced record id " +
            std::to_string(refreshedId) + " instead of " +
            std::to_string(id) + " (fail closed)";
        return false;
    }
    std::string newContent;
    if (!performPhysicalMutation(request, read.content,
            /*containerWasAbsent=*/false, read.snapshot, id, newContent,
            error)) {
        return false;
    }
    if (!proveEntryState(request, desiredBody, id, error)) {
        return false;
    }
    if (!semantic(error)) {
        error = "semantic postcondition failed: " + error;
        return false;
    }
    if (!journal.setStatus(id, MutationStatus::Applied, error)) {
        error = "entry Applied transition failed after refresh (Prepared " +
            std::string("kept; crash recovery continues the ") +
            "previous→target transition or adopts the exact target): " +
            error;
        return false;
    }
    if (!reconcileContainerProvenance(
            journal, request, containerRecord, error)) {
        return false;
    }
    outcome = PamProviderManagedEntryOutcome::Applied;
    return true;
}

} // namespace

namespace {

// Active entry record (Prepared recovery / Applied / RollbackFailed) with
// an EXISTING physical container. The durable transaction is always
// honoured first; the desired value is then reconciled afterwards.
bool applyActiveEntryRecord(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const PamProviderManagedEntryExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const PamProviderBlockParseResult& parse,
    const MutationRecord& entryRecord,
    const std::optional<MutationRecord>& containerRecord,
    PamProviderManagedEntryOutcome& outcome, std::string& error) {
    const auto* payload = entryPayload(entryRecord);
    const MutationId id = entryRecord.id;
    const std::string desiredBody =
        pamProviderEntryBody(request.managedKey, request.nativeValue);
    if (contractToPlacement(payload->placement) != request.placement) {
        error = "placement contract of the active journal record " +
            std::to_string(id) + " does not match the request (fail closed)";
        return false;
    }

    if (entryRecord.status == MutationStatus::Prepared) {
        // Honour the durable transaction first, whatever the current
        // desired value is; the record keeps its id.
        auto expectation = expectationFromRecord(entryRecord, *payload);
        auto binding = classifyPamProviderJournalBinding(
            PamProviderJournalMutationStatus::Prepared, parse, expectation);
        if (!binding.ok) {
            error = "journal binding classification failed: " + binding.error;
            return false;
        }
        switch (binding.state) {
        case PamProviderJournalBindingState::PreparedConflict:
            error = "PreparedConflict for record " + std::to_string(id) +
                ": physical state matches neither the previous nor the " +
                "target FIC-owned body — never rewritten, never re-id'd " +
                "(fail closed)";
            return false;
        case PamProviderJournalBindingState::PreparedFreshAbsent:
            // The physical mutation has not happened yet: continue with
            // the SAME record id.
        case PamProviderJournalBindingState::PreparedUpdatePreviousPresent:
            // The exact previous FIC-owned body is still physically
            // present: continue the previous→target transition, SAME id.
        {
            std::string newContent;
            if (!performPhysicalMutation(request, read.content,
                    /*containerWasAbsent=*/false, read.snapshot, id,
                    newContent, error)) {
                return false;
            }
            break;
        }
        case PamProviderJournalBindingState::PreparedFreshTargetPresent:
        case PamProviderJournalBindingState::PreparedUpdateTargetPresent:
            // Crash after the physical write, before journal completion:
            // ADOPT the exact completed physical state — no rewrite.
            break;
        default:
            error = "unexpected binding state " +
                bindingStateName(binding.state) +
                " for a Prepared record (fail closed)";
            return false;
        }
        if (!proveEntryState(request, payload->appliedBody, id, error)) {
            return false;
        }
        if (!semantic(error)) {
            error = "semantic postcondition failed: " + error;
            return false;
        }
        if (!journal.setStatus(id, MutationStatus::Applied, error)) {
            error = "entry Applied transition failed after recovery " +
                std::string("(Prepared kept; the next apply adopts the ") +
                "exact physical state): " + error;
            return false;
        }
        if (!reconcileContainerProvenance(
                journal, request, containerRecord, error)) {
            return false;
        }
        outcome = PamProviderManagedEntryOutcome::Applied;
        if (payload->appliedBody == desiredBody) {
            return true;
        }
        // Desired value changed while the prepared transaction was being
        // recovered: recovery is complete (record Applied, physical
        // exact), so run the normal refresh path below in the same
        // logical transaction.
    }

    return applyProvenOwnedOrFailedRecord(journal, request, semantic, read,
        parse, entryRecord, containerRecord, outcome, error);
}

} // namespace

bool PamProviderManagedEntryExecutor::apply(
    const PamProviderManagedEntryRequest& request,
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
    if (!isValidPamProviderManagedKey(request.managedKey) ||
        !isValidPamProviderEntryValue(request.nativeValue)) {
        error = "invalid managed key/value for policy " + request.policyName +
            ": key='" + request.managedKey + "' value='" +
            request.nativeValue + "'";
        return false;
    }
    if (request.configPath.empty()) {
        error = "empty PAM provider config path (fail closed)";
        return false;
    }

    // 1. Journal inspect. Without a usable journal record/provenance for a
    // new managed transaction the path fails closed — a physical mutation
    // without journal provenance would destroy rollback ownership.
    auto entryRecord = findActiveEntryRecord(journal, request, error);
    if (!entryRecord.has_value() && !error.empty()) {
        return false;
    }
    auto containerRecord = findActiveContainerRecord(journal, request, error);
    if (!containerRecord.has_value() && !error.empty()) {
        return false;
    }

    // 2. Trusted container classification read. This is a READ only: the
    // ENOENT-vs-existing classification is obtained with the permissive
    // key, the typed absent-container decision is enforced below.
    auto read = PamProviderManagedBlockFile::readForMutation(
        request.configPath,
        PamProviderAbsentContainerDecision::CreateFicOwned, error);
    if (!read.ok) {
        error = "trusted container read failed: " + error;
        return false;
    }
    if (read.state == PamProviderContainerState::Absent) {
        if (!applyAbsentContainer(journal, request, semantic, entryRecord,
                containerRecord, error)) {
            return false;
        }
        // A completed absent-container flow is always a physical create.
        outcome = PamProviderManagedEntryOutcome::Applied;
        return true;
    }

    // 3. Strict parse of the existing container — fail closed on any
    // malformed reserved FIC marker or broken canonical structure.
    auto parse = parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        error = "strict parse of " + request.configPath.string() +
            " failed (fail closed): " + parse.error;
        return false;
    }
    // A Prepared container provenance with an existing file that carries
    // no provider FIC block is an ambiguous externally-created container:
    // never adopt, never mutate (fail closed).
    if (containerRecord.has_value() &&
        containerRecord->status == MutationStatus::Prepared &&
        (!parse.view.present ||
            parse.view.provider != request.providerName)) {
        error = "container provenance is Prepared but the existing file " +
            request.configPath.string() +
            " carries no '" + request.providerName +
            "' FIC block — ambiguous externally created container state " +
            "(fail closed)";
        return false;
    }
    if (!entryRecord.has_value()) {
        if (!applyFreshEntryExistingContainer(
                journal, request, semantic, read, containerRecord, error)) {
            return false;
        }
        // A completed fresh-entry flow is always a physical mutation.
        outcome = PamProviderManagedEntryOutcome::Applied;
        return true;
    }
    return applyActiveEntryRecord(journal, request, semantic, read, parse,
        *entryRecord, containerRecord, outcome, error);
}

bool usesPamProviderManagedEntry(
    const PamProviderDescriptor& provider,
    const fic::platform::PamCapabilityConfig& capability,
    const PamProviderPolicyBinding& binding,
    fic::platform::PamPolicyFeature feature) {
    if (provider.kind != fic::platform::PamProviderKind::PamFaillock) {
        return false;
    }
    if (capability.configurationMode !=
        fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile) {
        return false;
    }
    if (binding.syntax != PamNativeOptionSyntax::Assignment) {
        return false;
    }
    switch (feature) {
    case fic::platform::PamPolicyFeature::FailedAuthenticationAttempts:
    case fic::platform::PamPolicyFeature::FailedAuthenticationCountingPeriod:
    case fic::platform::PamPolicyFeature::FailedAuthenticationUnlockTime:
        return true;
    default:
        return false;
    }
}

PamProviderAbsentContainerDecision pamProviderAbsentContainerDecision(
    const PamProviderDescriptor& provider) {
    switch (provider.defaultConfigTopology.explicitConfig) {
    case fic::platform::PamExplicitConfigSemantics::ReplacesNativeTopology:
        // An explicit primary suppresses the vendor/native fallback
        // topology; FIC has no deterministic platform-level proof that a
        // missing primary is safe to replace → fail closed.
        return PamProviderAbsentContainerDecision::FailClosed;
    case fic::platform::PamExplicitConfigSemantics::Unsupported:
        // No explicit-primary contract for this provider topology.
        return PamProviderAbsentContainerDecision::FailClosed;
    }
    return PamProviderAbsentContainerDecision::FailClosed;
}

} // namespace fic::identity::pam
