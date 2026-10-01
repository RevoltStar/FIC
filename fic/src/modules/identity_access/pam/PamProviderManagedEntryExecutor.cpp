#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"
#include "modules/identity_access/pam/PamProviderManagedLock.h"

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

// Typed proof token for completing a Prepared container provenance record
// as Applied. It can only be produced by
// provePreparedContainerCreationWitness() from a PRE-EXISTING exact
// journal↔physical creation witness (proven BEFORE any physical mutation
// of the current apply), or by the exclusive-create fresh flow for the
// container it just created and proved. A Prepared → Applied container
// transition can therefore never be triggered without proof.
struct ProvenPamProviderContainerCreation {
    MutationId witnessEntryId = 0;
};

// Extracts the native value of the DURABLE JOURNAL TARGET
// (payload->appliedBody) through the shared canonical body parser — never
// by string surgery — and proves the journal invariant that the parsed key
// matches the payload's managed key.
bool durableTargetNativeValue(const UndoRemovePamProviderManagedEntry& payload,
    std::string& nativeValue, std::string& error) {
    std::string key;
    std::string value;
    if (!parseCanonicalPamProviderEntryBody(payload.appliedBody, key, value) ||
        key != payload.managedKey) {
        error = "journal record applied body '" + payload.appliedBody +
            "' is not a canonical body for the managed key '" +
            payload.managedKey + "' (fail closed)";
        return false;
    }
    nativeValue = value;
    return true;
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
    // The EXACT native value to write. Recovery callers MUST pass the
    // durable journal target (derived from payload->appliedBody), NEVER
    // request.nativeValue: an unresolved Prepared transaction is completed
    // towards its durable target first, whatever the current desired value
    // is.
    const std::string& nativeValueToWrite, const std::string& currentContent,
    bool containerWasAbsent, const AtomicTargetState& snapshot,
    MutationId mutationId, std::string& newContent, std::string& error) {
    PamProviderEntrySpec spec;
    spec.provider = request.providerName;
    spec.policy = request.policyName;
    spec.managedKey = request.managedKey;
    spec.value = nativeValueToWrite;
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
// a Prepared record is completed ONLY with a proven creation-witness token
// (pre-existing exact journal↔physical witness, or the exclusive create of
// the current operation) — never merely because the path exists, and never
// from an entry the current recovery/apply operation just created inside a
// pre-existing container.
bool completePreparedContainerProvenance(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const std::optional<MutationRecord>& containerRecord,
    const ProvenPamProviderContainerCreation* proven, std::string& error) {
    if (!containerRecord.has_value() ||
        containerRecord->status == MutationStatus::Applied) {
        return true;
    }
    if (containerRecord->status != MutationStatus::Prepared) {
        error = "unexpected container provenance status for " +
            request.configPath.string() + " (fail closed)";
        return false;
    }
    if (proven == nullptr) {
        error = "container provenance for " + request.configPath.string() +
            " is Prepared but no pre-existing creation witness was proven " +
            "(fail closed): a Prepared container must never be legalized " +
            "by an entry created by the current operation";
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

// Proves a PRE-EXISTING creation witness for a Prepared container
// provenance record on the CURRENT trusted parse (before ANY physical
// mutation of this apply). The witness binds a physical FIC entry to an
// active journal entry transaction of the same provider/config path —
// exact physical mutation id + exact canonical body through the Step 7A
// classifier/ownership proof. Marker or block presence alone is never
// proof.
//
// Accepted witness states (strict set):
//   * entry Applied  + AppliedExact physical ownership;
//   * entry Prepared + PreparedFreshTargetPresent / PreparedUpdateTargetPresent
//     (the physical creation already happened before the crash).
// NOT witnesses: PreparedFreshAbsent (no physical creation),
// PreparedUpdatePreviousPresent (target not written), PreparedConflict,
// AppliedMissing, AppliedDrifted, and RollbackFailed (ambiguous creation
// provenance — fail closed by preference of the stricter witness set).
bool provePreparedContainerCreationWitness(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedEntryRequest& request,
    const PamProviderBlockParseResult& parse,
    ProvenPamProviderContainerCreation& witness, std::string& error) {
    const std::string configPath = request.configPath.string();
    for (const auto& record : journal.records()) {
        if (!record.isActive()) {
            continue;
        }
        const auto* payload = entryPayload(record);
        if (payload == nullptr || payload->providerName != request.providerName ||
            payload->configPath != configPath) {
            continue; // unrelated record kind or another container
        }
        if (record.status == MutationStatus::Applied) {
            auto proof = provePamProviderEntryOwnership(
                parse, expectationFromRecord(record, *payload));
            if (proof.proven) {
                witness.witnessEntryId = record.id;
                return true;
            }
            continue; // drifted/missing entry of another policy: not a witness
        }
        if (record.status == MutationStatus::Prepared) {
            auto binding = classifyPamProviderJournalBinding(
                PamProviderJournalMutationStatus::Prepared, parse,
                expectationFromRecord(record, *payload));
            if (binding.ok &&
                (binding.state ==
                        PamProviderJournalBindingState::PreparedFreshTargetPresent ||
                    binding.state ==
                        PamProviderJournalBindingState::PreparedUpdateTargetPresent)) {
                witness.witnessEntryId = record.id;
                return true;
            }
            continue;
        }
        // RollbackFailed: never accepted as a creation witness (strict set).
    }
    error = "container provenance for " + configPath +
        " is Prepared but no pre-existing exact journal↔physical creation " +
        "witness exists (fail closed): no active entry transaction of this " +
        "provider proves an exact physical FIC entry, so FIC creation of " +
        "the container cannot be proven — no new entry may legalize it";
    return false;
}

// Shared value-refresh path for a PROVEN Applied/RollbackFailed journal
// record: prepares the next transition (previous = journal appliedBody,
// target = CURRENT desired value, SAME record id), performs the physical
// mutation, proves it and completes the record as Applied.
//
// `read` MUST be a FRESH trusted read of the current container state: a
// read/snapshot captured before an earlier physical mutation of the same
// logical transaction is stale, and using it for a second physical
// mutation would make both the snapshot CAS and the ownership proof
// unsound. After completing one durable transition, always re-read.
bool refreshProvenOwnedEntry(
    fic::rollback::MutationJournal& journal,
    const PamProviderManagedEntryRequest& request,
    const PamProviderManagedEntryExecutor::SemanticPostcondition& semantic,
    const PamProviderContainerReadResult& read,
    const MutationRecord& entryRecord,
    const std::optional<MutationRecord>& containerRecord,
    const ProvenPamProviderContainerCreation* containerWitness,
    PamProviderManagedEntryOutcome& outcome, std::string& error) {
    const auto* payload = entryPayload(entryRecord);
    const MutationId id = entryRecord.id;
    const std::string desiredBody =
        pamProviderEntryBody(request.managedKey, request.nativeValue);
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
    if (!performPhysicalMutation(request, request.nativeValue, read.content,
            /*containerWasAbsent=*/false, read.snapshot, id, newContent,
            error)) {
        return false;
    }
    if (!proveEntryState(request, desiredBody, id, error)) {
        return false;
    }
    if (!semantic(request.nativeValue, error)) {
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
    if (!completePreparedContainerProvenance(
            journal, request, containerRecord, containerWitness, error)) {
        return false;
    }
    outcome = PamProviderManagedEntryOutcome::Applied;
    return true;
}

// Fresh trusted re-read + strict parse + exact Applied ownership proof of
// the recovered journal target, AFTER a completed durable transition. This
// is the mandatory starting point for any subsequent desired-value refresh
// of the same logical transaction: the read/parse captured before the
// recovery mutation are stale and must never back a second physical
// mutation.
bool freshProveRecoveredAppliedState(
    const PamProviderManagedEntryRequest& request,
    const MutationRecord& entryRecord,
    PamProviderContainerReadResult& read, std::string& error) {
    const auto* payload = entryPayload(entryRecord);
    read = PamProviderManagedBlockFile::readForMutation(
        request.configPath, PamProviderAbsentContainerDecision::FailClosed,
        error);
    if (!read.ok) {
        error = "fresh trusted re-read after the completed durable "
                "transition failed: " +
            error;
        return false;
    }
    auto parse = parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        error = "strict parse after the completed durable transition failed " +
            std::string("(fail closed): ") + parse.error;
        return false;
    }
    auto proof = provePamProviderEntryOwnership(
        parse, expectationFromRecord(entryRecord, *payload));
    if (!proof.proven) {
        error = "exact Applied ownership proof after the completed durable " +
            std::string("transition failed (") + entryProofName(proof.proof) +
            "): the recovered physical state is not the proven journal " +
            "target (fail closed)";
        return false;
    }
    return true;
}

} // namespace

namespace {

// Fresh FIC-created container flow: entry transaction prepared first,
// container provenance Prepared BEFORE the physical create, exclusive
// create, proof chain, then entry Applied and container Applied.
// Recovery of an existing Prepared entry transaction completes the DURABLE
// journal target first (never the current desired value); a differing
// current desired value is reconciled afterwards through a fresh trusted
// re-read and a normal same-id refresh.
bool applyFreshCreatedContainer(
    fic::rollback::MutationJournal& journal, const PamProviderManagedEntryRequest& request,
    const PamProviderManagedEntryExecutor::SemanticPostcondition& semantic,
    const std::optional<MutationRecord>& entryRecord,
    const std::optional<MutationRecord>& containerRecord,
    std::string& error) {
    // The value this transaction physically writes: the DURABLE JOURNAL
    // TARGET of an existing Prepared record, or the current desired value
    // for a genuinely fresh transaction.
    std::string targetNative;
    if (entryRecord.has_value()) {
        const auto* payload = entryPayload(*entryRecord);
        if (payload == nullptr ||
            payload->providerName != request.providerName ||
            payload->configPath != request.configPath.string() ||
            payload->managedKey != request.managedKey ||
            contractToPlacement(payload->placement) != request.placement) {
            error = "existing Prepared entry transaction identity does not " +
                std::string("match the request (fail closed)");
            return false;
        }
        if (!durableTargetNativeValue(*payload, targetNative, error)) {
            return false;
        }
    } else {
        targetNative = request.nativeValue;
    }
    const std::string targetBody =
        pamProviderEntryBody(request.managedKey, targetNative);
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
            request, targetNative, /*currentContent=*/"",
            /*containerWasAbsent=*/true, AtomicTargetState{}, entryId,
            newContent, error)) {
        return false;
    }
    if (!proveEntryState(request, targetBody, entryId, error)) {
        return false;
    }
    if (!semantic(targetNative, error)) {
        error = "semantic postcondition failed: " + error;
        return false;
    }
    if (!journal.setStatus(entryId, MutationStatus::Applied, error)) {
        error = "entry Applied transition failed after physical create " +
            std::string("(Prepared kept; crash recovery adopts the exact ") +
            "physical state): " + error;
        return false;
    }
    // The EXCLUSIVE create performed by THIS operation (container was
    // proven absent, no concurrent object existed, FIC entry ownership is
    // proven above) is the creation proof for the container it just
    // created; the durable container Prepared record was committed before
    // the physical create and is transitioned to Applied here.
    if (!journal.setStatus(containerId, MutationStatus::Applied, error)) {
        error = "container provenance Applied transition failed (Prepared " +
            std::string("kept; crash recovery reconciles against the ") +
            "proven FIC-created state): " + error;
        return false;
    }
    const std::string desiredBody =
        pamProviderEntryBody(request.managedKey, request.nativeValue);
    if (desiredBody == targetBody) {
        return true;
    }
    // The current desired value changed while the durable fresh-create
    // transaction was being recovered: complete it, then reconcile the
    // desired value from a FRESH trusted read (the pre-mutation state does
    // not exist here — the file was just created; never reuse a stale
    // snapshot for a second mutation).
    //
    // The container provenance is ALREADY durably Applied (journal
    // transition above), so the refresh must not re-reconcile it. The
    // caller's `containerRecord` optional is stale pre-prepare state and
    // may be disengaged when THIS operation created the provenance —
    // never fabricate a local record from it; nullopt makes the refresh
    // tail a verified no-op for the container.
    PamProviderContainerReadResult freshRead;
    if (!freshProveRecoveredAppliedState(request, *entryRecord, freshRead,
            error)) {
        return false;
    }
    PamProviderManagedEntryOutcome refreshedOutcome =
        PamProviderManagedEntryOutcome::Applied;
    return refreshProvenOwnedEntry(journal, request, semantic, freshRead,
        *entryRecord, /*containerRecord=*/std::nullopt,
        /*containerWitness=*/nullptr, refreshedOutcome, error);
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
    if (!performPhysicalMutation(request, request.nativeValue, read.content,
            /*containerWasAbsent=*/false, read.snapshot, entryId, newContent,
            error)) {
        return false;
    }
    const std::string desiredBody =
        pamProviderEntryBody(request.managedKey, request.nativeValue);
    if (!proveEntryState(request, desiredBody, entryId, error)) {
        return false;
    }
    if (!semantic(request.nativeValue, error)) {
        error = "semantic postcondition failed: " + error;
        return false;
    }
    if (!journal.setStatus(entryId, MutationStatus::Applied, error)) {
        error = "entry Applied transition failed after physical mutation " +
            std::string("(Prepared kept; crash recovery adopts the exact ") +
            "physical state): " + error;
        return false;
    }
    // A Prepared container provenance was already proven and completed in
    // apply() BEFORE any physical mutation of this operation (it must never
    // be legalized by this newly created entry), so this is a no-op unless
    // the provenance is absent/Applied.
    return completePreparedContainerProvenance(
        journal, request, containerRecord, /*proven=*/nullptr, error);
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
    // Native value of the PROVEN journal body (payload->appliedBody); used
    // for relocation writes and no-op semantics — the state being proven
    // here is the journaled body, not an assumed one.
    std::string provenNative;
    if (!durableTargetNativeValue(*payload, provenNative, error)) {
        return false;
    }

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
                if (!performPhysicalMutation(request, provenNative,
                        read.content,
                        /*containerWasAbsent=*/false, read.snapshot, id,
                        newContent, error)) {
                    return false;
                }
                if (!proveEntryState(
                        request, payload->appliedBody, id, error)) {
                    return false;
                }
            }
            if (!semantic(provenNative, error)) {
                error = "semantic postcondition failed: " + error;
                return false;
            }
            if (!completePreparedContainerProvenance(
                    journal, request, containerRecord, /*proven=*/nullptr,
                    error)) {
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
                if (!performPhysicalMutation(request, provenNative,
                        read.content,
                        /*containerWasAbsent=*/false, read.snapshot, id,
                        newContent, error)) {
                    return false;
                }
                if (!proveEntryState(
                        request, payload->appliedBody, id, error)) {
                    return false;
                }
            }
            if (!semantic(provenNative, error)) {
                error = "semantic postcondition failed: " + error;
                return false;
            }
            if (!completePreparedContainerProvenance(
                    journal, request, containerRecord, /*proven=*/nullptr,
                    error)) {
                return false;
            }
            outcome = PamProviderManagedEntryOutcome::AppliedNoOp;
            return true;
        }
    }

    // Value refresh: previous = journal appliedBody, target = CURRENT
    // desired value, SAME record id (legitimate transition for Applied and
    // RollbackFailed with proven current ownership; also reached after
    // Prepared recovery when the desired value changed during recovery —
    // the caller MUST pass a FRESH trusted read in that case).
    return refreshProvenOwnedEntry(journal, request, semantic, read,
        entryRecord, containerRecord, /*containerWitness=*/nullptr, outcome,
        error);
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
        // DURABLE TARGET FIRST. An unresolved Prepared transaction is
        // completed towards ITS journal target (payload->appliedBody),
        // whatever the current desired value is; the record keeps its id.
        // The current desired value has no right to steer an unresolved
        // transaction — it is reconciled only AFTER the durable transition
        // is proven and journaled as Applied.
        std::string durableNative;
        if (!durableTargetNativeValue(*payload, durableNative, error)) {
            return false;
        }
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
            // the SAME record id, writing the DURABLE TARGET.
        case PamProviderJournalBindingState::PreparedUpdatePreviousPresent:
            // The exact previous FIC-owned body is still physically
            // present: continue the previous→target transition towards
            // the DURABLE TARGET, SAME id — never towards the current
            // desired value.
        {
            std::string newContent;
            if (!performPhysicalMutation(request, durableNative, read.content,
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
        if (!semantic(durableNative, error)) {
            error = "semantic postcondition failed for the durable "
                    "transaction target: " +
                error;
            return false;
        }
        if (!journal.setStatus(id, MutationStatus::Applied, error)) {
            error = "entry Applied transition failed after recovery " +
                std::string("(Prepared kept; the next apply adopts the ") +
                "exact physical state): " + error;
            return false;
        }
        // A Prepared container provenance was already proven and completed
        // in apply() BEFORE any physical mutation; this is a no-op
        // defense-in-depth check.
        if (!completePreparedContainerProvenance(
                journal, request, containerRecord, /*proven=*/nullptr,
                error)) {
            return false;
        }
        outcome = PamProviderManagedEntryOutcome::Applied;
        if (payload->appliedBody == desiredBody) {
            return true;
        }
        // Desired value changed while the prepared transaction was being
        // recovered. The durable transition is complete (record Applied,
        // physical exact target); the read/parse captured BEFORE the
        // recovery mutation are now STALE and must never back a second
        // physical mutation. Mandatory order: fresh trusted read → strict
        // parse → exact Applied ownership proof of the recovered target →
        // only then the refresh previous=recovered target → desired.
        PamProviderContainerReadResult freshRead;
        if (!freshProveRecoveredAppliedState(request, entryRecord, freshRead,
                error)) {
            return false;
        }
        auto freshParse = parsePamProviderManagedBlock(freshRead.content);
        if (!freshParse.ok) {
            error = "strict parse of the recovered container failed (fail " +
                std::string("closed): ") + freshParse.error;
            return false;
        }
        return applyProvenOwnedOrFailedRecord(journal, request, semantic,
            freshRead, freshParse, entryRecord, containerRecord, outcome,
            error);
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
    // Step 7F concurrency contract: the public apply API serializes through
    // the shared interprocess managed-provider mutation lock domain (the
    // same lock the runtime rollback and the package release Stage B use).
    PamProviderManagedLock::Handle providerMutationLock;
    std::string providerLockError;
    if (!PamProviderManagedLock::acquire(providerMutationLock,
                                         providerLockError)) {
        error = providerLockError;
        return false;
    }
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
    // Prepared container provenance with an existing file: the historical
    // creation MUST be proven from a PRE-EXISTING exact journal↔physical
    // witness BEFORE any physical mutation of this operation — a new entry
    // created by this apply is never acceptable evidence of a previous
    // container creation (circular ownership proof). Fail closed when no
    // witness exists; reconcile (Prepared → Applied) immediately so the
    // current policy processing can never become the legalization
    // evidence.
    if (containerRecord.has_value() &&
        containerRecord->status == MutationStatus::Prepared) {
        ProvenPamProviderContainerCreation witness;
        if (!provePreparedContainerCreationWitness(
                journal, request, parse, witness, error)) {
            return false;
        }
        if (!completePreparedContainerProvenance(
                journal, request, containerRecord, &witness, error)) {
            return false;
        }
        containerRecord->status = MutationStatus::Applied;
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
    // SINGLE source of truth: the routed set is exactly the set for which
    // the total placement helper returns a placement contract. This
    // wrapper deliberately adds NO routing conditions of its own — the
    // configuration-mode, binding-syntax, provider, feature and topology
    // gates ALL live in pamProviderManagedEntryPlacement() below, so the
    // routing and placement contracts cannot drift apart (the Step 7C
    // default-End footgun is eliminated).
    return pamProviderManagedEntryPlacement(provider, capability, binding,
        feature)
        .has_value();
}

// Typed placement contract of the managed provider block — the COMPLETE
// single-source-of-truth routing+placement contract of the managed entry
// path. Every routing dimension (configuration mode, binding syntax,
// provider kind, feature, pwhistory topology) is evaluated HERE; an
// unroutable combination has NO placement (nullopt), never a silent End.
std::optional<PamProviderBlockPlacementRequest>
pamProviderManagedEntryPlacement(
    const PamProviderDescriptor& provider,
    const fic::platform::PamCapabilityConfig& capability,
    const PamProviderPolicyBinding& binding,
    fic::platform::PamPolicyFeature feature) {
    // Routing gate 1: the managed entry path physically mutates the shared
    // provider primary configuration; module-arguments capabilities (e.g.
    // Debian 12 pwhistory, Step 6 coordinator) have no provider config
    // file to mutate.
    if (capability.configurationMode !=
        fic::platform::PamCapabilityConfigurationMode::ProviderConfigFile) {
        return std::nullopt;
    }
    // Routing gate 2: Flag bindings route ONLY through the Step 7E
    // set-only flag whitelist (per provider + feature + topology); the
    // Assignment whitelist below is untouched (Step 7B/7C/7D matrix).
    // Any other syntax is unroutable.
    if (binding.syntax == PamNativeOptionSyntax::Flag) {
        switch (provider.kind) {
        case fic::platform::PamProviderKind::PamFaillock:
            // even_deny_root — journal-backed managed flag ownership, no
            // topology restriction beyond the ProviderConfigFile gate
            // (ALT ProviderConfigFile topology included).
            if (feature == fic::platform::PamPolicyFeature::
                               FailedAuthenticationEnforceForRoot) {
                return PamProviderBlockPlacementRequest::End;
            }
            return std::nullopt;
        case fic::platform::PamProviderKind::PamPwquality:
            // enforce_for_root — primary EOF; drop-ins stay READ-ONLY
            // evaluation inputs (Step 7C invariant).
            if (feature == fic::platform::PamPolicyFeature::
                               PasswordQualityEnforceForRoot) {
                return PamProviderBlockPlacementRequest::End;
            }
            return std::nullopt;
        case fic::platform::PamProviderKind::PamPwhistory:
            // enforce_for_root — same shared provider block, BOF (the FIC
            // bare flag must be the FIRST matching key under the upstream
            // first-match semantics). ALT p11 (AltTcbManaged) and Debian 12
            // (ModuleArguments, excluded by gate 1) stay outside.
            if (feature == fic::platform::PamPolicyFeature::
                               PasswordHistoryEnforceForRoot &&
                capability.topology ==
                    fic::platform::PamTopologyStrategyKind::PamAuthUpdate) {
                return PamProviderBlockPlacementRequest::Beginning;
            }
            return std::nullopt;
        default:
            // pam_passwdqc (Assignment binding "enforce") and all other
            // providers stay legacy.
            return std::nullopt;
        }
    }
    if (binding.syntax != PamNativeOptionSyntax::Assignment) {
        return std::nullopt;
    }
    switch (provider.kind) {
    case fic::platform::PamProviderKind::PamFaillock:
        switch (feature) {
        case fic::platform::PamPolicyFeature::FailedAuthenticationAttempts:
        case fic::platform::PamPolicyFeature::
                FailedAuthenticationCountingPeriod:
        case fic::platform::PamPolicyFeature::
                FailedAuthenticationUnlockTime:
            // faillock.conf scalar assignments have last-wins sequential
            // semantics → EOF.
            return PamProviderBlockPlacementRequest::End;
        default:
            return std::nullopt;
        }
    case fic::platform::PamProviderKind::PamPwquality:
        switch (feature) {
        case fic::platform::PamPolicyFeature::PasswordMinLength:
        case fic::platform::PamPolicyFeature::PasswordMinClasses:
        case fic::platform::PamPolicyFeature::PasswordCheckUsername:
        case fic::platform::PamPolicyFeature::PasswordCheckGecos:
        case fic::platform::PamPolicyFeature::PasswordMinChangedCharacters:
        case fic::platform::PamPolicyFeature::PasswordMinLowercase:
        case fic::platform::PamPolicyFeature::PasswordMinUppercase:
        case fic::platform::PamPolicyFeature::PasswordMinDigits:
        case fic::platform::PamPolicyFeature::PasswordMinOther:
            // PwqualityConfigEvaluator models DropInsThenPrimary: the
            // lexically sorted pwquality.conf.d/*.conf drop-ins are
            // applied first, then the primary is parsed sequentially. A
            // managed assignment at EOF of the primary therefore outranks
            // every drop-in and every earlier primary assignment. PAM
            // module argv is applied AFTER the config topology and cannot
            // be outranked — conflicting module arguments remain a
            // fail-closed semantic verifier concern, never a physical
            // mutation target.
            return PamProviderBlockPlacementRequest::End;
        default:
            return std::nullopt;
        }
    case fic::platform::PamProviderKind::PamPwhistory:
        // Step 7D: ONLY the current Debian 13 / Ubuntu 24.04 / Ubuntu
        // 26.04-style contract — ProviderConfigFile + PamAuthUpdate. The
        // typed topology contract (never a distro name) keeps ALT p11
        // (AltTcbManaged → /etc/security/fic-pwhistory.conf legacy
        // ownership) outside this route; ModuleArguments mode is already
        // excluded by routing gate 1 above (Debian 12 stays on the Step 6
        // joint coordinator). Upstream pam_modutil_search_key returns the
        // FIRST case-insensitive matching key, so the managed remember
        // entry MUST sit at the beginning of pwhistory.conf to outrank
        // later foreign assignments.
        if (feature ==
                fic::platform::PamPolicyFeature::PasswordHistoryDepth &&
            capability.topology ==
                fic::platform::PamTopologyStrategyKind::PamAuthUpdate) {
            return PamProviderBlockPlacementRequest::Beginning;
        }
        return std::nullopt;
    default:
        // pam_passwdqc (ALT password-quality topology),
        // tally/tally2/cracklib/pam_unix remember stay legacy.
        return std::nullopt;
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

// ---------------------------------------------------------------------------
// Step 7F: public container creation-witness proof for the rollback and
// package-release layer. Pure delegation to the strict Step 7B witness
// contract — no weaker legalization path exists.
// ---------------------------------------------------------------------------
bool provePamProviderPreparedContainerWitness(
    fic::rollback::MutationJournal& journal,
    const std::string& providerName,
    const std::filesystem::path& configPath,
    const PamProviderBlockParseResult& parse,
    std::string& error) {
    PamProviderManagedEntryRequest request;
    request.providerName = providerName;
    request.configPath = configPath;
    ProvenPamProviderContainerCreation witness;
    return provePreparedContainerCreationWitness(
        journal, request, parse, witness, error);
}

} // namespace fic::identity::pam
