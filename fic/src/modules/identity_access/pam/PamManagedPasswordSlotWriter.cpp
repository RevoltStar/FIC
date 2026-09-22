#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"

#include "modules/identity_access/pam/PamConfigFileTransaction.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <utility>

namespace fic::identity::pam {

PamManagedPasswordSlotWriter::PamManagedPasswordSlotWriter(
    std::filesystem::path configDirectory,
    fic::rollback::MutationJournal& journal,
    PolicyRef policyRef,
    PamManagedPasswordDomain domain)
    : configDirectory_(std::move(configDirectory)),
      journal_(journal),
      policyRef_(std::move(policyRef)),
      domain_(domain) {}

void PamManagedPasswordSlotWriter::setBeforeSlotWriteHookForTests(
    SlotFaultHook hook) {
    beforeWriteHook_ = std::move(hook);
}

void PamManagedPasswordSlotWriter::setAfterSlotWriteHookForTests(
    SlotFaultHook hook) {
    afterWriteHook_ = std::move(hook);
}

std::vector<const ManagedPasswordSlotSpec*>
PamManagedPasswordSlotWriter::domainSlots() const {
    switch (domain_) {
    case PamManagedPasswordDomain::Quality:
        return {&PamManagedPasswordSlots::qualitySlot()};
    case PamManagedPasswordDomain::History:
        return {&PamManagedPasswordSlots::historyNormalSlot(),
                &PamManagedPasswordSlots::historyInitialSlot()};
    }
    return {};
}

fic::rollback::UndoDisablePamCapability
PamManagedPasswordSlotWriter::expectedUndo() const {
    fic::rollback::UndoDisablePamCapability undo;
    undo.capability = policyRef_.policyName;
    undo.topology = fic::rollback::PamTopologyKind::PamAuthUpdate;
    for (const ManagedPasswordSlotSpec* spec : domainSlots()) {
        undo.activationIdentifiers.push_back(spec->fileName);
    }
    return undo;
}

bool PamManagedPasswordSlotWriter::journalMetadataMatches(
    const fic::rollback::MutationRecord& record, std::string& error) const {
    if (record.policy != policyRef_) {
        error = "journal record belongs to another policy";
        return false;
    }
    if (record.undo.backend != fic::rollback::MutationBackend::Pam) {
        error = "journal record does not use the PAM backend";
        return false;
    }
    if (record.resource != "capability/" + policyRef_.policyName) {
        error = "journal record carries a foreign resource";
        return false;
    }
    const auto* payload = std::get_if<fic::rollback::UndoDisablePamCapability>(
        &record.undo.payload);
    if (payload == nullptr) {
        error = "journal record carries a foreign undo payload";
        return false;
    }
    const fic::rollback::UndoDisablePamCapability expected = expectedUndo();
    if (payload->capability != expected.capability ||
        payload->topology != expected.topology ||
        payload->activationIdentifiers != expected.activationIdentifiers) {
        error =
            "journal record does not match this managed password domain";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::ensureJournalOperational(
    std::string& error) {
    if (journal_.usable()) {
        error.clear();
        return true;
    }
    if (!journal_.initializeOrLoad(error)) {
        error = "managed password journal is not operational: " + error;
        return false;
    }
    if (!journal_.usable()) {
        error = "managed password journal failed its operational gate";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::ensureJournalReadable(
    std::string& error) const {
    if (journal_.usable()) {
        error.clear();
        return true;
    }
    // Read-only persistent-state validation: the same witness-aware state
    // table as the operational lifecycle, but strictly without any
    // filesystem mutation (no bootstrap, no witness creation, no repair).
    if (!journal_.validatePersistentStateReadOnly(error)) {
        error = "managed password journal persistent state is not proven "
                "(fail closed): " +
            error;
        return false;
    }
    if (!journal_.usable()) {
        error = "managed password journal is not readable after validation";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::collectActiveRecord(
    bool& found, fic::rollback::MutationRecord& record, std::string& error) {
    found = false;
    if (!ensureJournalOperational(error)) {
        return false;
    }
    const std::vector<fic::rollback::MutationRecord> active =
        journal_.activeRecords(policyRef_);
    if (active.empty()) {
        error.clear();
        return true;
    }
    if (active.size() > 1) {
        error = "multiple active managed password journal records "
                "(fail closed)";
        return false;
    }
    if (!journalMetadataMatches(active.front(), error)) {
        error = "active managed password provenance does not match this "
                "domain (fail closed): " +
            error;
        return false;
    }
    if (active.front().status ==
        fic::rollback::MutationStatus::RollbackFailed) {
        error = "managed password rollback previously failed; active "
                "provenance requires rollback recovery before activation "
                "(fail closed)";
        return false;
    }
    found = true;
    record = active.front();
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::findBoundRecord(
    std::uint64_t id, PasswordSlotJournalBinding& binding,
    fic::rollback::MutationRecord& record, std::string& error) const {
    binding = PasswordSlotJournalBinding::Unbound;
    record = {};
    if (id == 0) {
        error = "physical marker carries no mutation id";
        return false;
    }
    for (const fic::rollback::MutationRecord& candidate :
         journal_.records()) {
        if (candidate.id != id) {
            continue;
        }
        std::string metadataError;
        if (!journalMetadataMatches(candidate, metadataError)) {
            error = "physical marker id " + std::to_string(id) +
                " belongs to a foreign journal record: " + metadataError;
            return false;
        }
        if (candidate.status == fic::rollback::MutationStatus::Applied) {
            binding = PasswordSlotJournalBinding::MatchingApplied;
        } else if (candidate.status ==
                   fic::rollback::MutationStatus::Prepared) {
            binding = PasswordSlotJournalBinding::MatchingPrepared;
        } else {
            error = "physical marker id " + std::to_string(id) +
                " matches a journal record with status " +
                fic::rollback::mutationStatusToString(candidate.status) +
                "; ownership is not proven";
            return false;
        }
        record = candidate;
        error.clear();
        return true;
    }
    error = "physical marker id " + std::to_string(id) +
        " has no matching journal record";
    return false;
}

bool PamManagedPasswordSlotWriter::prepareRecord(
    fic::rollback::MutationId& id, std::string& error) {
    fic::rollback::MutationRecord record;
    record.policy = policyRef_;
    record.resource = "capability/" + policyRef_.policyName;
    record.undo = {fic::rollback::MutationBackend::Pam, expectedUndo()};
    if (!journal_.prepareMutation(record, id, error)) {
        error = "managed password journal prepare failed: " + error;
        return false;
    }
    if (id == 0) {
        error = "managed password journal issued a zero mutation id";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::discardPrepared(
    fic::rollback::MutationId id, std::string& error) {
    if (!journal_.discard(id, error)) {
        error = "managed password journal discard failed: " + error;
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::completePrepared(
    fic::rollback::MutationId id, std::string& error) {
    if (!journal_.setStatus(
            id, fic::rollback::MutationStatus::Applied, error)) {
        error = "managed password journal commit failed: " + error;
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::captureSlot(
    const ManagedPasswordSlotSpec& spec, PamConfigFileSnapshot& snapshot,
    std::string& error) const {
    return PamConfigFileTransaction::capture(
        PamManagedPasswordSlots::slotFilePath(spec, configDirectory_),
        snapshot, error);
}

bool PamManagedPasswordSlotWriter::inspectSnapshot(
    const ManagedPasswordSlotSpec& spec,
    const PamConfigFileSnapshot& snapshot,
    ManagedPasswordSlotInspection& inspection, std::string& error) {
    const std::optional<std::string> content =
        snapshot.existed ? std::optional<std::string>(snapshot.content)
                         : std::nullopt;
    return PamManagedPasswordSlots::inspectContent(
        spec, content, inspection, error);
}

bool PamManagedPasswordSlotWriter::freshInspection(
    const ManagedPasswordSlotSpec& spec,
    ManagedPasswordSlotInspection& inspection, std::string& error) const {
    PamConfigFileSnapshot snapshot;
    if (!captureSlot(spec, snapshot, error)) {
        return false;
    }
    return inspectSnapshot(spec, snapshot, inspection, error);
}

bool PamManagedPasswordSlotWriter::proveSlotDurable(
    const PamConfigFileSnapshot& snapshot, std::string& error) {
    if (!snapshot.existed) {
        error = "cannot prove durability of a missing slot";
        return false;
    }
    AtomicTargetState state;
    state.identity = AtomicTargetIdentity{snapshot.device, snapshot.inode};
    state.content = snapshot.content;
    state.mode = snapshot.mode;
    state.owner = snapshot.owner;
    state.group = snapshot.group;
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            snapshot.path.string(), state, &error)) {
        error = "managed password slot durability proof failed: " + error;
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::writeSlot(
    const ManagedPasswordSlotSpec& spec, PamConfigFileSnapshot& snapshot,
    const std::string& content, std::size_t slotIndex, bool useHooks,
    std::string& error) {
    if (useHooks && beforeWriteHook_ && !beforeWriteHook_(slotIndex)) {
        error = "injected failure before managed password slot write: " +
            std::string(spec.fileName);
        return false;
    }
    if (!PamConfigFileTransaction::mutate(
            snapshot,
            [&](const PamConfigFileTransaction::Writer& writer,
                std::string& mutationError) {
                AtomicWriteOptions options;
                options.createIfMissing = false;
                options.rejectSymlink = true;
                options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
                return writer(
                    snapshot.path.string(), content, options,
                    &mutationError);
            },
            error)) {
        return false;
    }
    if (useHooks && afterWriteHook_ && !afterWriteHook_(slotIndex)) {
        error = "injected failure after managed password slot write: " +
            std::string(spec.fileName);
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::compensateSnapshots(
    std::vector<PamConfigFileSnapshot>& snapshots,
    std::size_t attemptedCount, std::string& error) {
    // Rollback every attempted slot in reverse order. mutate() may return
    // false after the atomic rename was installed while still marking the
    // snapshot committed, so the failing snapshot is always included;
    // rollback() is a no-op for a snapshot that never committed.
    std::string rollbackError;
    for (std::size_t index = attemptedCount; index > 0; --index) {
        std::string oneError;
        if (!PamConfigFileTransaction::rollback(
                snapshots[index - 1], oneError)) {
            if (!rollbackError.empty()) {
                rollbackError += "; ";
            }
            rollbackError += oneError;
        }
    }
    if (!rollbackError.empty()) {
        error = "CRITICAL: managed password slot rollback failed: " +
            rollbackError;
        return false;
    }
    error.clear();
    return true;
}

void PamManagedPasswordSlotWriter::compensateFreshFailure(
    std::vector<PamConfigFileSnapshot>& snapshots,
    std::size_t attemptedCount, fic::rollback::MutationId id,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    std::string rollbackError;
    const bool restored =
        compensateSnapshots(snapshots, attemptedCount, rollbackError);
    if (!restored) {
        // The physical mutation happened and could not be compensated.
        // The Prepared record stays for the existing lifecycle recovery;
        // never report a clean failure or claim ownership.
        result.changedSystemState = true;
        error += "; " + rollbackError;
        return;
    }
    // Disk bytes are the exact prior bytes again: no system state change
    // remains, and the Prepared record may be safely compensated.
    std::string discardError;
    if (!discardPrepared(id, discardError)) {
        error += "; " + discardError;
        return;
    }
}

bool PamManagedPasswordSlotWriter::neutralizeSlotForPreparedCompensation(
    const ManagedPasswordSlotSpec& spec,
    fic::rollback::MutationId preparedId, std::string& error) {
    PamConfigFileSnapshot snapshot;
    if (!captureSlot(spec, snapshot, error)) {
        return false;
    }
    if (!snapshot.existed) {
        error = "managed password slot disappeared during Prepared "
                "compensation (fail closed): " +
            snapshot.path.string();
        return false;
    }
    ManagedPasswordSlotInspection inspection;
    if (!inspectSnapshot(spec, snapshot, inspection, error)) {
        return false;
    }
    if (inspection.state == ManagedPasswordSlotState::Neutral) {
        // Nothing this Prepared mutation left behind in this slot.
        error.clear();
        return true;
    }
    if (inspection.state != ManagedPasswordSlotState::Active ||
        inspection.mutationId != preparedId) {
        // Exact mutation-ID compensation rule: a Prepared record may only
        // change physical state whose marker carries the exact same id.
        error = "refusing to compensate managed password slot " +
            std::string(spec.fileName) + " with " +
            (inspection.state == ManagedPasswordSlotState::Active
                 ? "foreign mutation id " +
                     std::to_string(inspection.mutationId)
                 : std::string("a non-canonical marker")) +
            " (fail closed)";
        return false;
    }
    PamConfigFileSnapshot neutralSnapshot;
    if (!captureSlot(spec, neutralSnapshot, error)) {
        return false;
    }
    if (!writeSlot(
            spec, neutralSnapshot, PamManagedPasswordSlots::neutralBody(),
            0, false, error)) {
        // The compensation write itself may have installed bytes before
        // failing: restore the exact pre-compensation state.
        std::string rollbackError;
        if (!PamConfigFileTransaction::rollback(
                neutralSnapshot, rollbackError)) {
            error += "; " + rollbackError;
        }
        return false;
    }
    ManagedPasswordSlotInspection after;
    if (!freshInspection(spec, after, error) ||
        after.state != ManagedPasswordSlotState::Neutral) {
        if (error.empty()) {
            error = "managed password slot is not neutral after Prepared "
                    "compensation";
        }
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::proveOwnedQuality(
    PamManagedPasswordSlotOwnership& ownership, std::string& error) const {
    ownership = {};
    if (!ensureJournalReadable(error)) {
        ownership.error = error;
        return false;
    }
    ManagedPasswordSlotInspection inspection;
    if (!freshInspection(
            PamManagedPasswordSlots::qualitySlot(), inspection, error)) {
        ownership.error = error;
        return false;
    }
    if (inspection.state != ManagedPasswordSlotState::Active) {
        error = inspection.state == ManagedPasswordSlotState::Neutral
            ? "managed quality slot is neutral: no physical ownership"
            : "managed quality slot is not canonical Active: " + error;
        ownership.error = error;
        return false;
    }
    PasswordSlotJournalBinding binding;
    fic::rollback::MutationRecord record;
    if (!findBoundRecord(inspection.mutationId, binding, record, error)) {
        ownership.error = error;
        return false;
    }
    ownership.journal = binding;
    ownership.mutationId = record.id;
    if (binding != PasswordSlotJournalBinding::MatchingApplied) {
        error = "managed quality slot is bound to a Prepared journal "
                "record; ownership is not proven";
        ownership.error = error;
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::proveOwnedHistory(
    PamManagedPasswordSlotOwnership& ownership, std::string& error) const {
    ownership = {};
    if (!ensureJournalReadable(error)) {
        ownership.error = error;
        return false;
    }
    ManagedPasswordSlotInspection normal;
    ManagedPasswordSlotInspection initial;
    ManagedHistoryPairInspection pair;
    if (!freshInspection(
            PamManagedPasswordSlots::historyNormalSlot(), normal, error) ||
        !freshInspection(
            PamManagedPasswordSlots::historyInitialSlot(), initial, error) ||
        !PamManagedPasswordSlots::inspectHistoryPair(
            normal, initial, pair, error)) {
        ownership.error = error;
        return false;
    }
    if (pair.state != ManagedHistoryPairState::Active) {
        error = pair.state == ManagedHistoryPairState::Neutral
            ? "managed history pair is neutral: no physical ownership"
            : "managed history pair is not canonical Active: " + error;
        ownership.error = error;
        return false;
    }
    PasswordSlotJournalBinding binding;
    fic::rollback::MutationRecord record;
    if (!findBoundRecord(pair.mutationId, binding, record, error)) {
        ownership.error = error;
        return false;
    }
    ownership.journal = binding;
    ownership.mutationId = record.id;
    ownership.historyOptions = pair.options;
    if (binding != PasswordSlotJournalBinding::MatchingApplied) {
        error = "managed history pair is bound to a Prepared journal "
                "record; ownership is not proven";
        ownership.error = error;
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::finishQualityActivation(
    std::vector<PamConfigFileSnapshot>& snapshots,
    fic::rollback::MutationId id,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    ManagedPasswordSlotInspection after;
    if (!freshInspection(
            PamManagedPasswordSlots::qualitySlot(), after, error) ||
        after.state != ManagedPasswordSlotState::Active ||
        after.role != ManagedPasswordSlotRole::Quality ||
        after.capability != ManagedPasswordCapability::PasswordQuality ||
        after.mutationId != id) {
        if (error.empty()) {
            error = "fresh quality slot proof did not report the exact "
                    "prepared mutation";
        }
        error = "quality activation fresh proof failed: " + error;
        compensateFreshFailure(snapshots, snapshots.size(), id, result, error);
        return false;
    }
    if (!completePrepared(id, error)) {
        // The physical mutation persisted; the journal commit failure must
        // never be reported as a clean failure.
        result.changedSystemState = true;
        return false;
    }
    result.success = true;
    result.changedSystemState = true;
    result.ownershipProven = true;
    result.mutationId = id;
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::finishHistoryActivation(
    const ManagedPwhistorySlotOptions& options,
    std::vector<PamConfigFileSnapshot>& snapshots,
    fic::rollback::MutationId id,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    ManagedPasswordSlotInspection normal;
    ManagedPasswordSlotInspection initial;
    ManagedHistoryPairInspection pair;
    if (!freshInspection(
            PamManagedPasswordSlots::historyNormalSlot(), normal, error) ||
        !freshInspection(
            PamManagedPasswordSlots::historyInitialSlot(), initial, error) ||
        !PamManagedPasswordSlots::inspectHistoryPair(
            normal, initial, pair, error)) {
        error = "history activation fresh pair proof failed: " + error;
        compensateFreshFailure(snapshots, snapshots.size(), id, result, error);
        return false;
    }
    const bool proven =
        pair.state == ManagedHistoryPairState::Active &&
        pair.mutationId == id && pair.options.has_value() &&
        *pair.options == options;
    if (!proven) {
        error = pair.state == ManagedHistoryPairState::Active
            ? "fresh history pair carries a foreign mutation id or "
              "divergent options"
            : "fresh history pair is not a canonical Active pair";
        compensateFreshFailure(snapshots, snapshots.size(), id, result, error);
        return false;
    }
    if (!completePrepared(id, error)) {
        result.changedSystemState = true;
        return false;
    }
    result.success = true;
    result.changedSystemState = true;
    result.ownershipProven = true;
    result.mutationId = id;
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::recoverBrokenHistoryPair(
    fic::rollback::MutationId preparedId, std::string& error) {
    ManagedPasswordSlotInspection normal;
    ManagedPasswordSlotInspection initial;
    if (!freshInspection(
            PamManagedPasswordSlots::historyNormalSlot(), normal, error) ||
        !freshInspection(
            PamManagedPasswordSlots::historyInitialSlot(), initial, error)) {
        return false;
    }
    // The only recoverable composition is an exact crash-partial: one
    // slot Active with the exact Prepared id, the other Neutral.
    // Everything else (mixed ids, foreign id, broken marker, missing
    // file) fails closed and is never compensated.
    const bool normalPartial =
        normal.state == ManagedPasswordSlotState::Active &&
        normal.mutationId == preparedId &&
        initial.state == ManagedPasswordSlotState::Neutral;
    const bool initialPartial =
        initial.state == ManagedPasswordSlotState::Active &&
        initial.mutationId == preparedId &&
        normal.state == ManagedPasswordSlotState::Neutral;
    if (!normalPartial && !initialPartial) {
        error = "Prepared managed history provenance faces a broken pair "
                "(fail closed)";
        return false;
    }
    const ManagedPasswordSlotSpec& activeSpec =
        normalPartial ? PamManagedPasswordSlots::historyNormalSlot()
                      : PamManagedPasswordSlots::historyInitialSlot();
    if (!neutralizeSlotForPreparedCompensation(
            activeSpec, preparedId, error)) {
        return false;
    }
    // Fresh proof of the compensated pair before the record is discarded.
    ManagedPasswordSlotInspection afterNormal;
    ManagedPasswordSlotInspection afterInitial;
    ManagedHistoryPairInspection afterPair;
    if (!freshInspection(
            PamManagedPasswordSlots::historyNormalSlot(), afterNormal,
            error) ||
        !freshInspection(
            PamManagedPasswordSlots::historyInitialSlot(), afterInitial,
            error) ||
        !PamManagedPasswordSlots::inspectHistoryPair(
            afterNormal, afterInitial, afterPair, error) ||
        afterPair.state != ManagedHistoryPairState::Neutral) {
        if (error.empty()) {
            error = "history pair is not neutral after Prepared "
                    "compensation";
        }
        return false;
    }
    if (!discardPrepared(preparedId, error)) {
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::activateFreshHistory(
    const ManagedPwhistorySlotOptions& options,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    // Snapshot both files, then classify the starting pair.
    std::vector<PamConfigFileSnapshot> snapshots(2);
    if (!captureSlot(
            PamManagedPasswordSlots::historyNormalSlot(), snapshots[0],
            error) ||
        !captureSlot(
            PamManagedPasswordSlots::historyInitialSlot(), snapshots[1],
            error)) {
        return false;
    }
    if (!snapshots[0].existed || !snapshots[1].existed) {
        error = "managed history slot is missing (fail closed; packaging "
                "must provide the infrastructure)";
        return false;
    }
    ManagedPasswordSlotInspection normal;
    ManagedPasswordSlotInspection initial;
    ManagedHistoryPairInspection pair;
    if (!inspectSnapshot(
            PamManagedPasswordSlots::historyNormalSlot(), snapshots[0],
            normal, error) ||
        !inspectSnapshot(
            PamManagedPasswordSlots::historyInitialSlot(), snapshots[1],
            initial, error) ||
        !PamManagedPasswordSlots::inspectHistoryPair(
            normal, initial, pair, error)) {
        error = "managed history pair is not canonical (fail closed): " +
            error;
        return false;
    }
    if (pair.state == ManagedHistoryPairState::Active) {
        // Canonical Active pair without matching journal provenance is
        // foreign state: never overwrite, never neutralize, never adopt.
        PasswordSlotJournalBinding binding;
        fic::rollback::MutationRecord record;
        if (!findBoundRecord(pair.mutationId, binding, record, error)) {
            error = "refusing active managed history pair without "
                    "matching journal provenance: " +
                error;
            return false;
        }
        error = "refusing active managed history pair bound to journal "
                "mutation " +
            std::to_string(record.id) + " with status " +
            fic::rollback::mutationStatusToString(record.status);
        return false;
    }
    if (pair.state == ManagedHistoryPairState::Broken) {
        error = "managed history pair is not canonical (fail closed): " +
            error;
        return false;
    }

    // One logical mutation: one Prepared record, one mutation id shared by
    // both active markers. Prepared BEFORE any physical mutation.
    fic::rollback::MutationId id = 0;
    if (!prepareRecord(id, error)) {
        return false;
    }
    std::string desiredNormal;
    std::string desiredInitial;
    if (!PamManagedPasswordSlots::renderActiveHistoryNormal(
            id, options, desiredNormal, error) ||
        !PamManagedPasswordSlots::renderActiveHistoryInitial(
            id, options, desiredInitial, error)) {
        compensateFreshFailure(snapshots, 0, id, result, error);
        return false;
    }
    for (std::size_t index = 0; index < snapshots.size(); ++index) {
        const ManagedPasswordSlotSpec& spec =
            index == 0 ? PamManagedPasswordSlots::historyNormalSlot()
                       : PamManagedPasswordSlots::historyInitialSlot();
        const std::string& desired =
            index == 0 ? desiredNormal : desiredInitial;
        if (!writeSlot(
                spec, snapshots[index], desired, index, true, error)) {
            compensateFreshFailure(snapshots, index + 1, id, result, error);
            return false;
        }
    }
    return finishHistoryActivation(options, snapshots, id, result, error);
}

bool PamManagedPasswordSlotWriter::activateOwnedPasswordHistory(
    const ManagedPwhistorySlotOptions& options,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    result = {};
    bool found = false;
    fic::rollback::MutationRecord active;
    if (!collectActiveRecord(found, active, error)) {
        return false;
    }
    if (found) {
        if (active.status == fic::rollback::MutationStatus::Applied) {
            // Idempotence: the pair must still be the exact canonical
            // Active pair of this record with the same logical options.
            PamManagedPasswordSlotOwnership ownership;
            if (!proveOwnedHistory(ownership, error) ||
                !ownership.historyOptions.has_value() ||
                !(*ownership.historyOptions == options)) {
                if (error.empty()) {
                    error = "Applied managed history provenance carries "
                            "different logical options than requested";
                }
                error = "history idempotence check failed: " + error;
                return false;
            }
            result.success = true;
            result.ownershipProven = true;
            result.mutationId = active.id;
            error.clear();
            return true;
        }
        // Prepared recovery. Classify the fresh physical pair. A pair
        // inspection failure (mixed states = Broken) must fall through to
        // the exact crash-partial recovery, never abort it.
        ManagedPasswordSlotInspection normal;
        ManagedPasswordSlotInspection initial;
        ManagedHistoryPairInspection pair;
        if (!freshInspection(
                PamManagedPasswordSlots::historyNormalSlot(), normal,
                error) ||
            !freshInspection(
                PamManagedPasswordSlots::historyInitialSlot(), initial,
                error)) {
            return false;
        }
        std::string pairError;
        if (!PamManagedPasswordSlots::inspectHistoryPair(
                normal, initial, pair, pairError)) {
            if (!recoverBrokenHistoryPair(active.id, error)) {
                error = "Prepared managed history provenance faces a "
                        "broken pair (fail closed): " +
                    pairError + "; " + error;
                return false;
            }
            return activateFreshHistory(options, result, error);
        }
        if (pair.state == ManagedHistoryPairState::Neutral) {
            PamConfigFileSnapshot normalSnapshot;
            PamConfigFileSnapshot initialSnapshot;
            if (!captureSlot(
                    PamManagedPasswordSlots::historyNormalSlot(),
                    normalSnapshot, error) ||
                !captureSlot(
                    PamManagedPasswordSlots::historyInitialSlot(),
                    initialSnapshot, error) ||
                !proveSlotDurable(normalSnapshot, error) ||
                !proveSlotDurable(initialSnapshot, error) ||
                !discardPrepared(active.id, error)) {
                return false;
            }
            error.clear();
        } else if (
            pair.state == ManagedHistoryPairState::Active &&
            pair.mutationId == active.id && pair.options.has_value() &&
            *pair.options == options) {
            PamConfigFileSnapshot normalSnapshot;
            PamConfigFileSnapshot initialSnapshot;
            if (!captureSlot(
                    PamManagedPasswordSlots::historyNormalSlot(),
                    normalSnapshot, error) ||
                !captureSlot(
                    PamManagedPasswordSlots::historyInitialSlot(),
                    initialSnapshot, error) ||
                !proveSlotDurable(normalSnapshot, error) ||
                !proveSlotDurable(initialSnapshot, error) ||
                !completePrepared(active.id, error)) {
                return false;
            }
            result.success = true;
            result.ownershipProven = true;
            result.mutationId = active.id;
            error.clear();
            return true;
        } else if (
            pair.state == ManagedHistoryPairState::Active &&
            pair.mutationId == active.id) {
            error = "Prepared managed history provenance faces an Active "
                    "pair with divergent logical options (fail closed)";
            return false;
        } else if (
            pair.state == ManagedHistoryPairState::Active) {
            error = "Prepared managed history provenance faces a pair "
                    "owned by journal mutation " +
                std::to_string(pair.mutationId) + " (fail closed)";
            return false;
        } else if (!recoverBrokenHistoryPair(active.id, error)) {
            return false;
        }
    }
    return activateFreshHistory(options, result, error);
}

bool PamManagedPasswordSlotWriter::activateOwnedPasswordQuality(
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    result = {};
    bool found = false;
    fic::rollback::MutationRecord active;
    if (!collectActiveRecord(found, active, error)) {
        return false;
    }
    if (found) {
        if (active.status == fic::rollback::MutationStatus::Applied) {
            // Idempotence (existing ownership): never rewrite, never issue
            // a new mutation id. The physical state must still be the
            // exact canonical Active slot of this record.
            ManagedPasswordSlotInspection inspection;
            if (!freshInspection(
                    PamManagedPasswordSlots::qualitySlot(), inspection,
                    error) ||
                inspection.state != ManagedPasswordSlotState::Active ||
                inspection.mutationId != active.id) {
                result.ownershipProven = false;
                error = "Applied managed quality provenance has no proven "
                        "owned slot (fail closed)" +
                    (error.empty() ? std::string() : ": " + error);
                return false;
            }
            result.success = true;
            result.ownershipProven = true;
            result.mutationId = active.id;
            error.clear();
            return true;
        }
        // Prepared recovery (existing lifecycle semantics):
        //   Neutral -> stale Prepared: prove durability, discard, fresh
        //   Active(same id) -> complete to Applied (idempotent outcome)
        //   Active(other id)/Broken/missing -> fail closed
        ManagedPasswordSlotInspection inspection;
        if (!freshInspection(
                PamManagedPasswordSlots::qualitySlot(), inspection, error)) {
            return false;
        }
        if (inspection.state == ManagedPasswordSlotState::Neutral) {
            PamConfigFileSnapshot snapshot;
            if (!captureSlot(
                    PamManagedPasswordSlots::qualitySlot(), snapshot,
                    error) ||
                !proveSlotDurable(snapshot, error) ||
                !discardPrepared(active.id, error)) {
                return false;
            }
            error.clear();
        } else if (
            inspection.state == ManagedPasswordSlotState::Active &&
            inspection.mutationId == active.id) {
            PamConfigFileSnapshot snapshot;
            if (!captureSlot(
                    PamManagedPasswordSlots::qualitySlot(), snapshot,
                    error) ||
                !proveSlotDurable(snapshot, error) ||
                !completePrepared(active.id, error)) {
                return false;
            }
            result.success = true;
            result.ownershipProven = true;
            result.mutationId = active.id;
            error.clear();
            return true;
        } else if (
            inspection.state == ManagedPasswordSlotState::Active) {
            error = "Prepared managed quality provenance faces a slot "
                    "owned by journal mutation " +
                std::to_string(inspection.mutationId) + " (fail closed)";
            return false;
        } else {
            error = "Prepared managed quality provenance faces a " +
                std::string(
                    inspection.state == ManagedPasswordSlotState::Broken
                        ? "broken"
                        : "missing") +
                " slot (fail closed)";
            return false;
        }
    }

    // Fresh activation: classify the starting state first.
    const ManagedPasswordSlotSpec& spec =
        PamManagedPasswordSlots::qualitySlot();
    PamConfigFileSnapshot snapshot;
    if (!captureSlot(spec, snapshot, error)) {
        return false;
    }
    ManagedPasswordSlotInspection inspection;
    if (!inspectSnapshot(spec, snapshot, inspection, error)) {
        return false;
    }
    if (inspection.state == ManagedPasswordSlotState::Unavailable) {
        error = "managed quality slot is missing (fail closed; packaging "
                "must provide the infrastructure): " + snapshot.path.string();
        return false;
    }
    if (inspection.state == ManagedPasswordSlotState::Broken) {
        error = "managed quality slot is not canonical (fail closed): " +
            error;
        return false;
    }
    if (inspection.state == ManagedPasswordSlotState::Active) {
        // Canonical Active without matching journal provenance is foreign
        // state: never overwrite, never neutralize, never adopt.
        PasswordSlotJournalBinding binding;
        fic::rollback::MutationRecord record;
        if (!findBoundRecord(inspection.mutationId, binding, record, error)) {
            error = "refusing active managed quality slot without matching "
                    "journal provenance: " +
                error;
            return false;
        }
        error = "refusing active managed quality slot bound to journal "
                "mutation " +
            std::to_string(record.id) + " with status " +
            fic::rollback::mutationStatusToString(record.status);
        return false;
    }

    // Prepared BEFORE any physical mutation.
    fic::rollback::MutationId id = 0;
    if (!prepareRecord(id, error)) {
        return false;
    }
    std::string desired;
    if (!PamManagedPasswordSlots::renderActiveQuality(id, desired, error)) {
        // No physical mutation happened; only the Prepared record must be
        // compensated.
        std::vector<PamConfigFileSnapshot> noSnapshots;
        compensateFreshFailure(noSnapshots, 0, id, result, error);
        return false;
    }
    std::vector<PamConfigFileSnapshot> snapshots{snapshot};
    if (!writeSlot(spec, snapshots.front(), desired, 0, true, error)) {
        compensateFreshFailure(snapshots, 1, id, result, error);
        return false;
    }
    return finishQualityActivation(snapshots, id, result, error);
}


} // namespace fic::identity::pam
