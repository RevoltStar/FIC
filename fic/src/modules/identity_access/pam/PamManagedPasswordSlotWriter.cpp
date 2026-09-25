#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"

#include "modules/identity_access/pam/PamConfigFileTransaction.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <stdexcept>
#include <utility>

namespace fic::identity::pam {

namespace {

// Canonical domain identity (P1-2 security identity, not caller input):
// the only two policies this component may ever journal or prove.
const PolicyRef kQualityPolicyRef{
    "IDENTITY_ACCESS", "PAM", "enable_password_quality"};
const PolicyRef kHistoryPolicyRef{
    "IDENTITY_ACCESS", "PAM", "enable_password_history"};

// P1-3: activationIdentifiers carry the pam-auth-update PERMANENT HOOK
// PROFILE id of the domain (the Step 1 design canonical journal activation
// domain), never the physical slot filenames. The history domain uses ONE
// identifier: its two physical slots are exposed through a single
// dual-stack hook profile (Password -> include fic-password-history,
// Password-Initial -> include fic-password-history-initial). Physical slot
// file names stay internal to PamManagedPasswordSlots /
// PamManagedPasswordSlotWriter. The current platform profiles still carry
// legacy identifiers; they are migrated by the later packaging/platform
// integration steps — this payload fixes the future provenance contract.
constexpr const char* kQualityActivationIdentifier =
    "fic-password-quality-hook";
constexpr const char* kHistoryActivationIdentifier =
    "fic-password-history-hook";
constexpr const char* kHistoryInitialActivationIdentifier =
    "fic-password-history-initial-hook";

} // namespace

PamManagedPasswordSlotWriter::PamManagedPasswordSlotWriter(
    std::filesystem::path configDirectory,
    fic::rollback::MutationJournal& journal,
    PamManagedPasswordDomain domain)
    : configDirectory_(std::move(configDirectory)),
      journal_(journal),
      policyRef_(canonicalPolicyRef(domain)),
      domain_(domain) {}

PolicyRef PamManagedPasswordSlotWriter::canonicalPolicyRef(
    PamManagedPasswordDomain domain) {
    switch (domain) {
    case PamManagedPasswordDomain::Quality:
        return kQualityPolicyRef;
    case PamManagedPasswordDomain::History:
        return kHistoryPolicyRef;
    }
    throw std::runtime_error("unknown PamManagedPasswordDomain");
}

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
    // P1-3: journal undo activation domain = pam-auth-update hook/profile
    // identifiers, NEVER the physical include-target slot filenames (the
    // physical slot domain is /etc/pam.d/fic-password-* and stays internal
    // to the slots layer).
    switch (domain_) {
    case PamManagedPasswordDomain::Quality:
        undo.activationIdentifiers = {kQualityActivationIdentifier};
        break;
    case PamManagedPasswordDomain::History:
        // One dual-stack hook profile for both history slots.
        undo.activationIdentifiers = {kHistoryActivationIdentifier};
        break;
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
    std::string& error) const {
    // P1-1: operational provenance requires usable() AND
    // lifecycleInitialized(). A raw load() (usable without the
    // witness-aware lifecycle) is NEVER trusted as operational state here.
    if (journal_.usable() && journal_.lifecycleInitialized()) {
        error.clear();
        return true;
    }
    // Witness-aware lifecycle entrypoint only. Its returned true alone is
    // not accepted: both flags are re-checked after the call (on a
    // raw-loaded object initializeOrLoad() runs the full witness-aware
    // state table — virgin bootstrap or migration — and establishes the
    // lifecycle before the journal may drive mutations).
    if (!journal_.initializeOrLoad(error)) {
        error = "managed password journal is not operational: " + error;
        return false;
    }
    if (!journal_.usable() || !journal_.lifecycleInitialized()) {
        error = "managed password journal failed its operational gate";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::ensureJournalReadable(
    std::string& error) const {
    // Read-only path (P1-1): no writes, no witness creation, no migration,
    // no bootstrap. usable() WITHOUT lifecycleInitialized() (e.g. after a
    // raw load()) must never short-circuit to success: the persistent
    // (journal, witness) pair is proven strictly non-mutatingly first.
    if (journal_.usable() && journal_.lifecycleInitialized()) {
        error.clear();
        return true;
    }
    // Read-only persistent-state validation: the same witness-aware state
    // table as the operational lifecycle, but strictly without any
    // filesystem mutation (no bootstrap, no witness creation, no repair,
    // no migration). On success it establishes the lifecycle on the
    // journal object (the persistent pair was proven) without touching
    // the filesystem.
    if (!journal_.validatePersistentStateReadOnly(error)) {
        error = "managed password journal persistent state is not proven "
                "(fail closed): " +
            error;
        return false;
    }
    if (!journal_.usable() || !journal_.lifecycleInitialized()) {
        error = "managed password journal is not readable after validation";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::collectActiveRecord(
    bool& found, fic::rollback::MutationRecord& record,
    std::string& error) const {
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
    fic::rollback::MutationId preparedId, bool& changedSystemState,
    std::string& error) {
    // P1-5 contract: changedSystemState is only ever ORed with true by
    // this helper (monotonic); the caller owns the accumulator and must
    // never infer "no physical change" from a false return alone.
    // Every return below after a possible physical mutation documents
    // why the flag value is correct for its branch:
    //   - failure before any write attempt: flag untouched (false);
    //   - write installed + exact restore PROVEN: flag untouched (false);
    //   - write installed + restore failed/unproven: flag set true;
    //   - write committed (state left the entry state): flag set true.
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
        // Case A: nothing this Prepared mutation left behind in this
        // slot; no write is attempted, so no change is reported.
        error.clear();
        return true;
    }
    if (inspection.state != ManagedPasswordSlotState::Active ||
        inspection.mutationId != preparedId) {
        // Exact mutation-ID compensation rule: a Prepared record may only
        // change physical state whose marker carries the exact same id.
        // No write has been attempted: changedSystemState stays false.
        error = "refusing to compensate managed password slot " +
            std::string(spec.fileName) + " with " +
            (inspection.state == ManagedPasswordSlotState::Active
                 ? "foreign mutation id " +
                     std::to_string(inspection.mutationId)
                 : std::string("a non-canonical marker")) +
            " (fail closed)";
        return false;
    }
    // P1-6 (same-snapshot ownership proof): from this point `snapshot` is
    // the ownership proof token — these exact bytes/metadata/inode were
    // proven as canonical Active with the EXACT prepared id above, and the
    // conditional transaction write below is allowed only while the target
    // is still exactly this state. There is deliberately NO second capture
    // between the proof and the mutation: a concurrent Active(A) →
    // Active(B) replacement after the proof makes the transaction's
    // expectedTargetState (built from THIS snapshot) mismatch the current
    // target, so the write fails closed and the foreign state is never
    // neutralized.
    //
    // Same fault-hook seam as the fresh activation writes so tests can
    // inject failures before and after the physical commit of the
    // compensation write itself. Production runs with no hooks set.
    const std::size_t slotIndex =
        spec.role == ManagedPasswordSlotRole::HistoryInitial ? 1 : 0;
    if (!writeSlot(
            spec, snapshot, PamManagedPasswordSlots::neutralBody(),
            slotIndex, true, error)) {
        // Distinguish what actually happened from the failure alone:
        // mutate() marks the snapshot MutationCommitted only when the FIC
        // replacement was physically installed AND ownership of the output
        // was recorded. A concurrent A→B replacement between the proof and
        // the write fails the expectedTargetState precondition BEFORE any
        // install, so the snapshot stays Captured and the on-disk foreign
        // state is not FIC's to restore (rollback() would be a no-op
        // anyway and must never overwrite it with Active(A)).
        if (snapshot.state !=
            PamConfigFileTransactionState::MutationCommitted) {
            // FIC replacement was never accepted as committed: no FIC
            // physical change exists, so changedSystemState stays
            // unchanged (false at this point) even though the current
            // bytes may differ from the proof snapshot due to an external
            // actor. Fail closed.
            error = "Prepared compensation write was not committed to the "
                    "proven snapshot state (fail closed): " +
                std::string(spec.fileName) + "; " + error;
            return false;
        }
        // The FIC replacement was installed: restore the exact
        // pre-compensation state unconditionally.
        std::string rollbackError;
        if (!PamConfigFileTransaction::rollback(snapshot, rollbackError)) {
            // Case E: the installed physical change cannot be undone;
            // the caller must never treat this as a clean no-op failure.
            changedSystemState = true;
            error += "; " + rollbackError;
            return false;
        }
        // Rollback reported success, but the exact restoration of the
        // entry state (Active with the exact Prepared id) still has to
        // be proven before the change may be reported as compensated.
        ManagedPasswordSlotInspection restored;
        std::string proofError;
        if (!freshInspection(spec, restored, proofError) ||
            restored.state != ManagedPasswordSlotState::Active ||
            restored.mutationId != preparedId) {
            // Case E variant: installed write, restore not provable.
            changedSystemState = true;
            error += "; exact restoration of the pre-compensation state "
                     "could not be proven" +
                (proofError.empty() ? std::string() : ": " + proofError);
            return false;
        }
        // Case D: installed write, then exact proven restore of the
        // entry bytes — no system state change remains (flag false).
        return false;
    }
    // The write committed: physical state left the entry state. Set the
    // flag BEFORE the post-write proof so a proof failure cannot lose it.
    changedSystemState = true;
    ManagedPasswordSlotInspection after;
    if (!freshInspection(spec, after, error) ||
        after.state != ManagedPasswordSlotState::Neutral) {
        // Case F: the physical neutralization stands (flag already true)
        // but the fresh proof failed; fail closed, never clean.
        if (error.empty()) {
            error = "managed password slot is not neutral after Prepared "
                    "compensation";
        }
        return false;
    }
    // Case B: proven fresh Neutral; the change is reported (flag true).
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

PasswordDomainJournalState
PamManagedPasswordSlotWriter::inspectJournalBindingForDomain(
    std::uint64_t& mutationId, std::string& error) const {
    mutationId = 0;
    // witnessPath() contract is <journal path>.initialized. Probe directory
    // entries without following links: dangling links are not virgin state.
    const auto witness = journal_.witnessPath();
    auto journalPath = witness;
    journalPath.replace_extension();
    const auto absent = [](const std::filesystem::path& path) {
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(path, ec);
        return status.type() == std::filesystem::file_type::not_found &&
            (!ec || ec == std::errc::no_such_file_or_directory);
    };
    if (!journal_.loaded() && absent(journalPath) && absent(witness)) {
        error.clear();
        return PasswordDomainJournalState::VirginUnbound;
    }
    // Read-only persistent-state gate: exactly the same witness-aware
    // state table as the ownership proofs use, strictly non-mutating.
    if (!ensureJournalReadable(error)) {
        error = "managed password journal persistent state is not proven "
                "(fail closed): " +
            error;
        return PasswordDomainJournalState::Invalid;
    }
    // collectActiveRecord enforces the strict domain preconditions:
    // at most one active record, exact metadata match (policy ref, PAM
    // backend, resource, capability/topology/activation payload) and no
    // RollbackFailed provenance. Multiple active records, metadata
    // mismatches and RollbackFailed records all fail closed through the
    // error path (Conflict), never by selecting a record by chance.
    bool found = false;
    fic::rollback::MutationRecord record;
    if (!collectActiveRecord(found, record, error)) {
        error = "managed password journal domain classification failed "
                "(fail closed): " +
            error;
        return PasswordDomainJournalState::Conflict;
    }
    if (!found) {
        error.clear();
        return PasswordDomainJournalState::Unbound;
    }
    mutationId = record.id;
    if (record.status == fic::rollback::MutationStatus::Applied) {
        error.clear();
        return PasswordDomainJournalState::Applied;
    }
    error.clear();
    return PasswordDomainJournalState::Prepared;
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
    fic::rollback::MutationId preparedId,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
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
    // P1-5: the helper reports the physical-change outcome separately from
    // success/failure. It may return false AFTER physically mutating the
    // slot (installed write with failed/unproven restore, or failed post-
    // write proof); the OR-accumulation below preserves that change in the
    // top-level result regardless of the helper outcome.
    bool neutralizeChanged = false;
    if (!neutralizeSlotForPreparedCompensation(
            activeSpec, preparedId, neutralizeChanged, error)) {
        result.changedSystemState = result.changedSystemState || neutralizeChanged;
        return false;
    }
    // P1-4/P1-5: the exact-id Active slot WAS physically neutralized (the
    // successful helper return here implies neutralizeChanged == true).
    // From this point the top-level activation call has changed the system
    // state relative to its entry state, even if any later step (fresh
    // neutral proof, Prepared discard, subsequent fresh activation) fails
    // — a physical change that was installed must never be reported as a
    // clean no-op failure. Monotonic accumulation: later phases may only
    // OR additional changes on top, never reset the flag.
    result.changedSystemState = result.changedSystemState || neutralizeChanged;
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
            if (!recoverBrokenHistoryPair(active.id, result, error)) {
                // recoverBrokenHistoryPair already accumulated any physical
                // change it installed into result.changedSystemState
                // (P1-4); never report a clean failure after a real
                // neutralization.
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
        } else {
            // Exact crash-partial recovery. recoverBrokenHistoryPair
            // accounts for its physical neutralization in
            // result.changedSystemState (P1-4); the fresh activation below
            // only ever ORs additional changes on top of it.
            if (!recoverBrokenHistoryPair(active.id, result, error)) {
                return false;
            }
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

// ---- C2 per-identity lifecycle (activation-time FIC-owned hooks) ----

bool PamManagedPasswordSlotWriter::c2RoleUsesDomain(
    ManagedPasswordSlotRole role, PamManagedPasswordDomain domain) {
    switch (role) {
    case ManagedPasswordSlotRole::Quality:
        return domain == PamManagedPasswordDomain::Quality;
    case ManagedPasswordSlotRole::HistoryNormal:
    case ManagedPasswordSlotRole::HistoryInitial:
        return domain == PamManagedPasswordDomain::History;
    }
    return false;
}

const ManagedPasswordSlotSpec& PamManagedPasswordSlotWriter::c2RoleSlot(
    ManagedPasswordSlotRole role) {
    switch (role) {
    case ManagedPasswordSlotRole::Quality:
        return PamManagedPasswordSlots::qualitySlot();
    case ManagedPasswordSlotRole::HistoryNormal:
        return PamManagedPasswordSlots::historyNormalSlot();
    case ManagedPasswordSlotRole::HistoryInitial:
        return PamManagedPasswordSlots::historyInitialSlot();
    }
    throw std::runtime_error("unknown ManagedPasswordSlotRole");
}

const char* PamManagedPasswordSlotWriter::c2RoleActivationIdentifier(
    ManagedPasswordSlotRole role) {
    switch (role) {
    case ManagedPasswordSlotRole::Quality:
        return kQualityActivationIdentifier;
    case ManagedPasswordSlotRole::HistoryNormal:
        return kHistoryActivationIdentifier;
    case ManagedPasswordSlotRole::HistoryInitial:
        return kHistoryInitialActivationIdentifier;
    }
    throw std::runtime_error("unknown ManagedPasswordSlotRole");
}

std::size_t PamManagedPasswordSlotWriter::c2RoleSlotIndex(
    ManagedPasswordSlotRole role) {
    // Same fault-hook indexing convention as the pair API: 0 = quality or
    // history-normal, 1 = history-initial.
    return role == ManagedPasswordSlotRole::HistoryInitial ? 1 : 0;
}

fic::rollback::UndoDisablePamCapability
PamManagedPasswordSlotWriter::expectedUndoWithIdentifier(
    PamManagedPasswordDomain domain, const char* activationIdentifier) {
    fic::rollback::UndoDisablePamCapability undo;
    undo.capability = domain == PamManagedPasswordDomain::Quality
        ? kQualityPolicyRef.policyName
        : kHistoryPolicyRef.policyName;
    undo.topology = fic::rollback::PamTopologyKind::PamAuthUpdate;
    undo.activationIdentifiers = {activationIdentifier};
    return undo;
}

bool PamManagedPasswordSlotWriter::journalMetadataMatchesRole(
    const fic::rollback::MutationRecord& record,
    ManagedPasswordSlotRole role, std::string& error) const {
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
    const fic::rollback::UndoDisablePamCapability expected =
        expectedUndoWithIdentifier(domain_, c2RoleActivationIdentifier(role));
    if (payload->capability != expected.capability ||
        payload->topology != expected.topology ||
        payload->activationIdentifiers != expected.activationIdentifiers) {
        error = "journal record does not match the activation identifier of "
                "this C2 identity";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::prepareRecordWithIdentifier(
    const char* activationIdentifier, fic::rollback::MutationId& id,
    std::string& error) {
    fic::rollback::MutationRecord record;
    record.policy = policyRef_;
    record.resource = "capability/" + policyRef_.policyName;
    record.undo = {fic::rollback::MutationBackend::Pam,
        expectedUndoWithIdentifier(domain_, activationIdentifier)};
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

bool PamManagedPasswordSlotWriter::proveOwnedC2Slot(
    ManagedPasswordSlotRole role,
    PamManagedPasswordSlotOwnership& ownership, std::string& error) const {
    ownership = {};
    if (!c2RoleUsesDomain(role, domain_)) {
        error = "C2 identity role does not belong to this managed password "
                "domain";
        ownership.error = error;
        return false;
    }
    if (!ensureJournalReadable(error)) {
        ownership.error = error;
        return false;
    }
    const ManagedPasswordSlotSpec& spec = c2RoleSlot(role);
    ManagedPasswordSlotInspection inspection;
    if (!freshInspection(spec, inspection, error)) {
        ownership.error = error;
        return false;
    }
    if (inspection.state != ManagedPasswordSlotState::Active) {
        error = inspection.state == ManagedPasswordSlotState::Neutral
            ? std::string("managed ") + spec.fileName +
                " slot is neutral: no physical ownership"
            : std::string("managed ") + spec.fileName +
                " slot is not canonical Active: " + error;
        ownership.error = error;
        return false;
    }
    for (const fic::rollback::MutationRecord& candidate :
         journal_.records()) {
        if (candidate.id != inspection.mutationId) {
            continue;
        }
        std::string metadataError;
        if (!journalMetadataMatchesRole(candidate, role, metadataError)) {
            error = "physical marker id " +
                std::to_string(inspection.mutationId) +
                " does not prove this C2 identity: " + metadataError;
            ownership.error = error;
            return false;
        }
        if (candidate.status != fic::rollback::MutationStatus::Applied) {
            error = "managed " + std::string(spec.fileName) +
                " slot is bound to a " +
                fic::rollback::mutationStatusToString(candidate.status) +
                " journal record; ownership is not proven";
            ownership.journal =
                candidate.status == fic::rollback::MutationStatus::Prepared
                ? PasswordSlotJournalBinding::MatchingPrepared
                : PasswordSlotJournalBinding::Unbound;
            ownership.error = error;
            return false;
        }
        ownership.journal = PasswordSlotJournalBinding::MatchingApplied;
        ownership.mutationId = candidate.id;
        ownership.historyOptions = inspection.pwhistoryOptions;
        error.clear();
        return true;
    }
    error = "physical marker id " +
        std::to_string(inspection.mutationId) +
        " has no matching journal record";
    ownership.error = error;
    return false;
}

bool PamManagedPasswordSlotWriter::activateC2Slot(
    ManagedPasswordSlotRole role,
    const ManagedPwhistorySlotOptions& options,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    result = {};
    if (!c2RoleUsesDomain(role, domain_)) {
        error = "C2 identity role does not belong to this managed password "
                "domain";
        return false;
    }
    if (!ensureJournalOperational(error)) {
        return false;
    }
    const ManagedPasswordSlotSpec& spec = c2RoleSlot(role);
    PamConfigFileSnapshot snapshot;
    if (!captureSlot(spec, snapshot, error)) {
        return false;
    }
    ManagedPasswordSlotInspection inspection;
    if (!inspectSnapshot(spec, snapshot, inspection, error)) {
        return false;
    }
    if (inspection.state == ManagedPasswordSlotState::Unavailable) {
        error = "managed " + std::string(spec.fileName) +
            " slot is missing (fail closed; packaging must provide the "
            "infrastructure): " +
            snapshot.path.string();
        return false;
    }
    if (inspection.state == ManagedPasswordSlotState::Broken) {
        error = "managed " + std::string(spec.fileName) +
            " slot is not canonical (fail closed): " + error;
        return false;
    }
    if (inspection.state == ManagedPasswordSlotState::Active) {
        // Idempotence or refusal. Canonical Active WITH the role-bound
        // Applied provenance is already the desired state; canonical Active
        // bound to the exact Prepared record of this domain is an exact
        // crash-partial of this very activation and is completed;
        // anything else is foreign state: never overwrite, never
        // neutralize, never adopt.
        for (const fic::rollback::MutationRecord& candidate :
             journal_.records()) {
            if (candidate.id != inspection.mutationId) {
                continue;
            }
            std::string metadataError;
            if (!journalMetadataMatchesRole(
                    candidate, role, metadataError)) {
                error = "refusing active managed " +
                    std::string(spec.fileName) +
                    " slot without matching C2 provenance: " + metadataError;
                return false;
            }
            if (candidate.status == fic::rollback::MutationStatus::Applied) {
                if (role != ManagedPasswordSlotRole::Quality &&
                    (!inspection.pwhistoryOptions.has_value() ||
                        !(*inspection.pwhistoryOptions == options))) {
                    error = "C2 idempotence check failed: the active " +
                        std::string(spec.fileName) +
                        " slot carries different managed options";
                    return false;
                }
                result.success = true;
                result.ownershipProven = true;
                result.mutationId = candidate.id;
                error.clear();
                return true;
            }
            if (candidate.status == fic::rollback::MutationStatus::Prepared) {
                // Exact crash-partial adoption: the slot is canonical
                // Active with the exact Prepared id of this domain and the
                // role-bound payload; completing the record is the same
                // lifecycle the fresh path would have committed.
                if (!completePrepared(candidate.id, error)) {
                    return false;
                }
                result.success = true;
                result.ownershipProven = true;
                result.mutationId = candidate.id;
                error.clear();
                return true;
            }
            error = "refusing active managed " + std::string(spec.fileName) +
                " slot bound to journal mutation " +
                std::to_string(candidate.id) + " with status " +
                fic::rollback::mutationStatusToString(candidate.status);
            return false;
        }
        error = "refusing active managed " + std::string(spec.fileName) +
            " slot without matching journal provenance";
        return false;
    }

    // Neutral entry state: one Prepared record with the role-specific
    // activation identifier, one physical write, fresh durable proof,
    // then Applied.
    fic::rollback::MutationId id = 0;
    if (!prepareRecordWithIdentifier(
            c2RoleActivationIdentifier(role), id, error)) {
        return false;
    }
    std::string desired;
    bool rendered = false;
    switch (role) {
    case ManagedPasswordSlotRole::Quality:
        rendered = PamManagedPasswordSlots::renderActiveQuality(
            id, desired, error);
        break;
    case ManagedPasswordSlotRole::HistoryNormal:
        rendered = PamManagedPasswordSlots::renderActiveHistoryNormal(
            id, options, desired, error);
        break;
    case ManagedPasswordSlotRole::HistoryInitial:
        rendered = PamManagedPasswordSlots::renderActiveHistoryInitial(
            id, options, desired, error);
        break;
    }
    if (!rendered) {
        std::vector<PamConfigFileSnapshot> noSnapshots;
        compensateFreshFailure(noSnapshots, 0, id, result, error);
        return false;
    }
    std::vector<PamConfigFileSnapshot> snapshots{snapshot};
    if (!writeSlot(spec, snapshots.front(), desired,
            c2RoleSlotIndex(role), true, error)) {
        compensateFreshFailure(snapshots, 1, id, result, error);
        return false;
    }
    ManagedPasswordSlotInspection after;
    if (!freshInspection(spec, after, error) ||
        after.state != ManagedPasswordSlotState::Active ||
        after.mutationId != id) {
        if (error.empty()) {
            error = "fresh C2 slot proof did not report the exact prepared "
                    "mutation";
        }
        error = "C2 activation fresh proof failed: " + error;
        compensateFreshFailure(snapshots, 1, id, result, error);
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

bool PamManagedPasswordSlotWriter::compensateC2ActiveSlot(
    ManagedPasswordSlotRole role, fic::rollback::MutationId id,
    bool& changedSystemState, std::string& error) {
    changedSystemState = false;
    if (!c2RoleUsesDomain(role, domain_)) {
        error = "C2 identity role does not belong to this managed password "
                "domain";
        return false;
    }
    if (id == 0) {
        error = "C2 slot compensation requires a nonzero mutation id";
        return false;
    }
    if (!ensureJournalOperational(error)) {
        return false;
    }
    const ManagedPasswordSlotSpec& spec = c2RoleSlot(role);
    PamConfigFileSnapshot snapshot;
    if (!captureSlot(spec, snapshot, error)) {
        return false;
    }
    ManagedPasswordSlotInspection inspection;
    if (!inspectSnapshot(spec, snapshot, inspection, error)) {
        return false;
    }
    if (inspection.state != ManagedPasswordSlotState::Active) {
        error = "refusing C2 compensation of managed " +
            std::string(spec.fileName) + " slot: the slot is not canonical "
            "Active (fail closed; an unexpected state must be resolved by "
            "the caller's drift handling)";
        return false;
    }
    if (inspection.mutationId != id) {
        error = "refusing C2 compensation of managed " +
            std::string(spec.fileName) + " slot: the physical marker "
            "carries foreign mutation id " +
            std::to_string(inspection.mutationId) + " (expected " +
            std::to_string(id) + ")";
        return false;
    }
    // P1-6 same-snapshot rule: these exact bytes were proven canonical
    // Active with the EXACT id; the conditional transaction write below is
    // allowed only while the target still is exactly this state.
    if (!writeSlot(spec, snapshot, PamManagedPasswordSlots::neutralBody(),
            c2RoleSlotIndex(role), true, error)) {
        if (snapshot.state !=
            PamConfigFileTransactionState::MutationCommitted) {
            // No FIC write was committed: no system change to report.
            return false;
        }
        // The write was installed: restore the exact pre-compensation
        // Active state unconditionally.
        std::string rollbackError;
        if (!PamConfigFileTransaction::rollback(snapshot, rollbackError)) {
            changedSystemState = true;
            error += "; CRITICAL: exact restoration of the compensated "
                     "slot failed: " +
                rollbackError;
            return false;
        }
        ManagedPasswordSlotInspection restored;
        std::string proofError;
        if (!freshInspection(spec, restored, proofError) ||
            restored.state != ManagedPasswordSlotState::Active ||
            restored.mutationId != id) {
            changedSystemState = true;
            error += "; exact restoration of the pre-compensation state "
                     "could not be proven" +
                (proofError.empty() ? std::string() : ": " + proofError);
            return false;
        }
        // Installed write, then exact proven restore: no change remains.
        return false;
    }
    changedSystemState = true;
    ManagedPasswordSlotInspection after;
    if (!freshInspection(spec, after, error) ||
        after.state != ManagedPasswordSlotState::Neutral) {
        if (error.empty()) {
            error = "managed " + std::string(spec.fileName) +
                " slot is not neutral after C2 compensation";
        }
        return false;
    }
    // Resolve the journal record by its exact status: Applied becomes
    // RolledBack (the activation is undone), Prepared is discarded (exact
    // crash-partial). Any other status is foreign incoherence.
    fic::rollback::MutationStatus boundStatus{};
    bool found = false;
    for (const fic::rollback::MutationRecord& candidate :
         journal_.records()) {
        if (candidate.id != id) {
            continue;
        }
        boundStatus = candidate.status;
        found = true;
        break;
    }
    if (!found) {
        error = "compensated managed " + std::string(spec.fileName) +
            " slot has no journal record for mutation id " +
            std::to_string(id) + " (fail closed)";
        return false;
    }
    if (boundStatus == fic::rollback::MutationStatus::Applied) {
        if (!journal_.setStatus(
                id, fic::rollback::MutationStatus::RolledBack, error)) {
            error = "managed password journal rollback commit failed: " +
                error;
            return false;
        }
    } else if (boundStatus == fic::rollback::MutationStatus::Prepared) {
        if (!discardPrepared(id, error)) {
            return false;
        }
    } else {
        error = "compensated managed " + std::string(spec.fileName) +
            " slot is bound to a journal record with status " +
            fic::rollback::mutationStatusToString(boundStatus) +
            " (fail closed)";
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlotWriter::deactivateC2Slot(
    ManagedPasswordSlotRole role,
    PamManagedPasswordSlotActivationResult& result, std::string& error) {
    result = {};
    if (!c2RoleUsesDomain(role, domain_)) {
        error = "C2 identity role does not belong to this managed password "
                "domain";
        return false;
    }
    if (!ensureJournalOperational(error)) {
        return false;
    }
    const ManagedPasswordSlotSpec& spec = c2RoleSlot(role);
    ManagedPasswordSlotInspection inspection;
    if (!freshInspection(spec, inspection, error)) {
        return false;
    }
    if (inspection.state != ManagedPasswordSlotState::Active) {
        error = inspection.state == ManagedPasswordSlotState::Neutral
            ? std::string("managed ") + spec.fileName +
                " slot is already neutral: nothing to deactivate"
            : std::string("managed ") + spec.fileName +
                " slot is not canonical Active (fail closed): " + error;
        return false;
    }
    // Exact C2 ownership gate: only an Applied record whose payload carries
    // this identity's activation identifier may be deactivated.
    {
        bool roleBound = false;
        fic::rollback::MutationStatus status{};
        for (const fic::rollback::MutationRecord& candidate :
             journal_.records()) {
            if (candidate.id != inspection.mutationId) {
                continue;
            }
            std::string metadataError;
            if (!journalMetadataMatchesRole(candidate, role, metadataError)) {
                error = "refusing deactivation of managed " +
                    std::string(spec.fileName) +
                    " slot: the physical marker does not prove this C2 "
                    "identity: " +
                    metadataError;
                return false;
            }
            status = candidate.status;
            roleBound = true;
            break;
        }
        if (!roleBound) {
            error = "refusing deactivation of managed " +
                std::string(spec.fileName) +
                " slot: the physical marker id " +
                std::to_string(inspection.mutationId) +
                " has no matching journal record";
            return false;
        }
        if (status != fic::rollback::MutationStatus::Applied) {
            error = "refusing deactivation of managed " +
                std::string(spec.fileName) + " slot: the bound record has "
                "status " +
                fic::rollback::mutationStatusToString(status) +
                "; ownership is not proven";
            return false;
        }
    }
    bool changed = false;
    if (!compensateC2ActiveSlot(
            role, inspection.mutationId, changed, error)) {
        result.changedSystemState = changed;
        return false;
    }
    result.success = true;
    result.changedSystemState = true;
    result.mutationId = 0;
    error.clear();
    return true;
}


} // namespace fic::identity::pam
