#ifndef FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOT_WRITER_H
#define FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOT_WRITER_H

#include "modules/identity_access/pam/PamConfigFileTransaction.h"

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"

#include <fic/policy/PolicyDependency.h>

#include <rollback/MutationJournal.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace fic::identity::pam {

// Step 3: physical writer and journal-bound activation lifecycle for the
// three FIC-owned managed password slots:
//
//   <configDirectory>/fic-password-quality           quality
//   <configDirectory>/fic-password-history           history-normal
//   <configDirectory>/fic-password-history-initial   history-initial
//
// Ownership invariant: a password slot is FIC-owned ONLY when the slot is
// canonical Active AND its marker mutation id equals the id of a valid
// persistent MutationJournal record AND that record matches this policy
// domain exactly (policy ref, Pam backend, resource, capability/topology/
// activation-identifier payload). Any divergence (wrong id, missing record,
// wrong metadata, wrong payload, one history slot active while the other is
// neutral, mixed ids, divergent options) fails closed: ownership is never
// adopted, never repaired and never neutralized.
//
// Journal lifecycle (existing MutationJournal semantics, same model as the
// managed faillock slots): a Prepared record is created BEFORE any physical
// mutation, then the canonical physical mutation carries the exact journal
// id, then a durable fresh re-read with strict physical proof, then the
// journal record becomes Applied. Any failure after Prepared compensates
// only what this exact Prepared mutation changed; a Prepared record that
// cannot be compensated stays Prepared (existing lifecycle) and is resolved
// by the recovery matrix on the next activation (see the activation methods).
//
// This component never repairs the journal and never writes the witness in
// a read-only proof path. The daemon runtime registry, platform profiles and
// PamPolicySupport::ReadOnly are intentionally untouched (Step 7 wires the
// capability policies to this lifecycle).
enum class PasswordSlotJournalBinding {
    // No journal record matches the physical marker id with exact metadata.
    Unbound,
    // A valid Applied record matches the physical marker exactly.
    MatchingApplied,
    // A valid Prepared record matches the physical marker exactly
    // (compensation scope; NOT ownership by itself).
    MatchingPrepared
};

struct PamManagedPasswordSlotOwnership {
    PasswordSlotJournalBinding journal = PasswordSlotJournalBinding::Unbound;
    // Journal record id when bound, otherwise 0.
    std::uint64_t mutationId = 0;
    // Observed logical options of an Active history pair (nullopt otherwise).
    std::optional<ManagedPwhistorySlotOptions> historyOptions;
    // Diagnostic when ownership is NOT proven.
    std::string error;

    // Ownership is proven only for a valid Applied journal record; a
    // matching Prepared record is a compensation binding, never ownership.
    bool owned() const {
        return journal == PasswordSlotJournalBinding::MatchingApplied;
    }
};

// Physical domain of the writer. The journal record payload and the set of
// canonical slot files are derived from this domain; callers can never
// combine a foreign policy name with foreign slot files (the writer always
// resolves the canonical specs through PamManagedPasswordSlots and never
// accepts externally constructed slot specs for persistent writes).
enum class PamManagedPasswordDomain {
    Quality,
    History
};

struct PamManagedPasswordSlotActivationResult {
    bool success = false;
    // True only when physical disk bytes were mutated by this call and the
    // mutation was not fully compensated. Never set merely because a write
    // was attempted.
    bool changedSystemState = false;
    // True only when the resulting state carries proven journal-bound
    // ownership (physical proof + matching Applied journal record).
    bool ownershipProven = false;
    // Journal mutation id of the resulting state (0 when none).
    std::uint64_t mutationId = 0;
    std::string error;
};

class PamManagedPasswordSlotWriter {
public:
    // journal must outlive the writer. configDirectory is the (test
    // injectable) PAM configuration directory; slot paths are always the
    // canonical managed file names inside it.
    PamManagedPasswordSlotWriter(
        std::filesystem::path configDirectory,
        fic::rollback::MutationJournal& journal,
        PolicyRef policyRef,
        PamManagedPasswordDomain domain);

    // The managed password slot grammar embeds the journal mutation id:
    // physical ownership is proven through the journal (Step 7 wires this
    // into the capability lifecycle layer).
    static constexpr bool journalBindsPhysicalOwnership() { return true; }

    // Read-only ownership proof (no journal repair, no witness write, no
    // slot rewrite, no Prepared completion). The quality slot must be
    // canonical Active and its marker id must match a valid Applied record
    // of this policy domain. Fails closed otherwise; ownership.error
    // carries the diagnostic and ownership.journal/mutationId the closest
    // binding observed.
    bool proveOwnedQuality(
        PamManagedPasswordSlotOwnership& ownership, std::string& error) const;

    // Read-only ownership proof for the history pair: both slots must form
    // a canonical Active pair (inspectHistoryPair) whose single mutation id
    // matches a valid Applied record of this policy domain. The observed
    // logical options are returned in ownership.historyOptions; the proof
    // itself never compares them with a desired value (option state is
    // physical, not journal payload).
    bool proveOwnedHistory(
        PamManagedPasswordSlotOwnership& ownership, std::string& error) const;

    // Journal-bound activation of the FIC-owned quality slot
    // (Neutral -> Active with a fresh Prepared->Applied lifecycle,
    // idempotent when already Active with a matching Applied record).
    bool activateOwnedPasswordQuality(
        PamManagedPasswordSlotActivationResult& result, std::string& error);

    // Journal-bound activation of the history pair as ONE logical mutation:
    // a single Prepared record and a single mutation id shared by both
    // active markers, both files snapshotted before, both written, both
    // fresh re-read and proven as a pair before the record becomes Applied.
    // A partial two-file state is never a success: any failure after the
    // first write restores the exact prior bytes of every touched file.
    bool activateOwnedPasswordHistory(
        const ManagedPwhistorySlotOptions& options,
        PamManagedPasswordSlotActivationResult& result, std::string& error);

    // Test-only deterministic fault-injection seams (production code must
    // never set them). slotIndex: 0 = quality or history-normal, 1 =
    // history-initial. A before-hook returning false aborts the write of
    // that slot BEFORE its mutation (previous slots may already be
    // committed); an after-hook returning false fails the post-write fresh
    // verification of that slot (the hook may also tamper with the file to
    // model an externally replaced target).
    using SlotFaultHook = std::function<bool(std::size_t slotIndex)>;
    void setBeforeSlotWriteHookForTests(SlotFaultHook hook);
    void setAfterSlotWriteHookForTests(SlotFaultHook hook);

private:
    bool ensureJournalOperational(std::string& error);
    bool ensureJournalReadable(std::string& error) const;
    bool journalMetadataMatches(
        const fic::rollback::MutationRecord& record, std::string& error) const;
    // Collects the single active journal record of this policy domain and
    // enforces the strict metadata preconditions (multiple active records
    // and provenance mismatches fail closed). Returns false with
    // record.status untouched when no active record exists.
    bool collectActiveRecord(
        bool& found, fic::rollback::MutationRecord& record,
        std::string& error);
    // Finds the record with the exact id and verifies the full metadata
    // match. binding reports the closest outcome for diagnostics.
    bool findBoundRecord(
        std::uint64_t id, PasswordSlotJournalBinding& binding,
        fic::rollback::MutationRecord& record, std::string& error) const;
    bool prepareRecord(fic::rollback::MutationId& id, std::string& error);
    bool discardPrepared(fic::rollback::MutationId id, std::string& error);
    bool completePrepared(fic::rollback::MutationId id, std::string& error);

    fic::rollback::UndoDisablePamCapability expectedUndo() const;
    std::vector<const ManagedPasswordSlotSpec*> domainSlots() const;

    bool captureSlot(
        const ManagedPasswordSlotSpec& spec, PamConfigFileSnapshot& snapshot,
        std::string& error) const;
    static bool inspectSnapshot(
        const ManagedPasswordSlotSpec& spec,
        const PamConfigFileSnapshot& snapshot,
        ManagedPasswordSlotInspection& inspection, std::string& error);
    // Fresh re-read from disk (never trusts in-memory content).
    bool freshInspection(
        const ManagedPasswordSlotSpec& spec,
        ManagedPasswordSlotInspection& inspection, std::string& error) const;
    // State-bound durability proof of an existing captured slot state.
    static bool proveSlotDurable(
        const PamConfigFileSnapshot& snapshot, std::string& error);

    bool writeSlot(
        const ManagedPasswordSlotSpec& spec, PamConfigFileSnapshot& snapshot,
        const std::string& content, std::size_t slotIndex, bool useHooks,
        std::string& error);
    // Exact in-process compensation: restore the exact prior bytes of every
    // snapshot that may have been committed (reverse order; rollback() is a
    // no-op for a snapshot that never committed).
    static bool compensateSnapshots(
        std::vector<PamConfigFileSnapshot>& snapshots,
        std::size_t attemptedCount, std::string& error);
    // Prepared compensation (crash-recovery model): neutralize only a slot
    // whose canonical Active marker carries the EXACT Prepared id. Neutral
    // slots are left untouched; Broken/foreign-id slots fail closed.
    bool neutralizeSlotForPreparedCompensation(
        const ManagedPasswordSlotSpec& spec,
        fic::rollback::MutationId preparedId, std::string& error);
    // Failure compensation for the fresh activation path: exact snapshot
    // rollback of every attempted slot plus Prepared discard when proven.
    void compensateFreshFailure(
        std::vector<PamConfigFileSnapshot>& snapshots,
        std::size_t attemptedCount, fic::rollback::MutationId id,
        PamManagedPasswordSlotActivationResult& result, std::string& error);
    bool finishQualityActivation(
        std::vector<PamConfigFileSnapshot>& snapshots,
        fic::rollback::MutationId id,
        PamManagedPasswordSlotActivationResult& result, std::string& error);
    bool finishHistoryActivation(
        const ManagedPwhistorySlotOptions& options,
        std::vector<PamConfigFileSnapshot>& snapshots,
        fic::rollback::MutationId id,
        PamManagedPasswordSlotActivationResult& result, std::string& error);
    // Prepared recovery for a Broken history pair: compensates ONLY an
    // exact crash-partial composition (one slot Active with the Prepared
    // id, the other Neutral), then discards the record. Everything else
    // fails closed.
    bool recoverBrokenHistoryPair(
        fic::rollback::MutationId preparedId, std::string& error);
    // Fresh history activation: pair snapshots, starting-state
    // classification, Prepared record, both writes, fresh pair proof.
    bool activateFreshHistory(
        const ManagedPwhistorySlotOptions& options,
        PamManagedPasswordSlotActivationResult& result, std::string& error);

    std::filesystem::path configDirectory_;
    fic::rollback::MutationJournal& journal_;
    PolicyRef policyRef_;
    PamManagedPasswordDomain domain_;
    SlotFaultHook beforeWriteHook_;
    SlotFaultHook afterWriteHook_;
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOT_WRITER_H
