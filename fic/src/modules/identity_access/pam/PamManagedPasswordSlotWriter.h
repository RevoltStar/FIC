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
//
// Journal lifecycle gates (P1-1 hardening): operational mutation paths
// require usable() AND lifecycleInitialized(); a raw load() (usable without
// the witness-aware lifecycle) is never trusted operationally — the writer
// runs the witness-aware initializeOrLoad() first and re-checks both flags
// after it (a returned true alone is not accepted). Read-only proof paths
// never write: when the lifecycle is not yet proven on the journal object
// they run the strictly non-mutating validatePersistentStateReadOnly() and
// fail closed unless it proves the persistent (journal, witness) pair.
enum class PasswordSlotJournalBinding {
    // No journal record matches the physical marker id with exact metadata.
    Unbound,
    // A valid Applied record matches the physical marker exactly.
    MatchingApplied,
    // A valid Prepared record matches the physical marker exactly
    // (compensation scope; NOT ownership by itself).
    MatchingPrepared
};

// Journal-domain classification (P1-4 hardening): the state of the journal
// for one canonical password domain, independent of the physical slot
// bytes. A Neutral physical slot is provenance-safe (journal Unbound) only
// when the journal carries NO active record of that domain; any active
// Prepared or Applied record for a Neutral domain is stale provenance and
// fails closed (recovering it is the activation/recovery responsibility,
// never the read-only validator's).
enum class PasswordDomainJournalState {
    // Both journal and witness are absent; usable only for Neutral slots.
    VirginUnbound,
    // No active record of this domain exists.
    Unbound,
    // Exactly one active record of this domain exists and is Prepared.
    Prepared,
    // Exactly one active record of this domain exists and is Applied.
    Applied,
    // Multiple active records of this domain, a metadata mismatch against
    // the canonical domain identity, or a RollbackFailed record.
    Conflict,
    // The journal persistent state could not be proven read-only.
    Invalid
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

// Physical domain of the writer. The journal record payload, the canonical
// PolicyRef and the set of canonical slot files are ALL derived from this
// single domain (P1-2 security identity: there is no policy input at all,
// so a foreign policy/domain combination is not representable through the
// public API). Callers can never combine a foreign policy name with
// foreign slot files (the writer always resolves the canonical specs
// through PamManagedPasswordSlots and never accepts externally constructed
// slot specs for persistent writes).
enum class PamManagedPasswordDomain {
    Quality,
    History
};

struct PamManagedPasswordSlotActivationResult {
    bool success = false;
    // True only when physical disk bytes were mutated by this top-level
    // call RELATIVE TO THE ENTRY STATE and not fully compensated. The
    // accounting covers the WHOLE call (P1-4), including the physical
    // neutralization performed by the Prepared crash-partial recovery
    // phase: a recovery that neutralized an exact-id Active slot keeps
    // changedSystemState == true even when the subsequent fresh activation
    // fails and fully compensates its own writes. Never set merely because
    // a write was attempted.
    bool changedSystemState = false;
    // True only when the resulting state carries proven journal-bound
    // ownership (physical proof + matching Applied journal record).
    bool ownershipProven = false;
    // Journal mutation id of the resulting state (0 when none).
    //
    // Failure contract (C2 partial-state propagation): on a FAILED
    // activation, mutationId is nonzero ONLY when an exact outstanding C2
    // activation state remains physically/journal-present and MUST be
    // compensated by the caller through compensateC2ActiveSlot() (e.g. the
    // journal Prepared -> Applied commit failed after the physical slot
    // write already persisted). When the writer fully compensated the
    // failure internally (exact physical restore + Prepared discard), or
    // nothing was mutated at all, mutationId is 0. It is NOT a historical
    // "id once allocated" value.
    std::uint64_t mutationId = 0;
    std::string error;
};

class PamManagedPasswordSlotWriter {
public:
    // journal must outlive the writer. configDirectory is the (test
    // injectable) PAM configuration directory; slot paths are always the
    // canonical managed file names inside it. The canonical PolicyRef is
    // derived internally from the domain (canonicalPolicyRef): there is no
    // policy argument that could be mismatched with the domain (P1-2).
    PamManagedPasswordSlotWriter(
        std::filesystem::path configDirectory,
        fic::rollback::MutationJournal& journal,
        PamManagedPasswordDomain domain);

    // Canonical domain identity (P1-2 security identity, not caller
    // input): the only two PolicyRefs this component may ever journal or
    // prove. Exposed so callers/tests can use the canonical journal
    // identity without duplicating the mapping.
    static PolicyRef canonicalPolicyRef(PamManagedPasswordDomain domain);

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

    // Read-only journal-domain classification (P1-4 hardening): the state
    // of THE JOURNAL for one canonical password domain, independent of the
    // physical slot bytes. Never writes: uses the same strictly
    // non-mutating read-only persistent-state gate as the ownership proofs
    // (no bootstrap, no witness creation, no repair).
    //
    //   VirginUnbound — neither journal nor witness exists (no bootstrap);
    //   Unbound  — no active record exists for the canonical domain
    //              (Neutral provenance);
    //   Prepared — exactly one active record of this domain and it is
    //              Prepared (active Prepared provenance);
    //   Applied  — exactly one active record of this domain and it is
    //              Applied (active Applied provenance);
    //   Conflict — multiple active records of this domain, a record with
    //              metadata that does not match the canonical domain
    //              identity, or a RollbackFailed record (ambiguous or
    //              broken provenance; never select a record by chance);
    //   Invalid  — the journal persistent state itself could not be proven
    //              read-only (the caller must fail closed).
    //
    // For the History domain the canonical identity is the single dual-slot
    // domain (both history slots share one journal domain), so the pair
    // classification is domain-wide, not per physical slot.
    PasswordDomainJournalState inspectJournalBindingForDomain(
        std::uint64_t& mutationId, std::string& error) const;

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

    // Test-only deterministic seam of the journal Prepared -> Applied
    // completion (completePrepared). Returning false injects a journal
    // commit failure AFTER the physical slot write has already persisted,
    // exercising the caller-visible partial-state propagation. Production
    // code must never set this hook.
    using JournalCompletionFaultHook = std::function<bool()>;
    void setJournalCompletionFaultHookForTests(
        JournalCompletionFaultHook hook);
    // Test-only seam: injects a failure at the very top of
    // compensateC2ActiveSlot(). Production never installs this hook.
    using C2CompensationFaultHook = std::function<bool()>;
    void setC2CompensationFaultHookForTests(C2CompensationFaultHook hook);

private:
    bool ensureJournalOperational(std::string& error) const;
    bool ensureJournalReadable(std::string& error) const;
    bool journalMetadataMatches(
        const fic::rollback::MutationRecord& record, std::string& error) const;
    // Collects the single active journal record of this policy domain and
    // enforces the strict metadata preconditions (multiple active records
    // and provenance mismatches fail closed). Returns false with
    // record.status untouched when no active record exists.
    bool collectActiveRecord(
        bool& found, fic::rollback::MutationRecord& record,
        std::string& error) const;
    // Finds the record with the exact id and verifies the full metadata
    // match. binding reports the closest outcome for diagnostics.
    bool findBoundRecord(
        std::uint64_t id, PasswordSlotJournalBinding& binding,
        fic::rollback::MutationRecord& record, std::string& error) const;
    bool prepareRecord(fic::rollback::MutationId& id, std::string& error);
    bool prepareRecordWithIdentifier(
        const char* activationIdentifier, fic::rollback::MutationId& id,
        std::string& error);
    bool discardPrepared(fic::rollback::MutationId id, std::string& error);
    bool completePrepared(fic::rollback::MutationId id, std::string& error);

    // C2 role plumbing: the canonical slot spec, the role-specific journal
    // activation identifier and the role-bound metadata matcher. Role and
    // writer domain must agree (Quality role only on the Quality writer,
    // history roles only on the History writer) — mismatches fail closed.
    static bool c2RoleUsesDomain(
        ManagedPasswordSlotRole role, PamManagedPasswordDomain domain);
    static const ManagedPasswordSlotSpec& c2RoleSlot(
        ManagedPasswordSlotRole role);
    static const char* c2RoleActivationIdentifier(
        ManagedPasswordSlotRole role);
    static std::size_t c2RoleSlotIndex(ManagedPasswordSlotRole role);
    static fic::rollback::UndoDisablePamCapability expectedUndoWithIdentifier(
        PamManagedPasswordDomain domain, const char* activationIdentifier);
    bool journalMetadataMatchesRole(
        const fic::rollback::MutationRecord& record,
        ManagedPasswordSlotRole role, std::string& error) const;

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
    //
    // Physical-change accounting (P1-5): on every return, *changedSystemState
    // is true iff the physical bytes may differ from the entry state of this
    // call or an exact restoration could not be proven — even when the
    // helper itself returns false. The helper only ever ORs true into the
    // flag (monotonic); it never resets it. A successful return is NOT the
    // point at which a change becomes knowable: an installed write whose
    // rollback or post-write proof failed must still report the change.
    //
    // Same-snapshot ownership proof (P1-6): the exact Prepared-ID proof and
    // the conditional mutation share ONE PamConfigFileSnapshot (no second
    // capture between proof and write). A concurrent replacement after the
    // proof fails the transaction's expectedTargetState precondition before
    // any install; the snapshot then stays Captured, the foreign state is
    // never neutralized or rolled back, and — because no FIC write was
    // committed — changedSystemState stays false.
    bool neutralizeSlotForPreparedCompensation(
        const ManagedPasswordSlotSpec& spec,
        fic::rollback::MutationId preparedId, bool& changedSystemState,
        std::string& error);
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
    // fails closed. Reports physical-change accounting relative to the
    // entry state of the top-level activation call.
    bool recoverBrokenHistoryPair(
        fic::rollback::MutationId preparedId,
        PamManagedPasswordSlotActivationResult& result, std::string& error);
    // Fresh history activation: pair snapshots, starting-state
    // classification, Prepared record, both writes, fresh pair proof.
    bool activateFreshHistory(
        const ManagedPwhistorySlotOptions& options,
        PamManagedPasswordSlotActivationResult& result, std::string& error);

public:
    // ---- C2 per-identity lifecycle (activation-time FIC-owned hooks) ----
    //
    // Under C2 the two history variants are MUTUALLY EXCLUSIVE single-slot
    // identities: the history-consumer state keeps the history-normal slot
    // Active while the history-initial slot is Neutral, and the
    // history-initial state is the mirror image. The pair-level activation
    // API above (both slots Active with one shared id) is the legacy
    // dual-slot domain and is intentionally NOT used by C2 transitions.
    //
    // Journal provenance stays domain-bound (one canonical PolicyRef per
    // domain), but the undo payload carries the ROLE-SPECIFIC activation
    // identifier: fic-password-quality-hook, fic-password-history-hook or
    // fic-password-history-initial-hook. Physical ownership of one C2
    // identity is proven only by an Applied record whose payload carries
    // exactly that identity's identifier; a record with the other history
    // variant's identifier never proves this identity.

    // Read-only ownership proof for ONE C2 identity slot: the slot must be
    // canonical Active and its marker id must match a valid Applied record
    // of the canonical domain carrying the role-specific activation
    // identifier. Strictly non-mutating; fails closed otherwise.
    bool proveOwnedC2Slot(
        ManagedPasswordSlotRole role,
        PamManagedPasswordSlotOwnership& ownership, std::string& error) const;

    // Journal-bound activation of ONE C2 identity slot (Neutral -> Active):
    // one Prepared record (role-specific activation identifier payload),
    // one physical write of the exact canonical active bytes, fresh durable
    // re-read proof, then Applied. Idempotent when the slot is already
    // canonical Active with an exactly matching Applied record. Any other
    // entry state (Broken, Unavailable, foreign or foreign-id Active) fails
    // closed — ownership is never adopted and never repaired.
    bool activateC2Slot(
        ManagedPasswordSlotRole role,
        const ManagedPwhistorySlotOptions& options,
        PamManagedPasswordSlotActivationResult& result, std::string& error);

    // Journal-bound deactivation of ONE C2 identity slot (Active ->
    // Neutral): the slot must be canonical Active with a MatchingApplied
    // record whose payload carries the role-specific activation identifier
    // (exact C2 ownership). The neutral bytes are written through the same
    // CAS transaction model, proven fresh Neutral, and only then does the
    // Applied record become RolledBack. Any failure restores the exact
    // prior Active bytes and leaves the record Applied (changedSystemState
    // accounting is monotonic, same model as the compensation helper).
    bool deactivateC2Slot(
        ManagedPasswordSlotRole role,
        PamManagedPasswordSlotActivationResult& result, std::string& error);

    // Exact-id compensation primitive of the C2 transition executor:
    // neutralize a slot whose canonical Active marker carries the EXACT
    // record id. An Applied record becomes RolledBack after the neutral
    // state is proven fresh; a Prepared record is discarded. Foreign-id,
    // non-canonical and Neutral slots fail closed (Neutral is an incoherent
    // compensation target here: the caller's drift gate must have caught
    // it). changedSystemState follows the monotonic P1-5 contract.
    bool compensateC2ActiveSlot(
        ManagedPasswordSlotRole role, fic::rollback::MutationId id,
        bool& changedSystemState, std::string& error);

private:
    std::filesystem::path configDirectory_;
    fic::rollback::MutationJournal& journal_;
    // Canonical domain identity derived once from domain_ (P1-2): never
    // caller-provided, never mutated after construction.
    PolicyRef policyRef_;
    PamManagedPasswordDomain domain_;
    SlotFaultHook beforeWriteHook_;
    SlotFaultHook afterWriteHook_;
    JournalCompletionFaultHook journalCompletionHook_;
    C2CompensationFaultHook c2CompensationHook_;
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOT_WRITER_H
