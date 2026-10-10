#ifndef FIC_ROLLBACK_MUTATION_RECORD_H
#define FIC_ROLLBACK_MUTATION_RECORD_H

#include <fic/policy/PolicyDependency.h>
#include <modules/dac/sudo/SudoersDisabledWrapper.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace fic::rollback {

using MutationId = std::uint64_t;

// Persistent lifecycle of one executed FIC mutation.
// Prepared is committed before the backend touches the system, so a crash
// between the system mutation and the commit still leaves undo provenance.
enum class MutationStatus {
    Prepared,
    Applied,
    RolledBack,
    RollbackFailed,
    Detached
};

enum class MutationBackend {
    Sysctl,
    Sudo,
    Ssh,
    Firewall,
    DeviceControl,
    Grub,
    Sssd,
    Kerberos,
    Pam,
    UserCreation,
    IdentityLoginDefs
};

// Typed undo actions. Each payload carries everything the rollback executor
// needs to undo the mutation without calling Policy::rollback().
struct UndoRemoveManagedSetting {
    std::string key;          // managed key (canonical sysctl key, sudoers Defaults key)
    std::string appliedValue; // value/line FIC last applied; drift fingerprint
};

// GRUB ownership-release payload. The record proves ONLY that FIC owns the
// managed setting (key, appliedValue); the storage location (Debian/Ubuntu
// owned drop-in vs ALT shared-defaults EOF managed block) is derived from
// the CURRENT platform profile at rollback time and is never journaled. No
// previous foreign value, no whole-file snapshot: rollback releases the FIC
// override, it never reconstructs pre-FIC state.
struct UndoRemoveGrubManagedSetting {
    std::string key;          // FIC-supported GRUB key (GRUB_TIMEOUT, ...)
    std::string appliedValue; // value FIC last applied; drift fingerprint
};

// Explicit FIC ownership payload for SSH rollback. The persistent rollback
// state lives in the FIC markers of the main sshd_config itself (managed
// block + disabled-line wrappers); the journal record only carries the
// policy reference, the exact applied line content (ownership proof against
// manual edits of the FIC block) and the provenance ids of the disabled
// blocks FIC created for this mutation. No reverse delta and no historical
// file content is recorded; old SSH payloads are not migrated.
struct UndoRemoveSshManagedPolicy {
    std::string policyName;   // FIC policy name (e.g. ssh_root_login)
    std::string directive;    // normalized sshd directive keyword
    std::string appliedValue; // expected content of the managed directive line
    // mutation ids of the FIC_DISABLED blocks created by this mutation. The
    // payload is a proof of permission (rollback may unwrap the wrappers
    // that still exist), NOT a backup manifest: wrappers that disappeared
    // externally are treated as already released and are never
    // reconstructed.
    std::vector<std::string> disabledMutationIds;
};

// Explicit FIC ownership payload for the SUDO scoped-Defaults blocker
// (sudo_disable_scoped_defaults). The persistent ownership state lives in the
// FIC_SUDO_DISABLED wrappers inside the FOREIGN sudoers files themselves; this
// record carries only the policy identity and the provenance ids FIC created,
// which is a proof of PERMISSION to unwrap those wrappers — NOT a backup and
// NOT a file snapshot. The original entry bytes are stored byte-exact inside
// the wrappers, never in the journal, so rollback never reconstructs
// historical configuration and never re-creates a wrapper that disappeared
// externally.
// The proof type is owned by the SUDO backend component and REUSED here so the
// persisted record and the physical wrapper model can never drift apart into
// two incompatible shapes.
using SudoScopedDefaultsWrapperProof = fic::sudoers::SudoScopedDefaultsWrapperProof;

// Ownership provenance for the SUDO scoped-Defaults blocker
// (sudo_disable_scoped_defaults).
//
// The persistent ownership state lives in the FIC_SUDO_DISABLED wrappers inside
// the FOREIGN sudoers files themselves; this record carries ONLY provenance:
//   * each proof names a wrapper FIC created AND carries a SHA-256 fingerprint
//     of the exact bytes FIC suppressed inside it. Rollback re-computes that
//     fingerprint from the live file and refuses on any mismatch, so FIC can
//     never unwrap a body edited after FIC wrapped it.
//   * the suppressed bytes are NEVER stored here and no whole-file snapshot is
//     taken: this is not a backup.
//   * targetProofs is the ownership set of the CURRENT target state;
//     previousProofs is the ownership FIC released when the transition was
//     prepared. A repeated reconciliation grows targetProofs and moves the old
//     set into previousProofs, so a previously created wrapper never loses its
//     journal permission.
struct UndoReleaseSudoScopedDefaults {
    std::string policyName;
    std::vector<SudoScopedDefaultsWrapperProof> previousProofs;
    std::vector<SudoScopedDefaultsWrapperProof> targetProofs;
};

enum class UserCreationConfigKind { UseraddDefaults, LoginDefs, Adduser };

struct UserCreationManagedAssignment {
    std::string key;
    std::string appliedLine;
    bool operator==(const UserCreationManagedAssignment& other) const {
        return key == other.key && appliedLine == other.appliedLine;
    }
};

// Ownership-release provenance for one USER_CREATION policy sub-block. It
// intentionally contains no foreign line/value and no file snapshot.
struct UndoRemoveUserCreationManagedPolicy {
    std::string policyName;
    UserCreationConfigKind configKind = UserCreationConfigKind::UseraddDefaults;
    std::string configPath;
    std::vector<UserCreationManagedAssignment> appliedAssignments;
    // Non-empty only while a Prepared in-place refresh A -> B is unresolved.
    std::vector<UserCreationManagedAssignment> previousAppliedAssignments;
};

// Shared /etc/login.defs ownership-release provenance (one FIC container
// shared by USER_CREATION and PASSWORD_AGING scalar policies). The record
// proves ONLY that FIC owns ONE managed assignment (key, exact applied
// line); rollback releases the FIC sub-block — it never restores a foreign
// value or any pre-FIC state. previousAppliedLine carries the durable
// previous→target transition of an in-place refresh (crash-safe ownership
// recovery): empty = fresh create.
struct UndoRemoveIdentityLoginDefsManagedPolicy {
    std::string policyName; // FIC policy identity (physical sub-block marker)
    std::string configPath; // managed login.defs resource
    std::string key;        // managed login.defs key (PASS_MIN_DAYS, ...)
    std::string appliedLine;         // exact canonical owned line "KEY value"
    std::string previousAppliedLine; // empty = fresh create
};

struct UndoRemoveFirewallPolicy {
    std::string policyName;   // FIC-managed nftables policy table
};

struct UndoDisableDeviceFeature {
    std::string feature;      // DC category-level desired state feature
};

// SSSD ownership-release payload for the FIC-owned drop-in
// (/etc/sssd/conf.d/zzzz-fic.conf). The record proves ONLY that FIC owns the
// managed setting (section, option, appliedValue); the foreign
// /etc/sssd/sssd.conf is never read into the payload and never restored:
// rollback releases the FIC override and the previous foreign value becomes
// effective naturally. No previous foreign value, no whole-file snapshot.
struct UndoRemoveSssdManagedSetting {
    std::string section;      // SSSD section (e.g. pam)
    std::string option;       // SSSD option (e.g. offline_credentials_expiration)
    std::string appliedValue; // value FIC last applied; drift fingerprint
};

// Kerberos reversible structured edit payload for a scalar relation of the
// root /etc/krb5.conf (foreign main config — no FIC-owned drop-in). The
// payload stores the EXACT pre-FIC before-state of the single target
// relation: the precise raw line (indentation, key-final/value-final '*'
// markers included) or the fact that the relation (or its whole section) was
// missing. No snapshot of the whole krb5.conf is ever stored; rollback is an
// inverse delta against the recorded target before-state.
enum class KerberosBeforeKind {
    Missing,
    Present
};

struct UndoRestoreKerberosScalar {
    std::string section;      // root profile section (e.g. libdefaults)
    std::string relation;     // relation name (e.g. ticket_lifetime)
    std::string appliedValue; // native applied value; drift fingerprint
    KerberosBeforeKind beforeKind = KerberosBeforeKind::Missing;
    // Exact pre-FIC line content; meaningful ONLY for Present. Includes the
    // original indentation and key/value '*' markers.
    std::string beforeRawLine;
    // Whether the section existed in the root profile before FIC touched it.
    // When false (and the relation was Missing) rollback may remove the
    // section header FIC created — but only while it is provably empty.
    bool sectionExistedBefore = false;
};

// PAM activation provenance, never a snapshot of PAM configuration. The
// identifiers form the complete FIC-owned selection domain for this
// capability (including all supported faillock strategies).
enum class PamTopologyKind { PamAuthUpdate, AltTcbManaged };
struct UndoDisablePamCapability {
    std::string capability;
    PamTopologyKind topology = PamTopologyKind::PamAuthUpdate;
    std::vector<std::string> activationIdentifiers;
    // Set before reusing an already Applied record. Crash recovery may
    // discard Prepared+Disabled only for a genuinely fresh mutation.
    bool hadAppliedProvenance = false;
    // Persisted transaction identity for a strategy change. Recovery must
    // resolve this BEFORE consulting the possibly changed policy value.
    std::optional<std::string> previousStrategy;
    std::optional<std::string> targetStrategy;
    std::string previousError;
};

// Requested placement contract of the FIC managed block inside a shared
// PAM provider configuration (Step 7A). Placement is an ownership-release
// contract, not stored history: the CURRENT effective placement is always
// re-proved from the physical file.
enum class PamProviderBlockPlacementContract { Beginning, End };

// Durable container-level FIC ownership record for a shared PAM provider
// primary configuration file (Step 7A). The record proves ONLY that FIC
// created the previously ABSENT container file after an explicitly proven
// safe-creation decision; it is completely independent of the lifecycle of
// the entry record that happened to trigger the creation: losing the
// creator entry (its rollback, detach or refresh) must never invalidate the
// container provenance. This is the only accepted proof for unlinking the
// container after the last FIC entry is released; a pre-existing file is
// never proven by this payload (fail closed on lost or corrupt provenance).
struct UndoOwnPamProviderContainer {
    std::string providerName; // PAM provider identity (physical block marker)
    std::string configPath;   // primary provider configuration resource
};

// PAM shared provider configuration ownership-release payload (Step 7A).
// The record proves ONLY FIC ownership of ONE managed entry inside the FIC
// managed block: the physical entry must carry this record's id as its
// physical mutation id (ABA protection), the exact policy identity, the
// exact canonical applied body and the correct provider identity. No
// previous foreign value, no whole-file snapshot, no foreign block copy:
// rollback releases the FIC entry, it never reconstructs pre-FIC state.
// previousAppliedBody carries the durable previous→target FIC-owned
// transition of an in-place refresh (crash-safe ownership recovery):
// empty = fresh create; non-empty = the exact previous canonical body of
// the SAME managed key that was FIC-owned immediately before this
// transition (recovery: previous present → continue; target present →
// adopt/complete; neither → fail closed).
struct UndoRemovePamProviderManagedEntry {
    std::string policyName;   // FIC policy identity (physical entry marker)
    std::string providerName; // PAM provider identity (physical block marker)
    std::string configPath;   // primary provider configuration resource
    std::string managedKey;   // managed key inside the canonical body
    std::string appliedBody;  // provider-specific canonical assignment body
    std::string previousAppliedBody; // empty = fresh create
    PamProviderBlockPlacementContract placement =
        PamProviderBlockPlacementContract::End;
};

// PAM shared provider configuration set-only FLAG ownership-release payload
// (Step 7E). The record proves ONLY FIC ownership of ONE managed set-only
// flag entry (bare enabled key / disabled sentinel) plus the PERMISSION to
// unwrap the suppression wrappers it lists — it is PROVENANCE, never a
// backup: no foreign line, no historical config content and no whole-file
// snapshot is ever stored. The embedded foreign lines live byte-exact
// inside the provider primary itself (inside the FIC suppression wrappers);
// rollback (Step 7F) removes the exact managed flag entry and unwraps only
// the CURRENTLY EXISTING wrappers proven by these suppression ids; a
// missing wrapper is an externally released subset and is NEVER
// reconstructed.
//
// appliedEnabled — the target flag state of the record;
// previousAppliedEnabled — nullopt = fresh transition (no previous FIC
// owned state); a value = refresh of the previous→target transition (the
// bool may legitimately be EQUAL for a false→false provenance refresh that
// only grows the suppression set);
// suppressionIds — the FIC-owned wrapper provenance of the TARGET state
// (always empty for an enabled target: an enabled flag never owns
// wrappers);
// previousSuppressionIds — the provenance of the PREVIOUS state (empty for
// a fresh transition).
struct UndoRemovePamProviderManagedFlag {
    std::string policyName;   // FIC policy identity (physical entry marker)
    std::string providerName; // PAM provider identity (physical block marker)
    std::string configPath;   // primary provider configuration resource
    std::string managedKey;   // managed set-only key
    bool appliedEnabled = false;
    std::optional<bool> previousAppliedEnabled;
    PamProviderBlockPlacementContract placement =
        PamProviderBlockPlacementContract::End;
    std::vector<std::string> suppressionIds;
    std::vector<std::string> previousSuppressionIds;
};

using UndoPayload = std::variant<
    UndoRemoveManagedSetting,
    UndoReleaseSudoScopedDefaults,
    UndoRemoveSshManagedPolicy,
    UndoRemoveUserCreationManagedPolicy,
    UndoRemoveFirewallPolicy,
    UndoDisableDeviceFeature,
    UndoRemoveGrubManagedSetting,
    UndoRemoveSssdManagedSetting,
    UndoRestoreKerberosScalar,
    UndoDisablePamCapability,
    UndoRemovePamProviderManagedEntry,
    UndoRemovePamProviderManagedFlag,
    UndoOwnPamProviderContainer,
    UndoRemoveIdentityLoginDefsManagedPolicy>;

struct UndoAction {
    MutationBackend backend = MutationBackend::Sysctl;
    UndoPayload payload;
};

struct MutationRecord {
    MutationId id = 0;
    PolicyRef policy;
    std::string resource;
    UndoAction undo;
    MutationStatus status = MutationStatus::Prepared;
    std::int64_t createdAtEpoch = 0;
    std::int64_t updatedAtEpoch = 0;
    std::string error;

    bool isActive() const {
        return status == MutationStatus::Prepared ||
               status == MutationStatus::Applied ||
               status == MutationStatus::RollbackFailed;
    }
};

std::string mutationStatusToString(MutationStatus status);
bool mutationStatusFromString(const std::string& value, MutationStatus& status);
std::string mutationBackendToString(MutationBackend backend);
bool mutationBackendFromString(const std::string& value, MutationBackend& backend);
std::string undoActionTypeName(const UndoAction& action);

} // namespace fic::rollback

#endif // FIC_ROLLBACK_MUTATION_RECORD_H
