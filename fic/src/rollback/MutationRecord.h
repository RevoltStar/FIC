#ifndef FIC_ROLLBACK_MUTATION_RECORD_H
#define FIC_ROLLBACK_MUTATION_RECORD_H

#include <fic/policy/PolicyDependency.h>

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
    Dac,
    Grub,
    Sssd,
    Kerberos
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

struct UndoRemoveFirewallPolicy {
    std::string policyName;   // FIC-managed nftables policy table
};

struct UndoDisableDeviceFeature {
    std::string feature;      // DC category-level desired state feature
};

// Platform-baseline rollback payload for the DAC hardening policies
// (systemcommandlock, blocking_user_access_to_system_files). The journal
// record only proves that FIC performed a state-changing apply of this
// policy; the rollback target metadata is NOT stored here and no pre-FIC
// owner/group/mode is ever recorded. The platform profile baseline
// (FileAccessRule::baseline / TcbCredentialStorageConfig) is the single
// source of truth for the disable-time state transition.
struct UndoApplyDacPlatformBaseline {
    std::string policyName; // "systemcommandlock" or
                            // "blocking_user_access_to_system_files"
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

using UndoPayload = std::variant<
    UndoRemoveManagedSetting,
    UndoRemoveSshManagedPolicy,
    UndoRemoveFirewallPolicy,
    UndoDisableDeviceFeature,
    UndoApplyDacPlatformBaseline,
    UndoRemoveGrubManagedSetting,
    UndoRemoveSssdManagedSetting,
    UndoRestoreKerberosScalar>;

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
