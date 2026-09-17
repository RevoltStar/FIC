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
    DeviceControl
};

// Typed undo actions. Each payload carries everything the rollback executor
// needs to undo the mutation without calling Policy::rollback().
struct UndoRemoveManagedSetting {
    std::string key;          // managed key (canonical sysctl key, sudoers Defaults key)
    std::string appliedValue; // value/line FIC last applied; drift fingerprint
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

using UndoPayload = std::variant<
    UndoRemoveManagedSetting,
    UndoRemoveSshManagedPolicy,
    UndoRemoveFirewallPolicy,
    UndoDisableDeviceFeature>;

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
