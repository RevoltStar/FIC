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

// One recorded per-occurrence textual mutation of an sshd directive in the
// shared main sshd_config global section, performed by
// SshConfigFileHandler::setValue(). occurrenceIndex is the 0-based position
// of the directive among the global-section directives of the same keyword
// at the time the mutation was applied. Rollback never relies on absolute
// file line numbers: the current state is matched against the recorded
// BEFORE/AFTER representations textually, so unrelated mutations of other
// FIC SSH policies (different keywords) do not affect it.
struct SshDirectiveOccurrenceMutation {
    std::size_t occurrenceIndex = 0;        // semantic occurrence role/order
    std::optional<std::string> beforeLine;  // nullopt -> FIC inserted the line
    std::string afterLine;                  // line content after the FIC mutation
};

// Restores only the textual FIC mutation of the shared main sshd_config.
// The full file is never restored: Match blocks, included files and external
// edits outside the recorded occurrences are not FIC-owned state.
// Mutation-local drift model used by the rollback executor:
//   current state == recorded AFTER  -> the FIC mutation is still applied; undo
//   current state == recorded BEFORE -> already factually rolled back; NothingToDo
//   neither                          -> drift of the FIC-controlled state; Conflict
struct UndoRestoreSshDirective {
    std::string parameter;                      // normalized sshd directive keyword
    std::string appliedValue;                   // value FIC last applied
    std::vector<SshDirectiveOccurrenceMutation> occurrences;
};

struct UndoRemoveFirewallPolicy {
    std::string policyName;   // FIC-managed nftables policy table
};

struct UndoDisableDeviceFeature {
    std::string feature;      // DC category-level desired state feature
};

using UndoPayload = std::variant<
    UndoRemoveManagedSetting,
    UndoRestoreSshDirective,
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
