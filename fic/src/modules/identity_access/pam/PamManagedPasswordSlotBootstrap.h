#ifndef FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOT_BOOTSTRAP_H
#define FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOT_BOOTSTRAP_H

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>
#include <sys/types.h>
#include <vector>

namespace fic::identity::pam {

// Step 5B: safe bootstrap (existence provisioning) of the three FIC-owned
// managed password slots:
//
//   <configDirectory>/fic-password-quality           quality
//   <configDirectory>/fic-password-history           history-normal
//   <configDirectory>/fic-password-history-initial   history-initial
//
// OWNERSHIP BOUNDARY (package/bootstrap vs runtime policy):
//
//   package/bootstrap owns INFRASTRUCTURE EXISTENCE. The bootstrap
//   exclusively creates the exact canonical neutral slot file ONLY when
//   the exact slot path is genuinely absent. Existing regular files are
//   NEVER inspected, modified, chmod'ed, chown'ed, truncated, removed or
//   repaired — in every state (neutral, active, broken, foreign-looking,
//   empty). Structural validity belongs exclusively to the read-only
//   validatePamPasswordSlotAttach(..., PreAttach, ...) validator.
//
//   The runtime policy + mutation journal own the MANAGED STATE. The
//   bootstrap never creates a MutationJournal record, never creates the
//   witness, never resolves Prepared/Applied records, never modifies an
//   existing journal entry and never rolls anything back. A canonical
//   neutral slot created (or shipped) by the package/bootstrap stays
//   fully compatible with the VirginUnbound/Unbound pre-attach contract
//   of the validator.
//
// SAFETY CONTRACT (fail closed):
//
//   - the parent directory must exist and every component of the parent
//     chain must be a physical directory (symlink traversal refused);
//   - the exact slot path must be genuinely absent (lstat, no follow);
//   - creation is exclusive (atomic O_EXCL-equivalent publish, never a
//     truncating open and never a replacement): if any object occupies
//     the target at publish time, the write fails;
//   - a symlink occupying the slot path fails closed, including a
//     dangling symlink (the target is never followed);
//   - a directory, FIFO, socket or device file occupying the slot path
//     fails closed;
//   - the written bytes are the exact canonical neutral body; the file
//     mode/owner/group are enforced to the configured expectation;
//   - the write is durable (file fsync + parent directory fsync) and is
//     followed by a FRESH post-write verification (identity/type, exact
//     content, metadata) read back from the filesystem — only then is
//     the slot considered bootstrapped;
//   - a failure is reported with a diagnostic; physical changes that may
//     already have happened are never reported as "nothing changed"
//     (changedSystemState below).
//
// IDEMPOTENCE: a repeated run on a fully provisioned directory performs
// no write at all (every slot AlreadyPresent) and reports
// changedSystemState == false.
enum class PamManagedPasswordSlotBootstrapStatus {
    // The slot file was genuinely absent and this call exclusively
    // created the exact canonical neutral bytes with a fresh post-write
    // proof. Durability (file + parent directory fsync) is confirmed by
    // the underlying atomic writer before this outcome is reported as a
    // success; a creation whose durability confirmation failed is still
    // reported as Created (the file may physically exist) but fails the
    // overall run.
    Created,
    // The slot file already existed as a regular file and was left
    // byte-identical and metadata-identical. Any content state qualifies
    // (bootstrap owns existence only).
    AlreadyPresent
};

struct PamManagedPasswordSlotBootstrapOutcome {
    ManagedPasswordSlotRole role = ManagedPasswordSlotRole::Quality;
    std::filesystem::path path;
    PamManagedPasswordSlotBootstrapStatus status =
        PamManagedPasswordSlotBootstrapStatus::AlreadyPresent;
    // True when this slot failed (unsafe filesystem state or operational
    // error); error carries the diagnostic. failed==true never implies
    // "nothing happened": status may still be Created when a creation
    // was physically installed but its post-write proof failed.
    bool failed = false;
    std::string error;
};

struct PamManagedPasswordSlotBootstrapResult {
    // One outcome per managed slot, in canonical role order. On a
    // fail-fast stop, only the attempted prefix is recorded (the failed
    // slot itself included), so partial mutations are always visible.
    std::vector<PamManagedPasswordSlotBootstrapOutcome> slots;
    // changedSystemState pattern (monotonic, same model as the managed
    // slot activation writer): true iff the physical filesystem state
    // may differ from the entry state of this call — i.e. at least one
    // slot was reported Created, or a creation may have been installed
    // without a provable result. Never reset to false by later slots.
    bool changedSystemState = false;

    // True when every recorded slot finished without a failure.
    bool complete() const;
};

// Expected metadata of a freshly created canonical neutral slot. The
// production maintainer-script path uses the defaults (root:root 0644,
// matching the dpkg conffile staging); unit tests run unprivileged and
// pass their own identity.
struct PamManagedPasswordSlotBootstrapOptions {
    mode_t slotMode = 0644;
    uid_t slotOwner = 0;
    gid_t slotGroup = 0;
};

class PamManagedPasswordSlotBootstrap {
public:
    // Test-only deterministic seam (same model as
    // PamManagedPasswordSlotWriter): returning false simulates a failure
    // right before the exclusive creation of the slot with the given
    // index. Production code must never set the hook.
    using SlotFaultHook = std::function<bool(std::size_t slotIndex)>;
    void setBeforeSlotWriteHookForTests(SlotFaultHook hook);

    explicit PamManagedPasswordSlotBootstrap(
        std::filesystem::path configDirectory =
            std::filesystem::path("/etc/pam.d"),
        const PamManagedPasswordSlotBootstrapOptions& options =
            PamManagedPasswordSlotBootstrapOptions{});

    // Bootstraps all three managed password slots in canonical role
    // order. Returns true only when every slot finished without a
    // failure (each slot either proven-created or existing-regular).
    // Returns false on the first unsafe filesystem state or operational
    // error (fail-fast); result still records every attempted slot and
    // the honest changedSystemState accounting. The bootstrap never
    // retries, never removes a durability-confirmed slot for pseudo-
    // atomicity and never touches the mutation journal or witness.
    bool run(PamManagedPasswordSlotBootstrapResult& result,
             std::string& error);

private:
    bool bootstrapSlot(const ManagedPasswordSlotSpec& spec,
                       std::size_t slotIndex,
                       PamManagedPasswordSlotBootstrapOutcome& outcome,
                       std::string& error);
    // Exclusive durable creation of the exact canonical neutral bytes for
    // a genuinely absent slot path (callers must have proven absence and
    // the physical parent chain already).
    bool createAbsentSlot(const ManagedPasswordSlotSpec& spec,
                          const std::filesystem::path& path,
                          PamManagedPasswordSlotBootstrapOutcome& outcome,
                          std::string& error);

    std::filesystem::path configDirectory_;
    PamManagedPasswordSlotBootstrapOptions options_;
    SlotFaultHook beforeWriteHook_;
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOT_BOOTSTRAP_H