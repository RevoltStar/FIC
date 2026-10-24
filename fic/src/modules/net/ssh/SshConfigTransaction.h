#ifndef SSHCONFIGTRANSACTION_H
#define SSHCONFIGTRANSACTION_H

#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshRuntime.h"

#include <functional>
#include <string>

struct SshConfigTransactionHooks {
    bool offlineOwnershipRelease = false;
    // Deterministic test seam invoked right before the conditional atomic
    // write (simulates concurrent external modification).
    std::function<void()> beforeWrite;
    // Deterministic test seam invoked right before the compensation restore
    // (simulates an external modification racing with the restore).
    std::function<void()> beforeRestore;
    // Strict caller: readonly admission immediately before CAS, then verified
    // activation pinned to this exact installed state. Any post-save failure
    // retains bytes/provenance and NEVER invokes legacy compensation/reload.
    std::function<bool(std::string&)> verifiedAdmission;
    std::function<bool(const AtomicTargetState&,std::string&)> verifiedActivation;
};

enum class SshPersistentEffect { Unknown, NotInstalled, Installed, DurableInstalled };
enum class SshCompensationEffect { NotAttempted, RestoredDurably, RefusedByCAS, FailedOrUnknown };
// Legacy command acceptance is diagnostic evidence, NOT verified runtime resolution.
enum class SshRuntimeReconciliation { NotAttempted, LegacyAccepted, Verified, FailedOrUnknown };

#ifdef FIC_SSH_TRANSACTION_TESTING
// Test-only observation fault: never compiled into production fic.
void setSshSaveOutcomeHookForTests(std::function<void(FileHandler::FileSaveOutcome&)> hook);
#endif

struct SshConfigTransactionResult {
    bool ok = false;
    bool conflict = false;    // concurrent external change; nothing was written
    bool nothingToDo = false; // caller-specific; set by the caller, not here
    std::string message;
    // Facts about THIS write attempt, not a claim about the current pathname.
    SshPersistentEffect persistentEffect = SshPersistentEffect::Unknown;
    SshCompensationEffect compensation = SshCompensationEffect::NotAttempted;
    SshRuntimeReconciliation activation = SshRuntimeReconciliation::NotAttempted;
    SshRuntimeReconciliation restoredRuntime = SshRuntimeReconciliation::NotAttempted;
    std::optional<AtomicTargetState> installedTargetState;
    std::optional<AtomicTargetState> restoredTargetState;

    bool mayDiscardPrepared(bool freshRecord) const {
        // Stage 1 cannot prove runtime resolution through legacy reload. Even
        // a durable restore retains provenance after any installed/unknown write.
        return freshRecord && !ok && persistentEffect == SshPersistentEffect::NotInstalled &&
               !installedTargetState && !restoredTargetState &&
               compensation == SshCompensationEffect::NotAttempted &&
               activation == SshRuntimeReconciliation::NotAttempted &&
               restoredRuntime == SshRuntimeReconciliation::NotAttempted;
    }
};

// Shared conditional transaction over the main sshd_config used by both the
// policy apply path and the rollback backend:
//
//   plan (in-memory edit of the loaded snapshot) ->
//   conditional atomic write (optimistic precondition, reject symlink,
//   metadata preservation) -> durability confirmation ->
//   postcondition verification (persistent content + sshd -T) ->
//   reload when the SSH service is active ->
//   on any post-install failure: conditional compensation restore of the
//   exact pre-attempt snapshot, its durability, validation and legacy reload.
// Typed facts are separate from ok: even restored bytes + accepted reload do
// not authorize discarding ownership after an installed/unknown write.
//
// The planEdits callback mutates handler.lines(); the write is refused when
// the file changed after the snapshot was captured. verifyPostcondition must
// prove the policy-specific effective postcondition (a mere sshd -t parse
// acceptance is not enough); it runs only after a proven durable write.
SshConfigTransactionResult runSshConfigTransaction(
    SshConfigFileHandler& handler,
    const SshRuntime& runtime,
    const SshConfigTransactionHooks& hooks,
    const std::function<bool(std::string& error)>& planEdits,
    const std::function<bool(std::string& error)>& verifyPostcondition,
    const std::string& successMessage);

#endif // SSHCONFIGTRANSACTION_H