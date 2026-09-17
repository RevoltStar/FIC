#ifndef SSHCONFIGTRANSACTION_H
#define SSHCONFIGTRANSACTION_H

#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshRuntime.h"

#include <functional>
#include <string>

struct SshConfigTransactionHooks {
    // Deterministic test seam invoked right before the conditional atomic
    // write (simulates concurrent external modification).
    std::function<void()> beforeWrite;
    // Deterministic test seam invoked right before the compensation restore
    // (simulates an external modification racing with the restore).
    std::function<void()> beforeRestore;
};

struct SshConfigTransactionResult {
    bool ok = false;
    bool conflict = false;    // concurrent external change; nothing was written
    bool nothingToDo = false; // caller-specific; set by the caller, not here
    std::string message;
};

// Shared conditional transaction over the main sshd_config used by both the
// policy apply path and the rollback backend:
//
//   plan (in-memory edit of the loaded snapshot) ->
//   conditional atomic write (optimistic precondition, reject symlink,
//   metadata preservation) -> durability confirmation ->
//   postcondition verification (persistent content + sshd -t/-T) ->
//   reload when the SSH service is active ->
//   on any post-install failure: conditional compensation restore of the
//   exact pre-attempt snapshot, its durability, validation and reload.
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