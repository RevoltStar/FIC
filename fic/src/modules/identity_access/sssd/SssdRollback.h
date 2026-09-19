#ifndef FIC_IDENTITY_ACCESS_SSSD_ROLLBACK_H
#define FIC_IDENTITY_ACCESS_SSSD_ROLLBACK_H

#include "modules/identity_access/sssd/SssdConfiguration.h"
#include "modules/identity_access/sssd/SssdRuntime.h"
#include "platform/PlatformExecutableResolver.h"
#include "rollback/MutationRecord.h"

#include <string>
#include <vector>

// Options for the SSSD rollback backend. The FIC-owned drop-in location and
// the snippet topology come from the CURRENT configuration options — never
// from the journal payload. The runner hook exists for unit tests; an empty
// runner falls back to VerifiedProcessExecutor.
struct SssdRollbackOptions {
    fic::identity::sssd::SssdConfigurationOptions configuration;
    std::vector<std::string> serviceUnits = {"sssd.service"};
    const fic::platform::PlatformExecutableResolver* executables = nullptr;
    fic::identity::sssd::SssdCommandRunner runner;
};

struct SssdRollbackResult {
    bool ok = false;
    bool conflict = false;    // FIC-owned state drifted; nothing was written
    bool nothingToDo = false; // the source undo was already completed
    std::string message;
};

// Restarts the ACTIVE SSSD service unit (if any) and verifies it comes back
// active. Inactive units are skipped: FIC never activates SSSD on its own.
// This is a mandatory postcondition of every active SSSD rollback lifecycle
// — including retries where the FIC-owned source state was already released
// by a previous (failed) rollback attempt.
bool reconcileSssdRuntime(
    const SssdRollbackOptions& options,
    std::string& error);

// Rolls back one SSSD policy mutation under the ownership-release model:
// removes ONLY the FIC-owned managed setting identified by the journal
// payload (section, option, appliedValue drift fingerprint) from the
// FIC-owned drop-in. The foreign /etc/sssd/sssd.conf and all foreign
// snippets are never modified, and no previous foreign value is ever
// restored or stored — after the FIC override is released, the previous
// foreign value becomes effective naturally.
//
// Classification against the CURRENT FIC-owned drop-in:
//   * the drop-in is unsafe/malformed or the option carries another
//     value — drift: Conflict, the file is never touched;
//   * the option equals appliedValue — the option line is removed through
//     an atomic CAS write; a drop-in that becomes semantically empty is
//     removed entirely (proof-bound rename-away removal). Afterwards the
//     runtime reconciliation below runs;
//   * the option is absent — the source undo was already completed by a
//     previous attempt; runtime reconciliation is still MANDATORY:
//     an active journal record means the rollback operation must finish
//     all of its postconditions (restart of an active SSSD + verification)
//     before the rollback may report Success/NothingToDo. A failed
//     reconciliation is RollbackFailed and the next retry re-attempts it;
//     the removed FIC drop-in is never re-created for a retry.
SssdRollbackResult undoSssdManagedSetting(
    const SssdRollbackOptions& options,
    const fic::rollback::UndoRemoveSssdManagedSetting& undo);

#endif // FIC_IDENTITY_ACCESS_SSSD_ROLLBACK_H