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
    bool nothingToDo = false; // ownership already released
    std::string message;
};

// Rolls back one SSSD policy mutation under the ownership-release model:
// removes ONLY the FIC-owned managed setting identified by the journal
// payload (section, option, appliedValue drift fingerprint) from the
// FIC-owned drop-in. The foreign /etc/sssd/sssd.conf and all foreign
// snippets are never modified, and no previous foreign value is ever
// restored or stored — after the FIC override is released, the previous
// foreign value becomes effective naturally.
//
// Classification against the CURRENT FIC-owned drop-in:
//   * the target option is absent — ownership already released:
//     NothingToDo (the foreign topology is not restarted);
//   * the drop-in is unsafe/malformed or the option carries another
//     value — drift: Conflict, the file is never touched;
//   * the option equals appliedValue — the option line is removed through
//     an atomic CAS write; a drop-in that becomes semantically empty is
//     removed entirely (CAS-verified unlink). Afterwards the SSSD topology
//     is re-read, an active SSSD service is restarted and verified, and
//     only then the rollback succeeds.
SssdRollbackResult undoSssdManagedSetting(
    const SssdRollbackOptions& options,
    const fic::rollback::UndoRemoveSssdManagedSetting& undo);

#endif // FIC_IDENTITY_ACCESS_SSSD_ROLLBACK_H