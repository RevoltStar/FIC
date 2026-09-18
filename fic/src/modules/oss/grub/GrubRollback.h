#ifndef FIC_OSS_GRUB_ROLLBACK_H
#define FIC_OSS_GRUB_ROLLBACK_H

#include "modules/oss/grub/GrubConfiguration.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationRecord.h"

#include <filesystem>
#include <functional>
#include <vector>

// Options for the GRUB rollback backend. The topology (Debian/Ubuntu owned
// drop-in vs ALT shared defaults EOF managed block) comes from the CURRENT
// platform profile — never from the journal payload. The runner hook exists
// for unit tests; an empty runner falls back to VerifiedProcessExecutor.
struct GrubRollbackOptions {
    fic::platform::GrubPlatformConfig platform;
    const fic::platform::PlatformExecutableResolver* executables = nullptr;
    bool enforceOwnership = true;
    GrubCommandRunner runner;
};

struct GrubRollbackResult {
    bool ok = false;
    bool conflict = false;    // FIC-owned state drifted; nothing was written
    bool nothingToDo = false; // ownership already released (rebuild performed)
    std::string message;
    std::vector<std::string> diagnostics;
};

// Rolls back one GRUB policy mutation under the ownership-release model:
// removes ONLY the FIC-owned managed setting identified by the journal
// payload (key + appliedValue drift fingerprint) from the FIC-owned
// artifact of the current topology — the Debian/Ubuntu owned drop-in
// zzzz-fic.cfg or the FIC managed block at the EOF of the ALT shared
// defaults — and then rebuilds grub.cfg. No previous foreign value is ever
// restored and no whole-file snapshot is stored or used.
//
// Semantics shared by both topologies:
//   * managed key missing (or the whole FIC artifact is gone) — the
//     ownership is already released: rebuild is STILL performed, then
//     NothingToDo (crash-after-source-rollback invariant);
//   * managed key present with another value — Conflict, the source is
//     never touched;
//   * key == appliedValue — the key is removed (an empty managed artifact
//     is removed entirely), the removal is written through an atomic CAS
//     write against the captured pre-rollback state, proven after the
//     write, and only after a SUCCESSFUL rebuild the rollback succeeds;
//   * rebuild failure — conditional compensation restores the exact
//     pre-rollback FIC-owned state (allowed only while the target still IS
//     the rollback-installed state); on concurrent external drift the
//     external state is never overwritten. The journal record stays active.
GrubRollbackResult undoGrubManagedSetting(
    const GrubRollbackOptions& options,
    const fic::rollback::UndoRemoveGrubManagedSetting& undo);

#endif // FIC_OSS_GRUB_ROLLBACK_H
