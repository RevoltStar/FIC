#ifndef SSHROLLBACK_H
#define SSHROLLBACK_H

#include "modules/net/ssh/SshRuntime.h"
#include "rollback/MutationRecord.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

// Options for the SSH rollback backend: shared main sshd_config location,
// service units and the executable resolver. The runner hook exists for unit
// tests; an empty runner falls back to VerifiedProcessExecutor. The
// beforeWrite hook is a deterministic test seam invoked right before the
// conditional atomic write (used to simulate concurrent external modification).
struct SshRollbackOptions {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> serviceUnits;
    const fic::platform::PlatformExecutableResolver* executables = nullptr;
    SshCommandRunner runner;
    std::function<void()> beforeWrite;
    // Deterministic test seam invoked right before the conditional
    // compensation write (simulates an external modification racing with the
    // restore attempt).
    std::function<void()> beforeRestore;
};

struct SshRollbackResult {
    bool ok = false;
    bool conflict = false;       // FIC-controlled state drifted; nothing was written
    bool nothingToDo = false;    // the mutation is already factually rolled back
    std::string message;
};

// Restores only the recorded FIC textual mutation of the main sshd_config
// global section. The current target-resource projection is matched as a
// whole against the recorded AFTER/BEFORE sequences: AFTER -> undo, BEFORE ->
// runtime reconciliation (validate + reload of the already rolled-back
// configuration; crash after the file undo but before the reload is resolved
// here) and only then NothingToDo, otherwise Conflict; nothing is written.
// The rollback is transactional relative to its own change: if validation or
// reload fails after the reverse write, the exact FIC-installed pre-rollback
// state is restored conditionally (the restore is refused when the file is
// no longer the FIC-installed state) and the mutation stays active.
// Match blocks and included files are never touched.
SshRollbackResult undoSshDirectiveMutation(
    const SshRollbackOptions& options,
    const fic::rollback::UndoRestoreSshDirective& undo);

// Outcome of a conditional compensation restore. installed means the
// replacement was published by rename(2) (the system already carries the
// restored content); durable means the replacement is additionally confirmed
// crash-durable by a successful parent directory fsync — installed !=
// durable. A proven compensation requires BOTH.
struct SshRestoreOutcome {
    bool installed = false;
    bool durable = false;
    // True when the restore was refused because the target is no longer the
    // exact expected FIC-installed state: an external modification was
    // preserved and nothing was replaced.
    bool preconditionFailed = false;
    // Present only when installed == true: the exact restored target state
    // (the durability-finishing anchor).
    std::optional<AtomicTargetState> installedState;
};

// Conditional content restore shared by apply-time and rollback-time
// compensation writes. The expectedTargetState must be the last proven
// FIC-installed state of the target (never a fresh capture): the replacement
// is performed only when the target still is exactly that state (identity,
// metadata, content), so an external modification made after the FIC write is
// never overwritten. Refuses symlinks, preserves existing file metadata.
// A non-durable restore (rename succeeded, parent directory fsync failed) is
// reported as installed=true / durable=false: the caller must finish the
// durability (see ensureSshConfigDurableIfCurrentState) before treating the
// compensation as proven.
SshRestoreOutcome restoreSshConfigContentIfCurrentState(
    const std::filesystem::path& path,
    const std::string& content,
    const AtomicTargetState& expectedTargetState,
    std::string& error);

// Confirms the crash-durability of an already installed FIC state: first
// re-proves that the target still is exactly the installed state (a mere
// directory fsync must never legitimize an externally replaced target), then
// fsyncs the parent directory. Returns false (fail closed) when the target
// drifted or the durability barrier fails.
bool ensureSshConfigDurableIfCurrentState(
    const std::filesystem::path& path,
    const AtomicTargetState& installedState,
    std::string& error);

#endif // SSHROLLBACK_H