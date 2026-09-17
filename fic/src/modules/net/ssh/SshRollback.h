#ifndef SSHROLLBACK_H
#define SSHROLLBACK_H

#include "modules/net/ssh/SshRuntime.h"
#include "rollback/MutationRecord.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// Options for the SSH rollback backend: shared main sshd_config location,
// service units and the executable resolver. The runner hook exists for unit
// tests; an empty runner falls back to VerifiedProcessExecutor. The
// beforeWrite / beforeRestore hooks are deterministic test seams.
struct SshRollbackOptions {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> serviceUnits;
    const fic::platform::PlatformExecutableResolver* executables = nullptr;
    SshCommandRunner runner;
    std::function<void()> beforeWrite;
    std::function<void()> beforeRestore;
};

struct SshRollbackResult {
    bool ok = false;
    bool conflict = false;       // FIC-controlled state drifted; nothing was written
    bool nothingToDo = false;    // the mutation is already factually rolled back
    std::string message;
};

// Rolls back one SSH policy mutation under the explicit FIC ownership model:
// removes the managed sub-block of the policy (ownership proven by the
// markers AND the exact recorded directive line) and restores the exact
// original lines of the FIC_DISABLED blocks whose mutation ids are listed in
// the journal payload. Everything FIC does not explicitly own — user lines,
// other policies' blocks, Match sections, included files — is never touched.
// Crash-resilient: a partially performed disable (block already removed,
// wrappers still present) is completed; a disable of an already absent
// mutation is NothingToDo with runtime reconciliation. Uses the shared
// conditional transaction (conditional atomic write, durability, sshd -t/-T
// validation, reload, compensation restore on failure).
SshRollbackResult undoSshManagedPolicyMutation(
    const SshRollbackOptions& options,
    const fic::rollback::UndoRemoveSshManagedPolicy& undo);

// Outcome of a conditional compensation restore. installed means the
// replacement was published by rename(2); durable means the replacement is
// additionally confirmed crash-durable. A proven compensation requires BOTH.
struct SshRestoreOutcome {
    bool installed = false;
    bool durable = false;
    // True when the restore was refused because the target is no longer the
    // exact expected FIC-installed state: an external modification was
    // preserved and nothing was replaced.
    bool preconditionFailed = false;
    std::optional<AtomicTargetState> installedState;
};

// Conditional content restore shared by apply-time and rollback-time
// compensation writes. The expectedTargetState must be the last proven
// FIC-installed state of the target: the replacement is performed only when
// the target still is exactly that state (identity, metadata, content).
// Refuses symlinks, preserves existing file metadata.
SshRestoreOutcome restoreSshConfigContentIfCurrentState(
    const std::filesystem::path& path,
    const std::string& content,
    const AtomicTargetState& expectedTargetState,
    std::string& error);

// Confirms the crash-durability of an already installed FIC state: first
// re-proves that the target still is exactly the installed state, then
// fsyncs the parent directory. Returns false (fail closed) when the target
// drifted or the durability barrier fails.
bool ensureSshConfigDurableIfCurrentState(
    const std::filesystem::path& path,
    const AtomicTargetState& installedState,
    std::string& error);

#endif // SSHROLLBACK_H
