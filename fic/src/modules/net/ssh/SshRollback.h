#ifndef SSHROLLBACK_H
#define SSHROLLBACK_H

#include "modules/net/ssh/SshRuntime.h"
#include "rollback/MutationRecord.h"

#include <filesystem>
#include <string>
#include <vector>

// Options for the SSH rollback backend: shared main sshd_config location,
// service units and the executable resolver. The runner hook exists for unit
// tests; an empty runner falls back to VerifiedProcessExecutor.
struct SshRollbackOptions {
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> serviceUnits;
    const fic::platform::PlatformExecutableResolver* executables = nullptr;
    SshCommandRunner runner;
};

struct SshRollbackResult {
    bool ok = false;
    bool conflict = false; // global section drifted; nothing was written
    std::string message;
};

// Restores only the recorded FIC textual mutation of the main sshd_config
// global section. The rollback is transactional relative to its own change:
// if validation or reload fails after the reverse write, the pre-rollback
// content is restored (and reloaded when the service is active) and the
// mutation stays active. Match blocks and included files are never touched.
SshRollbackResult undoSshDirectiveMutation(
    const SshRollbackOptions& options,
    const fic::rollback::UndoRestoreSshDirective& undo);

// Atomic content restore helper shared by apply-time and rollback-time
// compensation writes (preserves existing file metadata, refuses symlinks).
bool restoreSshConfigContent(const std::filesystem::path& path,
                             const std::string& content,
                             std::string& error);

#endif // SSHROLLBACK_H