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
class PolicyRegistry;
namespace fic::rollback {class MutationJournal;}

// Options for the SSH rollback backend: shared main sshd_config location,
// service units and the executable resolver. The runner hook exists for unit
// tests; an empty runner falls back to VerifiedProcessExecutor. The
// beforeWrite / beforeRestore hooks are deterministic test seams.
enum class SshOfflineReleaseProfile { None, UbuntuSocket, AltService };
enum class SshReleaseContext { PolicyDisable, Uninstall };
enum class SshReleaseDisposition { None, RuntimeVerified, ReleasedOffline, RecoveryRequired };
struct SshRollbackOptions {
    // Metadata enforcement for read-only unrecorded ownership inspection.
    // Production keeps true; isolated filesystem unit fixtures may opt out.
    bool enforceOwnership = true;
    SshOfflineReleaseProfile offlineRelease = SshOfflineReleaseProfile::None;
    std::filesystem::path configPath;
    std::filesystem::path includeBasePath;
    std::vector<std::string> serviceUnits;
    const fic::platform::PlatformExecutableResolver* executables = nullptr;
    SshCommandRunner runner;
    std::function<void()> beforeWrite;
    std::function<void()> beforeRestore;
    bool verifiedRelease=false;
    fic::rollback::MutationJournal* journal=nullptr;
    fic::rollback::MutationId mutationId=0;
    SshReleaseContext releaseContext=SshReleaseContext::PolicyDisable;
    std::function<bool(std::map<std::string,std::string>&,std::string&)> remainingRequestedState;
};

struct SshRollbackResult {
    bool ok = false;
    bool conflict = false;       // FIC-controlled state drifted; nothing was written
    bool nothingToDo = false;    // the mutation is already factually rolled back
    std::string message;
    SshReleaseDisposition disposition=SshReleaseDisposition::None;
};

// Rolls back one SSH policy mutation under the explicit FIC ownership model
// (ownership-release semantics): removes the managed sub-block of the policy
// (ownership proven by the markers AND the exact recorded directive line)
// and restores the exact original lines of the FIC_DISABLED blocks of the
// policy that still exist and whose mutation ids are proven by the journal
// payload. The payload is an ownership proof, not a backup manifest: owned
// artifacts that disappeared externally are treated as already released and
// are never reconstructed. Everything FIC does not explicitly own — user
// lines, other policies' blocks, Match sections, included files — is never
// touched. Crash-resilient: a partially performed disable (block already
// removed, wrappers still present) is completed; a mutation whose owned
// artifacts are all gone is NothingToDo with runtime reconciliation.
// Unknown, duplicated or manually modified existing FIC-owned artifacts are
// a Conflict: the file is never changed. Uses the shared conditional
// transaction (conditional atomic write, durability, sshd -t/-T validation,
// reload, compensation restore on failure).
SshRollbackResult undoSshManagedPolicyMutation(
    const SshRollbackOptions& options,
    const fic::rollback::UndoRemoveSshManagedPolicy& undo);
// Called ONLY after an explicit disable saved DISABLE and rebuilt its registry.
// Unknown Prepared is never resolved; only verified ReleasedAwaitingDisable.
bool acknowledgeSshPolicyDisable(const PolicyRef&,const PolicyRegistry&,std::string&);

#endif // SSHROLLBACK_H
