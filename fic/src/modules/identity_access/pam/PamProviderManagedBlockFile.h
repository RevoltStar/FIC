#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_BLOCK_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_BLOCK_FILE_H

#include "modules/identity_access/pam/PamProviderManagedBlock.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <string>

namespace fic::identity::pam {

// Typed container classification of a shared PAM provider primary
// configuration file. ABSENT is NOT EMPTY: a missing /etc/security/*.conf
// activates the PAM module's vendor fallback, so creating an empty primary
// file must be an explicitly proven, deliberate decision of the
// provider-specific caller (Step 7B-7D) — never a generic default.
enum class PamProviderContainerState {
    PreExisting, // primary file exists and passed the trusted-file checks
    Absent       // proven ENOENT through the trusted-file checks
};

// Caller-side typed decision for a proven-absent primary file. FailClosed
// refuses to create the container; CreateFicOwned marks the creation as an
// explicitly proven FIC-owned container.
enum class PamProviderAbsentContainerDecision {
    FailClosed,
    CreateFicOwned
};

struct PamProviderContainerReadResult {
    bool ok = false;
    PamProviderContainerState state = PamProviderContainerState::PreExisting;
    std::string content;
    // Captured exact target state (identity, metadata, content) of a
    // PreExisting file; valid ONLY when state == PreExisting. Passed to
    // writeMutation() as the snapshot precondition (stale-replacement
    // protection). AtomicFileWriter types live in the global namespace.
    ::AtomicTargetState snapshot;
    std::string error;
};

struct PamProviderContainerWriteResult {
    bool ok = false;
    // True only when this mutation CREATED the previously absent primary
    // file (FIC-owned container provenance for the release logic).
    bool containerCreated = false;
    // True when the snapshot precondition failed: the file changed between
    // readForMutation() and the write. NOTHING was replaced.
    bool stale = false;
    std::string error;
};

class PamProviderManagedBlockFile {
public:
    // Typed container proof + trusted read. Uses the project trusted-file
    // primitive (symlinks and non-regular objects refused). A proven ENOENT
    // is classified Absent; whether a container may then be created is the
    // caller's explicit typed decision (FailClosed refuses).
    static PamProviderContainerReadResult readForMutation(
        const std::filesystem::path& path,
        PamProviderAbsentContainerDecision absentDecision,
        std::string& error);

    // Snapshot-bound atomic install of the mutated content (temp file +
    // rename + directory fsync, file mode 0644, current euid/egid — the
    // same metadata policy as the existing PAM option file writers). For a
    // PreExisting file the captured snapshot is enforced as the replacement
    // precondition: a file that changed between read and write is detected
    // (stale=true) and never silently overwritten. For an absent container
    // the creation is exclusive (a concurrently appearing object refuses
    // the write).
    static PamProviderContainerWriteResult writeMutation(
        const std::filesystem::path& path,
        bool containerWasAbsent,
        const ::AtomicTargetState& snapshot,
        const std::string& newContent,
        std::string& error);
};

// Pure release-time decision for the FIC-CREATED container provenance
// (Step 7A foundation; the actual unlink belongs to the Step 7F release
// executor). The journal payload flag `containerCreated` of the record that
// created the absent primary file is the only accepted proof of FIC
// container creation; a pre-existing file is NEVER classified FIC-created.
//   * RemovableFicOwned    — container creation proven AND the content left
//                            after the block removal is empty: the file
//                            consists only of FIC serialization, so the
//                            release executor may unlink it;
//   * RetainForeignContent — foreign bytes exist: remove only the FIC
//                            block, keep the file;
//   * RetainUnproven       — container creation not proven (pre-existing
//                            file, or the provenance record is gone): a
//                            pre-existing foreign primary file is NEVER
//                            unlinked (fail closed).
enum class PamProviderContainerReleaseDecision {
    RemovableFicOwned,
    RetainForeignContent,
    RetainUnproven
};

PamProviderContainerReleaseDecision pamProviderContainerReleaseDecision(
    bool containerCreatedProven,
    const std::string& finalContentAfterBlockRemoval);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_BLOCK_FILE_H
