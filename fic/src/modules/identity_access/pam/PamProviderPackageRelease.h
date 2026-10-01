#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_PACKAGE_RELEASE_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_PACKAGE_RELEASE_H

#include "modules/identity_access/pam/PamProviderRollback.h"

#include <functional>
#include <string>
#include <vector>

namespace fic::identity::pam {

// ---------------------------------------------------------------------------
// Step 7F: package-removal release of the MANAGED PROVIDER configuration
// domain (faillock/pwquality/pwhistory provider primaries). This is a
// SEPARATE state domain from the C2 password topology release
// (PamPasswordPackageRelease): the C2 domain owns the pam-auth-update
// topology and managed slots with its own compensation model, this domain
// owns the FIC managed blocks/wrappers in the shared provider primaries and
// the FIC-created container provenance. The two release helpers are called
// sequentially by the package maintainer scripts and never compensate for
// each other.
//
// Modes (same shape as the C2 helper):
//   Preflight — strictly read-only Stage A. Loads the journal, enumerates
//               every active managed provider entry/flag/container record,
//               validates each against the CURRENT platform identity,
//               trusted-reads and strictly parses every known provider
//               primary, proves every active record releasable, detects
//               orphan FIC markers/wrappers without active journal
//               provenance (fail closed) and validates container
//               provenance coherence. NO writes of any kind.
//   Release   — Stage B (after every FIC writer has been stopped): an
//               exclusive acquisition of the SHARED managed-provider
//               mutation lock (the same domain as apply/runtime rollback),
//               a FRESH full preflight (the Stage A snapshot is never
//               trusted), deterministic release of the active provider
//               records (configPath, policy, managedKey, record id),
//               container cleanup and an independent final proof.
//
// Journal semantics: every successfully released provider entry/flag record
// becomes RolledBack; a deleted container becomes RolledBack and a retained
// foreign container becomes Detached. Unrelated journal records are never
// touched and the journal file is never deleted.
//
// Failure semantics: the release is a MONOTONIC ownership release — records
// already released stay RolledBack, a failing record stays active and the
// package removal is blocked. Nothing is reconstructed for compensation
// (unlike the C2 release, which compensates toward the proven pre-release
// topology): a later retry continues with the remaining active records.
// ---------------------------------------------------------------------------
class PamProviderPackageRelease {
public:
    enum class Mode { Preflight, Release };

    struct Options {
        // Cross-process mutation serialization of the release stage. Empty
        // disables the lock (tests). PRODUCTION must pass the SAME shared
        // managed-provider lock path the daemon apply/rollback paths use
        // (<runtimeDir>/pam-provider-managed.lock).
        std::filesystem::path lockFilePath;
        std::string lockDebugLogPath;
        // Test-only fault seam passed through to the rollback backend
        // (production never sets it).
        std::function<bool()> simulateContainerJournalResolutionFailure;
    };

    struct Report {
        // Released provider records: "entry|flag <id> <policy>".
        std::vector<std::string> releasedRecords;
        // FIC-created containers conditionally deleted (config paths).
        std::vector<std::string> containersDeleted;
        // FIC-created containers detached with foreign content.
        std::vector<std::string> containersDetached;
        // Containers retained without provenance (pre-existing files).
        std::vector<std::string> containersRetained;
        bool changedSystemState = false;
    };

    // journal must outlive the release object and be usable (Healthy).
    PamProviderPackageRelease(fic::rollback::MutationJournal& journal,
                              fic::platform::PamPlatformConfig platform,
                              Options options);

    bool run(Mode mode, Report& report, std::string& error);

private:
    // Read-only eligibility proof shared by both modes.
    bool preflight(Report& report, std::string& error);
    // Releasability proof of one active flag record (pure primitives only).
    bool preflightFlagRecord(
        const fic::rollback::MutationRecord& record,
        const fic::rollback::UndoRemovePamProviderManagedFlag& flag,
        PamProviderBlockPlacementRequest placement, std::string& error);
    // Orphan FIC marker/wrapper detection over every known provider
    // primary + container provenance coherence (read-only, fail closed).
    bool preflightPhysicalState(std::string& error);

    fic::rollback::MutationJournal& journal_;
    fic::platform::PamPlatformConfig platform_;
    Options options_;
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_PACKAGE_RELEASE_H
