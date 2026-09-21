#ifndef FIC_IDENTITY_ACCESS_PAM_SLOT_ATTACH_VALIDATOR_H
#define FIC_IDENTITY_ACCESS_PAM_SLOT_ATTACH_VALIDATOR_H

#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"

#include <filesystem>
#include <string>

namespace fic::identity::pam {

// Read-only pre-attach verdict for the permanent fic-faillock-hook-* PAM
// profiles (package infrastructure on pam-auth-update platforms).
struct PamSlotAttachVerdict {
    // true only when the existing /etc/pam.d/fic-faillock-* slot state is
    // PROVEN safe for attaching the permanent hooks to the live PAM graph:
    // either canonical neutral, or journal-bound FIC-owned active state.
    // Everything else (malformed markers, modified bodies, partial or mixed
    // topologies, missing/mismatched journal provenance) stays unsafe and
    // fails closed.
    bool safeToAttach = false;
    // Human-readable explanation of the verdict.
    std::string detail;
};

// Package-side pre-attach validation used by maintainer scripts before
// `pam-auth-update --enable fic-faillock-hook-*`.
//
// Strictly read-only: this function never rewrites slot files, never
// creates or mutates the mutation journal (no bootstrap, no witness
// repair), never runs pam-auth-update, never rolls back or neutralizes
// anything. It only answers "safe to attach" or "unsafe / indeterminate".
//
// Returns true when the validation ran to a verdict (verdict.safeToAttach
// carries the decision; an unsafe verdict is NOT an error return). Returns
// false only when the validation could not be performed at all (error set);
// callers must fail closed in both the unsafe and the error case.
bool validatePamSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamSlotAttachVerdict& verdict,
    std::string& error);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_SLOT_ATTACH_VALIDATOR_H
