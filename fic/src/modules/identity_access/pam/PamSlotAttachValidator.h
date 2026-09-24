#ifndef FIC_IDENTITY_ACCESS_PAM_SLOT_ATTACH_VALIDATOR_H
#define FIC_IDENTITY_ACCESS_PAM_SLOT_ATTACH_VALIDATOR_H

#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"

#include <filesystem>
#include <string>

namespace fic::identity::pam {

// Typed distinction of the two read-only password-slot validation phases
// (Step 5B). PreAttach proves the existing managed slots + journal state
// safe for a LATER package attach of the permanent password hooks; it must
// NOT require already-selected hooks or a generated attachment. Attached
// additionally requires the live-graph attachment proof.
enum class PamAttachmentValidationPhase {
    PreAttach,
    Attached
};

// Read-only pre-attach verdict for the permanent fic-faillock-hook-* PAM
// profiles (package infrastructure on pam-auth-update platforms).
struct PamSlotAttachVerdict {
    // true only when the existing /etc/pam.d/fic-faillock-* slot state is
    // PROVEN safe for attaching the permanent hooks to the live PAM graph:
    // either canonical neutral, or journal-bound FIC-owned active state
    // (exact mutation id, active status, PAM backend, capability, topology,
    // activation domain, policy identity, resource identity and physical
    // target strategy proven from a read-only witness-aware persistent
    // journal state).
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

// Step 4: read-only pre-attach validation for the permanent FIC password
// hook profiles (`fic-password-quality-hook`, `fic-password-history-hook`)
// on pam-auth-update platforms. Validates BOTH password capabilities
// (PasswordQuality + PasswordHistory) against the physical slot state, the
// journal provenance, the external distro pwquality topology and the
// effective Primary password stacks:
//
//   - every managed password slot must exist and be canonical neutral or
//     canonical Active with proven journal ownership (fail closed on
//     missing, broken, foreign or unproven state — decisions A/B/C/D);
//   - Rule I (external distro pwquality): "external present" = the distro
//     `pwquality` profile is selected in the pam-auth-update password
//     state file AND pam_pwquality.so occurs in the parsed Primary
//     password stack; at most one pam_pwquality.so may exist in the
//     Primary stack, and an external provider excludes an FIC-owned
//     active quality slot (XOR ownership);
//   - Rule G (use_authtok): history-only is Unsupported — when the FIC
//     history pair is active, a token producer (pam_pwquality.so, distro
//     or FIC) must exist in the Primary stack before the FIC history
//     include point;
//   - Rule J semantic checks: effective remember must be nonzero;
//     enforce_for_root is parsed strictly but both valid states are allowed;
//     conf-mode reads effective remember/enforce_for_root from pwhistory.conf
//     and requires canonical no-option slot bodies;
//   - Active domains require exact selected hooks, exactly one password
//     include of the normal managed slot, and exactly one provider whose
//     source is that slot. Live history-initial/foreign history fail closed;
//   - quality/history flow requirements are independent; history additionally
//     requires a successful quality producer before its use_authtok rule;
//   - Neutral requires Unbound or virgin (both journal and witness absent)
//     provenance. Virgin validation never bootstraps persistent state;
//   - every managed slot is read without following symlinks.
//
// Strictly read-only: this function never rewrites slot files, never
// creates or mutates the mutation journal (no bootstrap, no witness
// repair), never runs pam-auth-update. It only answers "safe to attach"
// or "unsafe / indeterminate".
//
// Returns true when the validation ran to a verdict (verdict.safeToAttach
// carries the decision; an unsafe verdict is NOT an error return). Returns
// false only when the validation could not be performed at all (error set);
// callers must fail closed in both the unsafe and the error case.
bool validatePamPasswordSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamSlotAttachVerdict& verdict,
    std::string& error);

// Step 5B: phase-typed overload of the password pre-attach validation.
// Semantics are identical to validatePamPasswordSlotAttach for PreAttach
// (the default for the legacy entry point). Attached additionally requires
// the live-graph proof: selected permanent hooks, exact managed includes,
// providers sourced from the managed slots and the Rule G/J topology.
// Strictly read-only in both phases.
bool validatePamPasswordSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamAttachmentValidationPhase phase,
    PamSlotAttachVerdict& verdict,
    std::string& error);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_SLOT_ATTACH_VALIDATOR_H
