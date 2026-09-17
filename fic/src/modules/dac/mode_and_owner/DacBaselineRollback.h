#ifndef FIC_DAC_BASELINE_ROLLBACK_H
#define FIC_DAC_BASELINE_ROLLBACK_H

#include "platform/PlatformProfile.h"

#include <string>

namespace fic::rollback {

// Platform-baseline rollback backend for the DAC hardening policies
// (DAC / Mode_and_Owner / systemcommandlock and
// DAC / Mode_and_Owner / blocking_user_access_to_system_files).
//
// Semantics (docs/rollback.md, "Platform-baseline rollback"):
//   apply   -> transition managed objects to rule.enforced metadata;
//   disable -> transition managed objects to rule.baseline metadata.
// The pre-FIC owner/group/mode is never used as a rollback target and is
// never stored in the mutation journal. All distribution differences live
// in the platform profile; this backend contains no distro switches.
struct DacBaselineRollbackOptions {
    // Ready-to-use platform DAC config (baseline source of truth).
    fic::platform::DacPlatformConfig platform;
};

// The undo action execution itself (undoDacBaselineMutation) is declared in
// rollback/RollbackExecutor.h next to MutationRollbackOutcome.

enum class DacBaselineOwnershipVerdict {
    Owned,      // enforced state is present: the state is eligible for a
                // legacy platform-baseline transition
    AtBaseline, // every managed object is missing or already at baseline
    Unproven    // state is not eligible for a legacy transition: fail closed
};

// Fail-safe eligibility check for a supported DAC policy without active
// journal records (legacy apply). The current state is only ELIGIBLE for a
// legacy platform-baseline transition (compatible with the enforced
// hardening envelope): the enforced state being present on at least one
// non-missing managed object while no object sits in a foreign (neither
// enforced nor baseline) state. This does not historically prove that FIC
// performed the change; it only proves the state is safe to transition to
// the platform profile baseline.
DacBaselineOwnershipVerdict checkDacBaselineOwnership(
    const DacBaselineRollbackOptions& options,
    const std::string& policyName,
    std::string& error);

} // namespace fic::rollback

#endif // FIC_DAC_BASELINE_ROLLBACK_H