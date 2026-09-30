#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_SEMANTIC_VERIFIER_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_SEMANTIC_VERIFIER_H

#include "modules/identity_access/pam/PamProviderInspector.h"

namespace fic::identity::pam {

enum class PamProviderSemanticFailure {
    None,
    Broken,
    Ineffective
};

class PamProviderSemanticVerifier {
public:
    static bool verifyCapability(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        bool requireSecurityEnforcement,
        PamProviderSemanticFailure& failure,
        std::string& error);

    static bool verifyOption(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        const std::string& option,
        const std::string& expectedValue,
        std::string& error);

    static bool verifyFlag(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        const std::string& flag,
        bool expectedEnabled,
        const std::vector<std::string>& conflictingOptionsWhenDisabled,
        std::string& error);

    static bool canApplyOption(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        const std::string& option,
        const std::string& expectedValue,
        std::string& error);

    static bool canApplyFlag(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        const std::string& flag,
        bool expectedEnabled,
        const std::vector<std::string>& conflictingOptionsWhenDisabled,
        std::string& error);

    // Step 7E: managed-flag PRE-MUTATION preflight for the journal-backed
    // set-only flag executor (PamProviderManagedFlagExecutor). Unlike the
    // legacy preflight, this models the SUPPRESSION of foreign primary
    // occurrences: a foreign active flag line that FIC can safely wrap
    // never blocks a requested disabled state. Per provider:
    //   * PamPwquality — the existing prospective DropInsThenPrimary
    //     evaluator (primary same-key occurrences skipped, drop-ins
    //     evaluated as-is: a drop-in flag occurrence still makes false
    //     unreachable and fails closed);
    //   * PamPwhistory — the Step 7D argv invariants (whole-token icase
    //     flags, valued forms fail closed, duplicates fail closed, conf=
    //     contract) PLUS the new prospective first-match flag evaluator;
    //   * PamFaillock / Generic — the generic argv-only check (the caller
    //     additionally proves the primary conflicting directives through
    //     the provider-correct directive scanner).
    static bool canApplyManagedProviderFlag(
        const PamProviderInspection& inspection,
        const fic::platform::PamCapabilityConfig& capability,
        const std::string& flag,
        bool expectedEnabled,
        const std::vector<std::string>& conflictingOptionsWhenDisabled,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_SEMANTIC_VERIFIER_H
