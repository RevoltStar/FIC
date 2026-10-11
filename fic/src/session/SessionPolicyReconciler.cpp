#include "session/SessionPolicyReconciler.h"
#include "policy/execution/PolicyExecutionPlanner.h"
#include <fic/core/logging/Logger.h>
#include <algorithm>

namespace fic::session {
PolicyApplySummary reconcileSessionReadyPolicies(
    PolicyRegistry& registry, incident::IncidentController& controller,
    const ClassifiedGraphicalSession& eventSession,
    const SessionReconcileContext* context,
    const std::vector<ClassifiedGraphicalSession>& inventory,
    bool inventoryComplete, const std::string& inventoryError,
    const DesktopGlobalReconcileReport& globalReport) {
    PolicyExecutionRequest request;
    for (const auto capability : {PolicyCapability::SessionAware,
                                 PolicyCapability::SessionInventoryCompliance}) {
        if (capability == PolicyCapability::SessionAware && !context) continue;
        for (Policy* policy : registry.capabilityPolicies(capability))
            if (policy->isEnabled()) request.requestedRoots.push_back(
                {policy->moduleName,policy->submoduleName,policy->policyName});
    }
    const std::string reason = "session_ready session=" + eventSession.session.id +
        " uid=" + std::to_string(eventSession.session.uid) + " desktop=" +
        std::string(DesktopEnvironmentBackend::kindName(eventSession.desktop)) + " phase=policy_reconciliation";
    PolicyExecutionPlanner planner(registry, [&](const PolicyRef& owner, Policy& policy)
        -> std::optional<PolicyApplyResult> {
        bool success = false, warning = false;
        std::string diagnostic, phase;
        if (auto* compliance = dynamic_cast<SessionInventoryCompliancePolicy*>(&policy)) {
            phase = "inventory_compliance";
            success = inventoryComplete && compliance->evaluateSessionInventory(inventory,diagnostic);
            if (!inventoryComplete) diagnostic = "Cannot prove graphical inventory: " + inventoryError;
        } else if (auto* sessionAware = dynamic_cast<SessionAwarePolicy*>(&policy)) {
            if (!context) return std::nullopt;
            phase = "session_reconciliation";
            auto targetGlobal = globalReport.resultFor(owner,context->target.desktop);
            if (globalReport.phase == "checkpoint_commit") {
                const auto owned = globalReport.resultsFor(owner);
                const auto found = owned.find(context->target.desktop);
                if (found != owned.end()) targetGlobal = found->second;
            }
            const auto outcome = sessionAware->reconcileSession(*context,targetGlobal);
            success = outcome.successful();
            warning = outcome.status == SessionReconcileStatus::MandatoryGlobalRuntimeWarning;
            diagnostic = outcome.diagnostic;
            // Attribute by the contributor's validated owner map, augmented only
            // by this policy's own applicable MandatoryGlobal declarations. An
            // incomplete Stage A must not turn a known obligation into SUCCESS.
            auto globals = globalReport.resultsFor(owner);
            for (const auto desktop : {DesktopEnvironmentKind::Gnome, DesktopEnvironmentKind::Fly,
                                       DesktopEnvironmentKind::Kde, DesktopEnvironmentKind::Xfce,
                                       DesktopEnvironmentKind::Lxqt}) {
                std::string applicabilityError;
                if (sessionAware->enforcementMode(desktop) == EnforcementMode::MandatoryGlobal &&
                    sessionAware->sessionApplicability(desktop, applicabilityError) == SessionApplicability::Applicable)
                    globals[desktop].hasRequirement = true;
            }
            std::string globalFailures;
            for (const auto& [desktop, global] : globals) {
                if (!global.hasRequirement || global.verified) continue;
                if (!globalFailures.empty()) globalFailures += "; ";
                globalFailures += std::string(DesktopEnvironmentBackend::kindName(desktop)) +
                    " phase=" + globalReport.phase + ": " +
                    (global.diagnostic.empty() ?
                        (globalReport.stageADiagnostic.empty() ? "own mandatory global requirement not verified" :
                         "own mandatory global requirement not verified; checkpoint: " + globalReport.stageADiagnostic) : global.diagnostic);
            }
            for (const auto& release : globalReport.releaseFailures) {
                if (release.owner != owner) continue;
                if (!globalFailures.empty()) globalFailures += "; ";
                globalFailures += std::string(DesktopEnvironmentBackend::kindName(release.desktop)) +
                    " phase=" + release.phase + " resource=" + release.resource +
                    " mutation=" + std::to_string(release.mutation) + ": " + release.diagnostic;
            }
            if (!globalFailures.empty()) {
                // Session reconciliation has already run. Keep its independent
                // outcome explicitly; never rollback its successful settings.
                diagnostic = globalFailures + "; session_reconciliation " +
                    (success ? "SUCCESS" : "FAILED") +
                    (diagnostic.empty() ? "" : ": " + diagnostic);
                success = false;
                warning = false;
            }

        } else {
            const auto capabilities = policy.capabilities();
            if (std::find(capabilities.begin(),capabilities.end(),PolicyCapability::SessionAware) == capabilities.end() &&
                std::find(capabilities.begin(),capabilities.end(),PolicyCapability::SessionInventoryCompliance) == capabilities.end())
                return std::nullopt; // Scope/dependencies keep ordinary apply().
            phase = "capability_validation";
            diagnostic = "targeted policy capability has no implementation";
        }
        if (diagnostic.empty() && (!success || warning))
            diagnostic = warning ? "MandatoryGlobal runtime convergence is unverified"
                                 : "targeted policy failed without backend diagnostics";
        const std::string message = reason + " policy=" + formatPolicyRef(owner) +
            " phase=" + phase + (diagnostic.empty() ? "" : ": " + diagnostic);
        if (!success || warning) policy.log(message,warning ? logLevel::WARN : logLevel::ERROR);
        PolicyApplyResult result{owner.moduleName,owner.submoduleName,owner.policyName,
            success ? PolicyApplyStatus::Applied : PolicyApplyStatus::Failed,
            diagnostic.empty() ? "targeted policy succeeded" : diagnostic};
        result.ownApplyAttempted = true;
        result.failureOrigin = success ? PolicyFailureOrigin::None : PolicyFailureOrigin::OwnApplyFailure;
        if (!success || warning) result.diagnostics.push_back({Logger::get_current_time(),
            warning ? "WARN" : "ERROR","daemon",message});
        return result;
    });
    auto summary = planner.execute(request);
    // One aggregate report preserves the common severity max, sinks and dedup.
    incident::PolicyIncidentReporter(controller).report(registry,summary,reason);
    return summary;
}
}
