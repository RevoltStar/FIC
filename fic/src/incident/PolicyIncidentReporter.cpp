#include "incident/PolicyIncidentReporter.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace fic::incident {
namespace {

using ::fic::core::IncidentSeverity;
using ::fic::core::ViolationSeverity;

} // namespace

PolicyIncidentReporter::PolicyIncidentReporter(IncidentController& controller)
    : controller_(controller) {
}

::fic::core::IncidentSeverity PolicyIncidentReporter::report(
    PolicyRegistry& registry,
    const PolicyApplySummary& summary,
    const std::string& reason) {
    // Collect first, raise once. Raising once keeps the notification
    // deduplication meaningful and keeps the audit trail to a single incident
    // record per pass instead of one per failing policy.
    struct Activation {
        IncidentSeverity severity;
        IncidentSource source;
        std::string message;
        PolicyFailureOrigin origin;
    };
    std::vector<Activation> activations;

    for (const PolicyApplyResult& result : summary.getResults()) {
        // Only an enabled policy that ended in Failed reacts. Disabled and
        // NotFound results are not policy violations of an enforced guarantee.
        if (result.status != PolicyApplyStatus::Failed) {
            continue;
        }
        const PolicyRef owner{
            result.moduleName, result.submoduleName, result.policyName};
        Policy* policy = registry.findPolicy(owner);
        if (policy == nullptr || !policy->isEnabled()) {
            continue;
        }
        const ViolationSeverity declared = policy->getViolationSeverity();
        if (!::fic::core::violationSeverityReacts(declared)) {
            // The policy declared that it does not react to its own failure.
            continue;
        }

        Activation activation;
        activation.severity =
            ::fic::core::violationSeverityToIncidentSeverity(declared);
        activation.origin = result.failureOrigin;
        activation.source.name = "policy";
        activation.source.policyModule = owner.moduleName;
        activation.source.policySubmodule = owner.submoduleName;
        activation.source.policyName = owner.policyName;
        activation.source.failureOrigin =
            policyFailureOriginToString(result.failureOrigin);
        activation.message = result.message;
        activations.push_back(std::move(activation));
    }

    if (activations.empty()) {
        return IncidentSeverity::Unlocked;
    }

    // Deterministic order, so the audit record is reproducible regardless of
    // the order the executor happened to visit the policies in.
    std::sort(activations.begin(), activations.end(),
              [](const Activation& left, const Activation& right) {
                  if (left.severity != right.severity) {
                      return static_cast<int>(left.severity) <
                             static_cast<int>(right.severity);
                  }
                  const std::string& leftRef =
                      left.source.policyModule + "/" +
                      left.source.policySubmodule + "/" +
                      left.source.policyName;
                  const std::string& rightRef =
                      right.source.policyModule + "/" +
                      right.source.policySubmodule + "/" +
                      right.source.policyName;
                  return leftRef < rightRef;
              });

    IncidentSeverity requested = IncidentSeverity::Unlocked;
    for (const Activation& activation : activations) {
        requested = ::fic::core::maxIncidentSeverity(
            requested, activation.severity);
    }

    // One raise per failing policy is not needed for the STATE (a raise is a
    // max), but the audit trail wants to know WHICH policies contributed. The
    // highest-severity activation is reported, and the full set is folded into
    // the reason so nothing is lost.
    std::string detail = reason;
    for (const Activation& activation : activations) {
        detail += "; " + activation.source.policyModule + "/" +
                  activation.source.policySubmodule + "/" +
                  activation.source.policyName + " failed (" +
                  policyFailureOriginToString(activation.origin) + "): " +
                  activation.message;
    }

    const IncidentResult raised = controller_.raise(
        requested, activations.back().source, detail);
    return raised.effectiveSeverity;
}

} // namespace fic::incident