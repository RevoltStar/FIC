#ifndef FIC_INCIDENT_POLICY_INCIDENT_REPORTER_H
#define FIC_INCIDENT_POLICY_INCIDENT_REPORTER_H

#include "incident/IncidentController.h"
#include "policy/registry/PolicyRegistry.h"

#include <fic/core/incident/IncidentSeverity.h>
#include <fic/policy/PolicyApplyResult.h>

#include <string>

namespace fic::incident {

// Reports policy execution failures to the IncidentController.
//
// This is the ONLY place where policy failures become incident state, and it
// deliberately lives outside the Policy classes: a Policy::apply() never calls
// the controller, so the policy layer stays free of containment concerns and
// the decision is made once, from the finished execution summary.
//
// The rule implemented here is exactly:
//     enabled policy + PolicyApplyStatus::Failed
//         -> raise that policy's OWN violation_severity
// There is no severity inheritance along the dependency graph: a policy whose
// apply() never ran because a Required dependency failed is ITSELF Failed and
// therefore raises its own severity, which is why A(Required->B) and B both
// contribute and the merge is max(X, Y).
//
// Because the merge is a max, the iteration order of the results cannot change
// the outcome.
class PolicyIncidentReporter {
public:
    explicit PolicyIncidentReporter(IncidentController& controller);

    // Inspects every result and raises the accumulated severity once. Returns
    // the severity that was requested of the controller, which is the
    // Unlocked sentinel when no enabled policy failed.
    ::fic::core::IncidentSeverity report(
        PolicyRegistry& registry,
        const PolicyApplySummary& summary,
        const std::string& reason);

private:
    IncidentController& controller_;
};

} // namespace fic::incident

#endif // FIC_INCIDENT_POLICY_INCIDENT_REPORTER_H