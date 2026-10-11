#ifndef FIC_SESSION_POLICY_RECONCILER_H
#define FIC_SESSION_POLICY_RECONCILER_H
#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "incident/PolicyIncidentReporter.h"

namespace fic::session {
// Synchronous worker-only entrypoint: context exists only after trusted context
// validation. Without it, only current-inventory compliance is evaluated.
PolicyApplySummary reconcileSessionReadyPolicies(
    PolicyRegistry& registry, incident::IncidentController& controller,
    const ClassifiedGraphicalSession& eventSession,
    const SessionReconcileContext* context,
    const std::vector<ClassifiedGraphicalSession>& inventory,
    bool inventoryComplete, const std::string& inventoryError,
    const DesktopGlobalReconcileReport& globalReport);
}
#endif
