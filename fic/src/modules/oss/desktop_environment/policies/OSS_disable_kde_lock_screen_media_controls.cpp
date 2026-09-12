#include "modules/oss/desktop_environment/policies/OSS_disable_kde_lock_screen_media_controls.h"

#include "modules/oss/desktop_environment/KdeSessionTopology.h"
#include "modules/oss/desktop_environment/backends/KdeBackend.h"
#include <utility>

OSS_disable_kde_lock_screen_media_controls::
OSS_disable_kde_lock_screen_media_controls(
    ControlledDesktopEnvironmentScope& scope,
    std::shared_ptr<GraphicalSessionInventory> inventory)
    : SessionAwareDesktopEnvironmentPolicy(scope, std::move(inventory))
{
    this->policyName = "disable_kde_lock_screen_media_controls";
    this->policyTypeValue = std::make_unique<FixedPolicyTypeValue>();
}

bool OSS_disable_kde_lock_screen_media_controls::prepare(std::string& error)
{
    error.clear();
    return true;
}

bool OSS_disable_kde_lock_screen_media_controls::relevantTo(
    DesktopEnvironmentKind desktop) const
{
    return desktop == DesktopEnvironmentKind::Kde;
}

EnforcementMode OSS_disable_kde_lock_screen_media_controls::modeFor(
    DesktopEnvironmentKind desktop) const
{
    return desktop == DesktopEnvironmentKind::Kde
        ? EnforcementMode::SessionOnly
        : EnforcementMode::Unsupported;
}

bool OSS_disable_kde_lock_screen_media_controls::reconcileControlledSession(
    const SessionReconcileContext& context,
    std::string& error)
{
    const KdeSessionTopologyInfo topology = determineKdeSessionTopology(
        context.target, context.sessions, context.inventoryComplete);
    KdeBackend backend(context.target.session, context.target.context,
                       topology);
    // Единый protocol: read → write only if mismatch → ALWAYS configure
    // → final readback → validateRuntimeContext. Уже корректный KConfig
    // не пропускает runtime configure reload.
    return kde_media_controls::reconcileMediaControls(backend, error);
}
