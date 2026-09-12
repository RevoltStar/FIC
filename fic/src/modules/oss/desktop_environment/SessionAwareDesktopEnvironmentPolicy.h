#ifndef FIC_SESSION_AWARE_DESKTOP_ENVIRONMENT_POLICY_H
#define FIC_SESSION_AWARE_DESKTOP_ENVIRONMENT_POLICY_H

#include "modules/oss/desktop_environment/DesktopEnvironment.h"
#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"

#include <map>
#include <memory>

class SessionAwareDesktopEnvironmentPolicy
    : public DesktopEnvironment,
      public SessionAwarePolicy {
public:
    SessionAwareDesktopEnvironmentPolicy(
        ControlledDesktopEnvironmentScope& scope,
        std::shared_ptr<GraphicalSessionInventory> inventory);

    bool apply() override;
    SessionApplicability sessionApplicability(
        DesktopEnvironmentKind desktop,
        std::string& error) override;
    EnforcementMode enforcementMode(
        DesktopEnvironmentKind desktop) const override;
    void setGlobalEnforcementResults(
        PolicyGlobalEnforcementResults results) override;
    SessionReconcileResult reconcileSession(
        const SessionReconcileContext& context,
        const PolicyGlobalEnforcementResult& globalResult) override;
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::SessionAware};
    }

protected:
    virtual bool prepare(std::string& error) = 0;
    virtual bool relevantTo(DesktopEnvironmentKind desktop) const = 0;
    virtual EnforcementMode modeFor(DesktopEnvironmentKind desktop) const = 0;
    virtual bool reconcileControlledSession(
        const SessionReconcileContext& context,
        std::string& error) = 0;

private:
    ControlledDesktopEnvironmentScope& scope_;
    std::shared_ptr<GraphicalSessionInventory> inventory_;
    PolicyGlobalEnforcementResults globalResults_;
};

#endif // FIC_SESSION_AWARE_DESKTOP_ENVIRONMENT_POLICY_H
