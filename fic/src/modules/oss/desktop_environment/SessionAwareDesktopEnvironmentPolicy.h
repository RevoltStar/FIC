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
    bool reconcileSession(
        const ClassifiedGraphicalSession& session,
        std::string& error) override;
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::SessionAware};
    }

protected:
    virtual bool prepare(std::string& error) = 0;
    virtual bool relevantTo(DesktopEnvironmentKind desktop) const = 0;
    virtual EnforcementMode modeFor(DesktopEnvironmentKind desktop) const = 0;
    virtual bool applyGlobalValue(
        DesktopEnvironmentKind desktop,
        std::string& error);
    virtual bool applyGlobalProtection(
        DesktopEnvironmentKind desktop,
        std::string& error);
    virtual bool verifyGlobalState(
        DesktopEnvironmentKind desktop,
        std::string& error);
    virtual bool reconcileControlledSession(
        const ClassifiedGraphicalSession& session,
        std::string& error) = 0;

private:
    ControlledDesktopEnvironmentScope& scope_;
    std::shared_ptr<GraphicalSessionInventory> inventory_;
};

#endif // FIC_SESSION_AWARE_DESKTOP_ENVIRONMENT_POLICY_H
