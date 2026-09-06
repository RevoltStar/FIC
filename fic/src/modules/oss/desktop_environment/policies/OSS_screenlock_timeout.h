#ifndef OSS_SCREENLOCK_TIMEOUT_H
#define OSS_SCREENLOCK_TIMEOUT_H

#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"

#include <string>
#include <vector>

class OSS_screenlock_timeout final : public SessionAwareDesktopEnvironmentPolicy
{
public:
    explicit OSS_screenlock_timeout(
        ControlledDesktopEnvironmentScope& scope,
        std::shared_ptr<GraphicalSessionInventory> inventory);

protected:
    bool prepare(std::string& error) override;
    bool relevantTo(DesktopEnvironmentKind desktop) const override;
    EnforcementMode modeFor(DesktopEnvironmentKind desktop) const override;
    bool reconcileControlledSession(
        const ClassifiedGraphicalSession& session,
        std::string& error) override;

private:
    int timeoutMinutes_ = 0;
};

#endif // OSS_SCREENLOCK_TIMEOUT_H
