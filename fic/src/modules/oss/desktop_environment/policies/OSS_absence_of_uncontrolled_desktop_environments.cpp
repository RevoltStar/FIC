#include "modules/oss/desktop_environment/policies/OSS_absence_of_uncontrolled_desktop_environments.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

#include <utility>

namespace {
std::string controlledList(const DesktopEnvironmentSet& controlled) {
    std::string result = "[";
    for (const auto desktop : controlled) {
        if (result.size() > 1) result += ',';
        result += DesktopEnvironmentBackend::kindName(desktop);
    }
    return result + ']';
}
}

OSS_absence_of_uncontrolled_desktop_environments::
OSS_absence_of_uncontrolled_desktop_environments(
    ControlledDesktopEnvironmentScope& scope,
    std::shared_ptr<GraphicalSessionInventory> inventory)
    : scope_(scope), inventory_(std::move(inventory))
{
    policyName = "absence_of_uncontrolled_desktop_environments";
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
}

bool OSS_absence_of_uncontrolled_desktop_environments::apply()
{
    std::vector<ClassifiedGraphicalSession> sessions;
    std::string error;
    if (!inventory_->currentSessions(sessions, error)) {
        log("Failed to enumerate graphical sessions: " + error,
            logLevel::ERROR);
        return false;
    }
    if (!evaluateSessionInventory(sessions, error)) {
        log(error, logLevel::ERROR);
        return false;
    }
    return true;
}

bool OSS_absence_of_uncontrolled_desktop_environments::
evaluateSessionInventory(
    const std::vector<ClassifiedGraphicalSession>& sessions,
    std::string& error)
{
    DesktopEnvironmentSet controlled;
    if (!scope_.controlledDesktopEnvironments(controlled, error)) return false;
    if (controlled.empty()) {
        error = "controlled_desktop_environments is empty (UNCONFIGURED)";
        return false;
    }
    for (const ClassifiedGraphicalSession& session : sessions) {
        if (!session.classified()) {
            error = "graphical session " + session.session.id +
                ", uid=" + std::to_string(session.session.uid) +
                " has an unknown or unclassifiable desktop; controlled=" +
                controlledList(controlled) + ", result=FAILED: " +
                session.classificationError;
            return false;
        }
        if (controlled.find(session.desktop) == controlled.end()) {
            error = "graphical session " + session.session.id + ", uid=" +
                std::to_string(session.session.uid) + ", desktop=" +
                DesktopEnvironmentBackend::kindName(session.desktop) +
                ", controlled=" + controlledList(controlled) +
                ", result=FAILED";
            return false;
        }
    }
    error.clear();
    return true;
}
