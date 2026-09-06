#include "session/SystemGraphicalSessionInventory.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "session/SessionAgentClient.h"
#include "session/SessionLocator.h"

SystemGraphicalSessionInventory::SystemGraphicalSessionInventory(
    const fic::platform::PlatformExecutableResolver& executables)
    : executables_(executables)
{
}

bool SystemGraphicalSessionInventory::currentSessions(
    std::vector<ClassifiedGraphicalSession>& sessions,
    std::string& error)
{
    sessions.clear();
    std::vector<UserSession> candidates;
    if (!SessionLocator::graphicalSessionCandidates(
            executables_, candidates, error)) {
        return false;
    }
    for (const UserSession& candidate : candidates) {
        ClassifiedGraphicalSession classified;
        classified.session = candidate;
        if (!SessionAgentClient::query(
                candidate, classified.context, classified.classificationError)) {
            sessions.push_back(std::move(classified));
            continue;
        }
        classified.desktop = DesktopEnvironmentBackend::kindFromName(
            classified.context.desktop);
        if (classified.desktop == DesktopEnvironmentKind::Unknown) {
            classified.classificationError =
                "session agent did not provide a supported desktop identity";
        }
        sessions.push_back(std::move(classified));
    }
    error.clear();
    return true;
}
