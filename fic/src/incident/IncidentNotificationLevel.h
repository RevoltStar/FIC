#pragma once

#include <fic/core/incident/IncidentSeverity.h>
#include <fic/core/notification/NotifyUser.h>

namespace fic::incident {

inline notifyLevel incidentNotificationLevel(::fic::core::IncidentSeverity severity) {
    switch (severity) {
        case ::fic::core::IncidentSeverity::Unlocked: return notifyLevel::INFO;
        case ::fic::core::IncidentSeverity::Soft:
        case ::fic::core::IncidentSeverity::Standard: return notifyLevel::WARN;
        case ::fic::core::IncidentSeverity::Hard: return notifyLevel::ERROR;
        case ::fic::core::IncidentSeverity::Isolate: return notifyLevel::FATAL;
    }
    return notifyLevel::FATAL;
}

} // namespace fic::incident
