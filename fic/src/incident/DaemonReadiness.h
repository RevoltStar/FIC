#pragma once

#include <fic/core/incident/IncidentSeverity.h>
#include "incident/IncidentResponseMode.h"

namespace fic::incident {

enum class DaemonReadinessState { Initializing, Applying, Ready, Degraded, Stopping };

inline const char* daemonReadinessToken(DaemonReadinessState state) {
    switch (state) {
        case DaemonReadinessState::Initializing: return "INITIALIZING";
        case DaemonReadinessState::Applying: return "APPLYING";
        case DaemonReadinessState::Ready: return "READY";
        case DaemonReadinessState::Degraded: return "DEGRADED";
        case DaemonReadinessState::Stopping: return "STOPPING";
    }
    return "STOPPING";
}

inline bool ordinaryLoginAllowed(DaemonReadinessState state,
                                 bool persistentStateProven,
                                 ::fic::core::IncidentSeverity severity,
                                 IncidentResponseMode mode = IncidentResponseMode::Active) {
    if (mode != IncidentResponseMode::Active) return true;
    return state == DaemonReadinessState::Ready && persistentStateProven &&
        (severity == ::fic::core::IncidentSeverity::Unlocked ||
         severity == ::fic::core::IncidentSeverity::Soft);
}

class DaemonReadiness {
public:
    DaemonReadinessState state() const { return state_; }
    void set(DaemonReadinessState state) { state_ = state; }

    class ScopedApplying {
    public:
        explicit ScopedApplying(DaemonReadiness& readiness)
            : readiness_(readiness), previous_(readiness.state()) {
            readiness_.set(DaemonReadinessState::Applying);
        }
        ~ScopedApplying() { readiness_.set(previous_); }
        ScopedApplying(const ScopedApplying&) = delete;
        ScopedApplying& operator=(const ScopedApplying&) = delete;
    private:
        DaemonReadiness& readiness_;
        DaemonReadinessState previous_;
    };

private:
    DaemonReadinessState state_ = DaemonReadinessState::Initializing;
};

} // namespace fic::incident
