#include "incident/DaemonReadiness.h"
#include "incident/AccessReadinessVerifier.h"

#include <stdexcept>

namespace {
void require(bool value) {
    if (!value) throw std::runtime_error("daemon readiness invariant failed");
}
}

int main() {
    using fic::core::IncidentSeverity;
    using fic::incident::DaemonReadiness;
    using fic::incident::DaemonReadinessState;
    using fic::incident::ordinaryLoginAllowed;

    DaemonReadiness readiness;
    require(readiness.state() == DaemonReadinessState::Initializing);
    for (const auto state : {DaemonReadinessState::Initializing,
                             DaemonReadinessState::Applying,
                             DaemonReadinessState::Stopping}) {
        for (const auto severity : {IncidentSeverity::Unlocked,
                                    IncidentSeverity::Soft,
                                    IncidentSeverity::Standard,
                                    IncidentSeverity::Hard,
                                    IncidentSeverity::Isolate}) {
            require(!ordinaryLoginAllowed(state, true, severity));
        }
    }
    readiness.set(DaemonReadinessState::Ready);
    require(ordinaryLoginAllowed(readiness.state(), true,
                                 IncidentSeverity::Unlocked));
    require(ordinaryLoginAllowed(readiness.state(), true,
                                 IncidentSeverity::Soft));
    require(!ordinaryLoginAllowed(readiness.state(), false,
                                  IncidentSeverity::Unlocked));
    for (const auto severity : {IncidentSeverity::Standard,
                                IncidentSeverity::Hard,
                                IncidentSeverity::Isolate}) {
        require(!ordinaryLoginAllowed(readiness.state(), true, severity));
    }
    {
        DaemonReadiness::ScopedApplying applying(readiness);
        require(readiness.state() == DaemonReadinessState::Applying);
        require(!ordinaryLoginAllowed(readiness.state(), true,
                                      IncidentSeverity::Unlocked));
    }
    require(readiness.state() == DaemonReadinessState::Ready);

    bool pamProven = true;
    bool sshProven = true;
    bool sshEnabled = true;
    const auto recompute = [&] {
        return fic::incident::AccessReadinessVerifier::evaluate(
            [&](std::string& error) {
                error = pamProven ? "" : "PAM topology drift";
                return pamProven;
            },
            [&] {
                return fic::incident::SshPamBridgeReadinessResult{
                    !sshEnabled || sshProven, !sshEnabled, "SSH bridge result"};
            });
    };
    require(recompute().ready);
    pamProven = false;
    require(!recompute().ready);
    sshEnabled = false;
    require(!recompute().ready);
    pamProven = true;
    require(recompute().ready && recompute().sshOptedOut);
    sshEnabled = true;
    sshProven = false;
    require(!recompute().ready);
}
