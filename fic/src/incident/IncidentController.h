#ifndef FIC_INCIDENT_INCIDENT_CONTROLLER_H
#define FIC_INCIDENT_INCIDENT_CONTROLLER_H

#include "incident/IncidentStateStore.h"
#include "session/SessionContainmentBackend.h"

#include <fic/core/incident/IncidentSeverity.h>

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace fic::incident {

// Runtime containment state. This is deliberately SEPARATE from the severity:
// a failed containment action must never lower the persistent severity, it only
// moves the runtime into DEGRADED.
enum class RuntimeState {
    // No incident: ordinary operation.
    Inactive,
    // A transition is in progress.
    Applying,
    // Containment is fully applied AND proven.
    Active,
    // Containment is partially applied; at least one component failed.
    Degraded,
    // An administrative clear is in progress.
    Clearing
};

std::string runtimeStateToString(RuntimeState state);

// Per-component containment outcome, so the degraded state is explainable.
struct ContainmentStatus {
    bool pamGateActive = false;
    bool sessionsContained = false;
    bool userRuntimeContained = false;
    bool networkQuarantined = false;
};

struct IncidentStatus {
    ::fic::core::IncidentSeverity severity =
        ::fic::core::IncidentSeverity::Isolate;
    // False when the persistent state could not be proven at all, i.e.
    // BROKEN_STATE, whose effective severity is always ISOLATE.
    bool stateProven = false;
    RuntimeState runtime = RuntimeState::Inactive;
    ContainmentStatus containment;
    std::string detail;
};

struct IncidentSource {
    // Short detector name, e.g. "policy", "device", "administrator".
    std::string name;
    // Optional policy reference for policy-driven raises.
    std::string policyModule;
    std::string policySubmodule;
    std::string policyName;
    // Optional device identity for device-driven raises.
    std::string deviceId;
    // Optional failure origin for policy-driven raises.
    std::string failureOrigin;
};

struct IncidentResult {
    bool ok = false;
    ::fic::core::IncidentSeverity previousSeverity = ::fic::core::IncidentSeverity::Unlocked;
    ::fic::core::IncidentSeverity effectiveSeverity = ::fic::core::IncidentSeverity::Isolate;
    // True only when this call raised the persistent severity. A repeat of the
    // same or a lower level leaves it false, which is what keeps desktop
    // notifications from repeating.
    bool escalated = false;
    // True when the persistent state is durably absent (BROKEN_STATE).
    bool brokenState = false;
    RuntimeState runtime = RuntimeState::Inactive;
    std::string detail;
};

// Network quarantine backend. Isolated so the firewall implementation stays
// out of the controller, and so tests can prove the decision without nftables.
class IncidentNetworkBackend {
public:
    virtual ~IncidentNetworkBackend() = default;
    // Applies (or removes) the FIC-owned network quarantine.
    virtual bool applyQuarantine(bool enabled, std::string& diagnostic) = 0;
};

// An unavailable backend: absence of a production firewall cannot prove
// quarantine at ISOLATE.
class NullIncidentNetworkBackend final : public IncidentNetworkBackend {
public:
    bool applyQuarantine(bool enabled, std::string& diagnostic) override {
        if (enabled) {
            diagnostic = "incident network backend is unavailable";
            return false;
        }
        diagnostic.clear();
        return true;
    }
};

// The single runtime owner of common incident state.
//
// Every detector (policy failure, device event, administrator action) reports
// here; only this class mutates the shared incident state and drives
// containment. Policy classes NEVER call it directly: the daemon inspects the
// finished execution summary and reports the failures here, which keeps the
// policy layer free of containment concerns and makes the iteration order of
// results irrelevant (the merge is a max).
class IncidentController {
public:
    IncidentController(
        IncidentStateStore stateStore,
        std::shared_ptr<session::SessionContainmentBackend> sessions,
        std::shared_ptr<IncidentNetworkBackend> network);

    IncidentController();

    // Monotonic raise. `requested` is the detector's severity; the persisted
    // severity only ever increases. Returns an ok result even for an
    // idempotent repeat, so callers can distinguish "raised" via `escalated`.
    IncidentResult raise(::fic::core::IncidentSeverity requested,
                         const IncidentSource& source,
                         const std::string& reason);

    // Administrative clear. Fails closed: without a durably proven UNLOCKED the
    // previous incident remains active. Never uses an unlink fallback and never
    // automatically unlocks a desktop session.
    IncidentResult clear(const std::string& actor);

    // Current status, derived from the authoritative persistent state plus the
    // runtime containment bookkeeping.
    IncidentStatus status();

    // Re-applies containment for the current severity without changing it.
    // Used at daemon startup and after a containment component failure.
    IncidentResult reconcile();

    IncidentStateStore& stateStore() { return stateStore_; }

    // Audit sink. The controller never decides WHO records the audit trail: it
    // hands the structured event to the injected sink, which the daemon wires
    // to the security audit trail. An empty sink (the default) disables audit
    // recording entirely, so a controller can be exercised without any global
    // runtime state. A sink that throws or fails must never abort containment.
    using AuditSink = std::function<void(const std::string& event)>;
    void setAuditSink(AuditSink sink) { auditSink_ = std::move(sink); }

    // Notification sink. Same reasoning as the audit sink: the controller
    // decides WHETHER a new severity warrants a desktop message, never HOW the
    // message is delivered. An empty sink disables notification.
    using NotifySink = std::function<void(::fic::core::IncidentSeverity,
                                         const std::string&)>;
    void setNotifySink(NotifySink sink) { notifySink_ = std::move(sink); }

private:
    IncidentResult applyContainment(
        ::fic::core::IncidentSeverity severity,
        const std::string& reason);

    void recordAudit(const std::string& event,
                     const IncidentResult& result,
                     const IncidentSource& source,
                     const std::string& reason) const;

    void notifySeverity(::fic::core::IncidentSeverity severity,
                        const std::string& reason) const;

    IncidentStateStore stateStore_;
    std::shared_ptr<session::SessionContainmentBackend> sessions_;
    std::shared_ptr<IncidentNetworkBackend> network_;

    // Incident transitions are serialised: two concurrent raises must not
    // interleave their read/compute/write cycles.
    std::mutex transitionMutex_;

    // Severity already announced to the desktop, so a repeated raise of the
    // same level does not spam identical notifications.
    AuditSink auditSink_;
    NotifySink notifySink_;
    mutable std::optional<::fic::core::IncidentSeverity> lastNotified_;
    mutable RuntimeState runtime_ = RuntimeState::Inactive;
    mutable ContainmentStatus containment_;
    mutable std::string lastDetail_;
};

} // namespace fic::incident

#endif // FIC_INCIDENT_INCIDENT_CONTROLLER_H
