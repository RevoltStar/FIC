#ifndef FIC_DICK_DAEMON_PERMANENT_DEVICE_RETRY_H
#define FIC_DICK_DAEMON_PERMANENT_DEVICE_RETRY_H

#include <atomic>
#include <chrono>

namespace fic::device_control {

// A scan-based retry obligation exists per violation kind that can be
// re-derived from the authoritative device database. A successful check of one
// kind never discharges the delivery obligation of another continuing
// violation, so the flags are independent.
//
// The obligation is deliberately in-memory only: a restart recovers through the
// startup reconciliation, which re-derives every violation from the
// authoritative database plus the observed device presence, so no persistent
// queue is needed. Each flag is GLOBAL for its kind: a partial check of one
// subtree knows nothing about undelivered violations elsewhere, so only a
// proven FULL check may clear it.
enum class DeviceIncidentRetryKind {
    // A permanent obligation whose device is absent.
    PermanentMissing,
    // A present static device whose effective rule is `blocked`.
    StaticPresent
};

inline std::atomic_bool& deviceIncidentRetryFlag(DeviceIncidentRetryKind kind) {
    static std::atomic_bool missing{false};
    static std::atomic_bool present{false};
    return kind == DeviceIncidentRetryKind::StaticPresent ? present : missing;
}

inline bool deviceIncidentRetryRequired(DeviceIncidentRetryKind kind) {
    return deviceIncidentRetryFlag(kind).load();
}

inline void setDeviceIncidentRetryRequired(DeviceIncidentRetryKind kind,
                                           bool required) {
    deviceIncidentRetryFlag(kind).store(required);
}

inline bool permanentIncidentRetryRequired() {
    return deviceIncidentRetryRequired(DeviceIncidentRetryKind::PermanentMissing);
}

inline void setPermanentIncidentRetryRequired(bool required) {
    setDeviceIncidentRetryRequired(DeviceIncidentRetryKind::PermanentMissing,
                                   required);
}

// The single production authority for a retry transition after one check pass
// of `kind`. The daemon's check functions call exactly this function; the
// tests exercise the same code.
//
//   scanOk        — the underlying inventory read was PROVEN successful (for
//                   a full check this means a complete SQLite scan to
//                   SQLITE_DONE; a failed read is an unproven inventory);
//   fullCheck     — the pass examined every permanent obligation, not just an
//                   affected subtree;
//   violationsEmpty — the pass found no violation of this kind;
//   delivered     — the found violations were all acknowledged by the main
//                   daemon.
//
// Semantics:
//   unproven scan            -> never touch the obligation: a failed read is
//                               not a proof of absence;
//   partial pass             -> may CREATE the obligation on a proven failed
//                               delivery (a real violation exists and was not
//                               delivered), but must NEVER discharge the
//                               global obligation: the subset proves nothing
//                               about the rest of the database;
//   full proven empty        -> the obligation clears;
//   full proven, all delivered -> the obligation clears;
//   full proven, delivery failed -> the obligation is set.
inline void updateDeviceIncidentRetry(
    DeviceIncidentRetryKind kind,
    bool scanOk,
    bool fullCheck,
    bool violationsEmpty,
    bool delivered) {
    if (!scanOk) {
        // Preserve the current obligation: nothing was proven that would
        // either create or discharge it.
        return;
    }
    if (!fullCheck) {
        // A partial check only sees an affected subtree. It can prove that a
        // REAL violation was not delivered (arming the retry so a temporary
        // main-daemon outage cannot lose the incident), but it can never
        // prove the absence of violations elsewhere, so it must not clear
        // the global obligation.
        if (!violationsEmpty && !delivered) {
            setDeviceIncidentRetryRequired(kind, true);
        }
        return;
    }
    if (violationsEmpty || delivered) {
        setDeviceIncidentRetryRequired(kind, false);
        return;
    }
    // A proven full scan still found unacknowledged violations.
    setDeviceIncidentRetryRequired(kind, true);
}

inline void updatePermanentIncidentRetry(
    bool scanOk,
    bool fullCheck,
    bool violationsEmpty,
    bool delivered) {
    updateDeviceIncidentRetry(DeviceIncidentRetryKind::PermanentMissing,
                              scanOk, fullCheck, violationsEmpty, delivered);
}

inline constexpr std::chrono::seconds PERMANENT_INCIDENT_RETRY_INTERVAL{5};

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_PERMANENT_DEVICE_RETRY_H