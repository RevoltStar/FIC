#ifndef FIC_DICK_DAEMON_PERMANENT_DEVICE_RETRY_H
#define FIC_DICK_DAEMON_PERMANENT_DEVICE_RETRY_H

#include <atomic>
#include <chrono>

namespace fic::device_control {

// The in-memory retry obligation for an undelivered permanent-device incident.
//
// It is deliberately in-memory only: a restart recovers through the startup
// reconciliation, which re-derives every violation from the authoritative
// database plus the observed device presence, so no persistent queue is
// needed. The flag is GLOBAL: a partial check of one subtree knows nothing
// about undelivered violations elsewhere, so only a proven FULL check may
// clear it.
inline std::atomic_bool g_permanentIncidentRetryRequired{false};

inline bool permanentIncidentRetryRequired() {
    return g_permanentIncidentRetryRequired.load();
}

inline void setPermanentIncidentRetryRequired(bool required) {
    g_permanentIncidentRetryRequired.store(required);
}

// The single production authority for a retry transition after one
// permanent-device check pass. The daemon's check_permanent_devices() calls
// exactly this function; the tests exercise the same code.
//
//   scanOk        — the underlying inventory read was PROVEN successful (for
//                   a full check this means a complete SQLite scan to
//                   SQLITE_DONE; a failed read is an unproven inventory);
//   fullCheck     — the pass examined every permanent obligation, not just an
//                   affected subtree;
//   violationsEmpty — the pass found no missing permanent devices;
//   delivered     — the found violations were all acknowledged by the main
//                   daemon.
//
// Semantics:
//   unproven scan            -> never touch the obligation: a failed read is
//                               not a proof of absence;
//   partial pass             -> never touch the obligation: the subset proves
//                               nothing about the rest of the database;
//   full proven empty        -> the obligation clears;
//   full proven, all delivered -> the obligation clears;
//   full proven, delivery failed -> the obligation is set.
inline void updatePermanentIncidentRetry(
    bool scanOk,
    bool fullCheck,
    bool violationsEmpty,
    bool delivered) {
    if (!scanOk || !fullCheck) {
        // Preserve the current obligation: nothing was proven that would
        // either create or discharge it.
        return;
    }
    if (violationsEmpty || delivered) {
        setPermanentIncidentRetryRequired(false);
        return;
    }
    // A proven full scan still found unacknowledged violations.
    setPermanentIncidentRetryRequired(true);
}

inline constexpr std::chrono::seconds PERMANENT_INCIDENT_RETRY_INTERVAL{5};

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_PERMANENT_DEVICE_RETRY_H