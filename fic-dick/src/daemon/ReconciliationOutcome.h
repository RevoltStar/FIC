#ifndef FIC_DICK_DAEMON_RECONCILIATION_OUTCOME_H
#define FIC_DICK_DAEMON_RECONCILIATION_OUTCOME_H

namespace fic::device_control {

// The single production authority for deciding whether a device
// reconciliation pass succeeded. The daemon's run_device_reconciliation()
// calls exactly this function; the tests exercise the same code.
//
// A pass is successful ONLY when EVERY mandatory stage succeeded — including
// the permanent-device check: an unreadable inventory, a failed incident
// delivery or an unverifiable main-daemon response must fail the whole pass,
// so the reconciliation obligation survives, the failure is retried with a
// bounded backoff, and the system never falsely believes the inventory is
// reconciled.
inline bool deviceReconciliationSucceeded(
    bool mandatoryStagesOk,
    bool permanentCheckOk) {
    return mandatoryStagesOk && permanentCheckOk;
}

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_RECONCILIATION_OUTCOME_H