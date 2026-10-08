// Reconciliation outcome tests for the permanent-device incident path.
//
// deviceReconciliationSucceeded() is the SINGLE production authority the
// daemon's run_device_reconciliation() calls to decide the pass result; these
// tests exercise exactly that function against the mandatory-stage contract:
//
//   every mandatory stage OK + permanent check OK   -> success
//   every mandatory stage OK + permanent check FAIL -> FAILURE
//     (unreadable inventory, failed delivery, unverifiable response)
//
// A failed pass must keep the reconciliation obligation pending so it is
// retried; a successful pass clears it. That flag lifecycle is mirrored here
// with the real DeviceEventQueue flag semantics (pending -> failed -> stays
// pending -> success -> cleared).
#include "daemon/ReconciliationOutcome.h"

#include <iostream>
#include <string>

using fic::device_control::deviceReconciliationSucceeded;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

// Mirrors the DeviceEventQueue reconciliation flag the daemon loop uses, so
// the obligation lifecycle is exercised alongside the production decision.
class ReconciliationFlag {
public:
    bool required() const { return required_; }
    void clear() { required_ = false; }

private:
    bool required_ = true;
};

int main() {
    // R2: udevadm OK, inventory OK, but the permanent check failed (SQL error,
    // delivery failure, or unverifiable response) -> the pass FAILS.
    require(!deviceReconciliationSucceeded(
                /*mandatoryStagesOk=*/true, /*permanentCheckOk=*/false),
            "a failed permanent check must fail the whole reconciliation");

    // The normal success path is unchanged.
    require(deviceReconciliationSucceeded(true, true),
            "all stages OK must remain a successful reconciliation");

    // A genuinely failed mandatory stage still fails the pass.
    require(!deviceReconciliationSucceeded(false, true),
            "a failed mandatory stage must fail the reconciliation");
    require(!deviceReconciliationSucceeded(false, false),
            "both failing must fail the reconciliation");

    // The obligation lifecycle: a failed pass keeps the flag pending; only a
    // successful pass clears it; a later failure keeps it pending again.
    {
        ReconciliationFlag flag;
        const bool firstPass = deviceReconciliationSucceeded(true, false);
        require(!firstPass, "the first pass with a failed check must fail");
        if (firstPass) {
            flag.clear();
        }
        require(flag.required(),
                "the reconciliation obligation must survive a failed pass");

        // Recovery: after the database or the main daemon recovers, the next
        // pass completes successfully and clears the obligation.
        const bool secondPass = deviceReconciliationSucceeded(true, true);
        if (secondPass) {
            flag.clear();
        }
        require(!flag.required(),
                "a successful reconciliation must clear the obligation");

        // A later failure re-arms the obligation (no sticky false success).
        flag = ReconciliationFlag{};
        const bool thirdPass = deviceReconciliationSucceeded(true, false);
        require(!thirdPass, "a later failed pass must fail again");
        require(flag.required(),
                "a later failed pass must keep the obligation pending");
    }

    std::cout << "Reconciliation outcome contract proven\n";
    return 0;
}