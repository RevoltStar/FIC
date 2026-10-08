// Full/partial retry transition tests for the permanent-device incident
// path.
//
// updatePermanentIncidentRetry() is the SINGLE production authority the
// daemon's check_permanent_devices() calls after every pass; these tests
// exercise exactly that function against the authoritative semantics table:
//
//   Partial, no violations            -> obligation unchanged
//   Partial, delivery success         -> obligation unchanged
//   Partial, delivery failure         -> obligation set
//   Full, proven empty                -> obligation cleared
//   Full, proven + all acknowledged   -> obligation cleared
//   Full, proven + delivery failure   -> obligation set
//   Full, unproven scan (SQL error)   -> obligation NEVER touched
//
// The unproven-inventory proof itself is covered by
// checked_device_inventory_tests with the real SQLite fault injection.
#include "daemon/PermanentDeviceRetry.h"

#include <iostream>
#include <string>

using fic::device_control::permanentIncidentRetryRequired;
using fic::device_control::setPermanentIncidentRetryRequired;
using fic::device_control::updatePermanentIncidentRetry;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

int main() {
    // G10/R2: partial empty check must not lose an existing retry.
    setPermanentIncidentRetryRequired(true);
    updatePermanentIncidentRetry(true, false, true, false);
    require(permanentIncidentRetryRequired(),
            "a partial empty check must keep the pending retry");

    // G11: partial successful delivery must not clear an existing retry.
    updatePermanentIncidentRetry(true, false, false, true);
    require(permanentIncidentRetryRequired(),
            "a partial successful delivery must keep the pending retry");

    // A partial delivery failure must (re)arm the obligation.
    updatePermanentIncidentRetry(true, false, false, false);
    require(permanentIncidentRetryRequired(),
            "a partial delivery failure must set the retry");

    // G12: a full proven empty check clears the obligation.
    updatePermanentIncidentRetry(true, true, true, false);
    require(!permanentIncidentRetryRequired(),
            "a full proven empty inventory must clear the retry");

    // G13: a full proven pass with every violation acknowledged clears it.
    setPermanentIncidentRetryRequired(true);
    updatePermanentIncidentRetry(true, true, false, true);
    require(!permanentIncidentRetryRequired(),
            "a full proven acknowledged delivery must clear the retry");

    // G14: a full pass with a delivery failure sets the obligation.
    updatePermanentIncidentRetry(true, true, false, false);
    require(permanentIncidentRetryRequired(),
            "a full pass with a failed delivery must set the retry");

    // G15/R3/R4: an unproven scan (SQLite prepare/step failure) must NEVER
    // create or clear the obligation.
    setPermanentIncidentRetryRequired(true);
    updatePermanentIncidentRetry(false, true, true, false);
    require(permanentIncidentRetryRequired(),
            "an unproven full scan must not clear a pending retry");
    setPermanentIncidentRetryRequired(false);
    updatePermanentIncidentRetry(false, true, true, false);
    require(!permanentIncidentRetryRequired(),
            "an unproven full scan must not create a retry either");
    updatePermanentIncidentRetry(false, false, false, false);
    require(!permanentIncidentRetryRequired(),
            "an unproven partial scan must not create a retry either");

    std::cout << "Permanent-device retry transition contract proven\n";
    return 0;
}