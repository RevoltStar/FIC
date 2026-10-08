// Full/partial retry transition tests for the permanent-device incident
// path.
//
// updatePermanentIncidentRetry() is the SINGLE production authority the
// daemon's check_permanent_devices() calls after every pass; these tests
// exercise exactly that function against the authoritative semantics table:
//
//   Partial, no violations            -> obligation unchanged
//   Partial, delivery success         -> obligation unchanged
//   Partial, delivery failure         -> obligation ARMED (even from false)
//   Full, proven empty                -> obligation cleared
//   Full, proven + all acknowledged   -> obligation cleared
//   Full, proven + delivery failure   -> obligation set
//   Unproven scan (SQL error)         -> obligation NEVER touched
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
    // ---- R1: the FALSE -> TRUE transition on a partial failed delivery ----
    // This is the main regression: with the retry initially CLEAR, a partial
    // check that finds a real violation but cannot deliver it MUST arm the
    // retry, otherwise a temporary main-daemon outage loses the incident.
    {
        setPermanentIncidentRetryRequired(false);
        updatePermanentIncidentRetry(
            /*scanOk=*/true,
            /*fullCheck=*/false,
            /*violationsEmpty=*/false,
            /*delivered=*/false);
        require(permanentIncidentRetryRequired(),
                "failed partial delivery must arm retry from a clear state");
    }

    // A partial failed delivery must keep an existing obligation too.
    setPermanentIncidentRetryRequired(true);
    updatePermanentIncidentRetry(true, false, false, false);
    require(permanentIncidentRetryRequired(),
            "a partial delivery failure must keep the retry armed");

    // G10: partial empty check must not lose an existing retry.
    updatePermanentIncidentRetry(true, false, true, false);
    require(permanentIncidentRetryRequired(),
            "a partial empty check must keep the pending retry");

    // G11: partial successful delivery must not clear an existing retry.
    updatePermanentIncidentRetry(true, false, false, true);
    require(permanentIncidentRetryRequired(),
            "a partial successful delivery must keep the pending retry");

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

    // ---- Scenario A: the full loss-prevention lifecycle -------------------
    {
        setPermanentIncidentRetryRequired(false);
        updatePermanentIncidentRetry(true, false, false, false);
        require(permanentIncidentRetryRequired(), "A: partial failed -> true");
        updatePermanentIncidentRetry(true, false, true, false);
        require(permanentIncidentRetryRequired(), "A: partial empty -> true");
        updatePermanentIncidentRetry(true, false, false, true);
        require(permanentIncidentRetryRequired(), "A: partial delivered -> true");
        updatePermanentIncidentRetry(true, true, false, true);
        require(!permanentIncidentRetryRequired(), "A: full delivered -> false");
    }

    // ---- Scenario B: unproven scans never discharge the obligation --------
    {
        setPermanentIncidentRetryRequired(false);
        updatePermanentIncidentRetry(true, false, false, false);
        require(permanentIncidentRetryRequired(), "B: partial failed -> true");
        updatePermanentIncidentRetry(false, true, true, false);
        require(permanentIncidentRetryRequired(), "B: unproven full scan -> true");
        updatePermanentIncidentRetry(false, true, false, false);
        require(permanentIncidentRetryRequired(), "B: second unproven scan -> true");
        updatePermanentIncidentRetry(true, true, true, false);
        require(!permanentIncidentRetryRequired(), "B: full proven empty -> false");
    }

    // ---- Scenario C: a partial success never discharges a full-pass debt --
    {
        setPermanentIncidentRetryRequired(false);
        updatePermanentIncidentRetry(true, true, false, false);
        require(permanentIncidentRetryRequired(), "C: full failed delivery -> true");
        updatePermanentIncidentRetry(true, false, false, true);
        require(permanentIncidentRetryRequired(), "C: partial success -> true");
        updatePermanentIncidentRetry(true, true, false, true);
        require(!permanentIncidentRetryRequired(), "C: full success -> false");
    }

    // ---- Scenario D: no false accumulation from healthy partial passes ----
    {
        setPermanentIncidentRetryRequired(false);
        updatePermanentIncidentRetry(true, false, false, true);
        require(!permanentIncidentRetryRequired(),
                "D: partial successful delivery from a clear state stays clear");
        updatePermanentIncidentRetry(true, false, true, false);
        require(!permanentIncidentRetryRequired(),
                "D: partial empty from a clear state stays clear");
    }

    std::cout << "Permanent-device retry transition contract proven\n";
    return 0;
}