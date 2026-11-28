// Regression tests for the in-memory delivery obligation of a failed dynamic
// block.
//
// A failed block is an ESTABLISHED fact that cannot be re-derived from the
// inventory (reconciliation never re-attempts enforcement), so a new violation
// must never replace an obligation that is still undelivered, and an
// acknowledgement must close exactly the obligations the acknowledged event
// carried.
#include "daemon/BlockFailureObligation.h"
#include "daemon/PermanentDeviceRetry.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

using fic::device_control::BlockFailureObligation;
using fic::device_control::DeviceIncidentRetryKind;
using fic::device_control::MAX_PENDING_BLOCK_FAILURES;
using fic::device_control::PermanentViolation;
using fic::device_control::deviceIncidentRetryRequired;
using fic::device_control::setDeviceIncidentRetryRequired;
using fic::device_control::updateDeviceIncidentRetry;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

PermanentViolation violation(int id, const std::string& devpath) {
    return PermanentViolation{id, id, devpath, "udev"};
}

bool contains(const std::vector<PermanentViolation>& violations, int id) {
    for (const PermanentViolation& entry : violations) {
        if (entry.deviceId == id) return true;
    }
    return false;
}

bool containsPath(const std::vector<PermanentViolation>& violations,
                  const std::string& devpath) {
    for (const PermanentViolation& entry : violations) {
        if (entry.devpath == devpath) return true;
    }
    return false;
}

} // namespace

int main() {
    // A is not delivered, then B fails: BOTH obligations are carried.
    {
        BlockFailureObligation obligations;
        require(obligations.remember({violation(11, "/devices/a")}),
                "the first violation must create an obligation");
        // Delivery of A failed: nothing acknowledges it.
        require(obligations.size() == 1, "A must stay pending");

        require(obligations.remember({violation(12, "/devices/b")}),
                "a second violation must be added");
        require(obligations.size() == 2,
                "a new violation must never replace a pending one");
        const auto snapshot = obligations.snapshot();
        require(contains(snapshot, 11) && contains(snapshot, 12),
                "both pending violations must be carried by the next event");
    }

    // Repeated failed delivery keeps every obligation, and repeating the same
    // violation does not duplicate it.
    {
        BlockFailureObligation obligations;
        obligations.remember({violation(11, "/devices/a")});
        for (int attempt = 0; attempt < 3; ++attempt) {
            const auto snapshot = obligations.snapshot();
            require(snapshot.size() == 1, "the snapshot must stay stable");
            // delivery failed: no acknowledge
            require(!obligations.remember(snapshot),
                    "re-remembering the same occurrence must not duplicate it");
        }
        require(obligations.size() == 1,
                "a failed re-delivery must not lose the obligation");
        require(!obligations.remember({violation(11, "/devices/a")}),
                "a known occurrence is not a new obligation");
    }

    // A successful delivery closes exactly the acknowledged obligations.
    {
        BlockFailureObligation obligations;
        obligations.remember({violation(11, "/devices/a")});
        obligations.remember({violation(12, "/devices/b")});
        const auto attempted = obligations.snapshot();
        require(obligations.acknowledge(attempted) == 2,
                "the acknowledgement must close both obligations");
        require(obligations.empty(), "no obligation may stay after an ack");
        require(obligations.snapshot().empty(),
                "the acknowledged event must not be re-delivered");

        // A later failure starts a fresh obligation.
        require(obligations.remember({violation(12, "/devices/b")}),
                "a new failure after an ack must arm the retry again");
        require(obligations.size() == 1, "exactly one obligation is pending");
    }

    // A partial acknowledgement closes only the acknowledged subset.
    {
        BlockFailureObligation obligations;
        obligations.remember({violation(11, "/devices/a")});
        obligations.remember({violation(12, "/devices/b")});
        require(obligations.acknowledge({violation(11, "/devices/a")}) == 1,
                "only the acknowledged occurrence may close");
        require(obligations.size() == 1, "one obligation must stay pending");
        require(!contains(obligations.snapshot(), 11),
                "the acknowledged occurrence must be gone");
        require(contains(obligations.snapshot(), 12),
                "the unacknowledged occurrence must stay");
    }

    // A path-only fact (category DENY of a device without a database record)
    // is an obligation too, identified by its managed DEVPATH.
    {
        BlockFailureObligation obligations;
        const PermanentViolation pathOnly{0, 0, "/devices/pci0000:00/usb1/1-1",
                                          "dc:category"};
        require(obligations.remember({pathOnly}),
                "a path-only violation must create an obligation");
        require(!obligations.remember({pathOnly}),
                "the same DEVPATH must not duplicate the obligation");
        const auto snapshot = obligations.snapshot();
        require(containsPath(snapshot, "/devices/pci0000:00/usb1/1-1"),
                "the DEVPATH must be carried by the next event");
        require(snapshot.front().deviceId == 0,
                "no synthetic device id may be invented");

        obligations.remember({violation(21, "/devices/pci0000:00/usb1/1-2")});
        require(obligations.size() == 2,
                "a path-only and an id-based fact must both be kept");
        const auto attempted = obligations.snapshot();
        require(obligations.acknowledge(attempted) == 2,
                "both obligations must close on a full ack");
        require(obligations.empty(), "nothing may stay pending");
    }

    // The pending set is bounded by the detector-event payload.
    {
        BlockFailureObligation obligations;
        std::vector<PermanentViolation> many;
        for (int index = 0; index < 100; ++index) {
            many.push_back(violation(1000 + index, "/devices/x"));
        }
        obligations.remember(many);
        require(obligations.size() == MAX_PENDING_BLOCK_FAILURES,
                "the pending list must stay within the bounded payload");
        require(obligations.acknowledge(obligations.snapshot()) ==
                    MAX_PENDING_BLOCK_FAILURES,
                "the bounded obligation must be closable");
        require(obligations.empty(), "a full ack must clear the container");
    }

    // The three incident kinds keep independent obligations: a successful
    // static-present or permanent pass must not discharge a pending failed
    // block.
    {
        BlockFailureObligation obligations;
        obligations.remember({violation(31, "/devices/c")});
        setDeviceIncidentRetryRequired(DeviceIncidentRetryKind::StaticPresent,
                                       false);
        setDeviceIncidentRetryRequired(DeviceIncidentRetryKind::PermanentMissing,
                                       false);
        updateDeviceIncidentRetry(DeviceIncidentRetryKind::StaticPresent,
                                  /*scanOk=*/true, /*fullCheck=*/true,
                                  /*violationsEmpty=*/true, /*delivered=*/true);
        updateDeviceIncidentRetry(DeviceIncidentRetryKind::PermanentMissing,
                                  /*scanOk=*/true, /*fullCheck=*/true,
                                  /*violationsEmpty=*/true, /*delivered=*/true);
        require(obligations.size() == 1,
                "other incident kinds must not touch the failed-block "
                "obligation");
        require(!deviceIncidentRetryRequired(
                    DeviceIncidentRetryKind::StaticPresent),
                "the static obligation must stay independent");
        require(!deviceIncidentRetryRequired(
                    DeviceIncidentRetryKind::PermanentMissing),
                "the permanent obligation must stay independent");

        // A delivered event of another kind cannot acknowledge this one.
        updateDeviceIncidentRetry(DeviceIncidentRetryKind::StaticPresent,
                                  /*scanOk=*/true, /*fullCheck=*/false,
                                  /*violationsEmpty=*/false, /*delivered=*/true);
        require(obligations.size() == 1,
                "a static-present delivery must not close a failed block");
    }

    std::cout << "Failed-block delivery obligation contract proven\n";
    return 0;
}

