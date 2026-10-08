// Detector-event contract tests for the permanent-device incident path.
//
// The trust boundary is the core of this contract: the device daemon reports
// the FACT of a violation and must never carry an authoritative severity or
// response decision. The main daemon resolves the reaction from its own
// configuration.
#include "daemon/PermanentDeviceIncident.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

using fic::device_control::PermanentViolation;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\\n";
        std::exit(1);
    }
}

} // namespace

int main() {
    using fic::device_control::is_valid_permanent_device_incident_request;
    using fic::device_control::MAX_DEVICE_INCIDENT_IDS;
    using fic::device_control::permanent_device_incident_request;

    // R1: the detector event must NOT be the legacy lock command.
    const std::vector<PermanentViolation> violations{
        {123, 100, "/devices/usb1", "dc:block_usb_storage"}};
    const nlohmann::json request =
        permanent_device_incident_request(violations);
    require(request.value("command", "") == "incident_device_missing",
            "the detector event must use the new incident command, not \"lock\"");
    require(request.value("command", "") != "lock",
            "the legacy lock command must be gone");
    require(!request.contains("severity"),
            "the detector must not carry an authoritative severity");
    require(!request.contains("value"),
            "the detector must not carry a severity value");
    require(!request.contains("mode"),
            "the detector must not carry a response-mode authority");

    // The fact of the violation travels as bounded device ids.
    require(request["device_ids"].is_array() &&
                request["device_ids"].size() == 1 &&
                request["device_ids"][0] == 123,
            "the violation id must be carried");
    require(request.value("device_ids_total", 0U) == 1U,
            "the untruncated total must be carried");

    std::string error;
    require(is_valid_permanent_device_incident_request(request, error),
            "the built request must satisfy its own schema: " + error);

    // An empty list is NOT a device-missing event.
    require(!is_valid_permanent_device_incident_request(
                nlohmann::json{{"command", "incident_device_missing"},
                               {"device_ids", nlohmann::json::array()},
                               {"device_ids_total", 0U}},
                error),
            "an empty violation list must be rejected");

    // Unknown fields are rejected.
    require(!is_valid_permanent_device_incident_request(
                nlohmann::json{{"command", "incident_device_missing"},
                               {"device_ids", nlohmann::json{123}},
                               {"device_ids_total", 1U},
                               {"severity", "HARD"}},
                error),
            "an authoritative severity field must be rejected");

    // Wrong command is rejected.
    require(!is_valid_permanent_device_incident_request(
                nlohmann::json{{"command", "lock"},
                               {"device_ids", nlohmann::json{123}},
                               {"device_ids_total", 1U}},
                error),
            "the legacy command must not validate");

    // Oversized payloads are bounded by truncation, and the total still tells
    // the truth.
    std::vector<PermanentViolation> many;
    for (int index = 0; index < 200; ++index) {
        many.push_back(PermanentViolation{index + 1, index + 1, "d", "s"});
    }
    const nlohmann::json bounded = permanent_device_incident_request(many);
    require(bounded["device_ids"].size() == MAX_DEVICE_INCIDENT_IDS,
            "the id list must be truncated to the bounded payload");
    require(bounded.value("device_ids_total", 0U) == 200U,
            "the total must stay truthful after truncation");
    require(is_valid_permanent_device_incident_request(bounded, error),
            "a truncated payload must still be a valid event");

    // Non-integer ids are rejected by the schema.
    require(!is_valid_permanent_device_incident_request(
                nlohmann::json{{"command", "incident_device_missing"},
                               {"device_ids", nlohmann::json{"abc"}},
                               {"device_ids_total", 1U}},
                error),
            "a non-integer id must be rejected");

    std::cout << "Permanent-device incident detector contract proven\\n";
    return 0;
}