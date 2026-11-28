// Detector-event contract tests for the device incident path. All three
// violation kinds share ONE bounded event schema, so the contract is proven
// once here and once against the production sender.
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
    using fic::device_control::device_incident_request;
    using fic::device_control::is_valid_device_incident_request;
    using fic::device_control::MAX_DEVICE_INCIDENT_IDS;
    const auto kind = fic::ipc::DeviceIncidentKind::PermanentDeviceMissing;

    // R1: the detector event must NOT be the legacy lock command.
    const std::vector<PermanentViolation> violations{
        {123, 100, "/devices/usb1", "dc:block_usb_storage"}};
    const nlohmann::json request =
        device_incident_request(kind, violations);
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
    require(is_valid_device_incident_request(request, kind, error),
            "the built request must satisfy its own schema: " + error);

    // An empty list is NOT a device-missing event.
    require(!is_valid_device_incident_request(
                nlohmann::json{{"command", "incident_device_missing"},
                               {"device_ids", nlohmann::json::array()},
                               {"device_ids_total", 0U}},
                kind, error),
            "an empty violation list must be rejected");

    // Unknown fields are rejected.
    require(!is_valid_device_incident_request(
                nlohmann::json{{"command", "incident_device_missing"},
                               {"device_ids", nlohmann::json{123}},
                               {"device_ids_total", 1U},
                               {"severity", "HARD"}},
                kind, error),
            "an authoritative severity field must be rejected");

    // Wrong command is rejected.
    require(!is_valid_device_incident_request(
                nlohmann::json{{"command", "lock"},
                               {"device_ids", nlohmann::json{123}},
                               {"device_ids_total", 1U}},
                kind, error),
            "the legacy command must not validate");

    // Oversized payloads are bounded by truncation, and the total still tells
    // the truth.
    std::vector<PermanentViolation> many;
    for (int index = 0; index < 200; ++index) {
        many.push_back(PermanentViolation{index + 1, index + 1, "d", "s"});
    }
    const nlohmann::json bounded = device_incident_request(kind, many);
    require(bounded["device_ids"].size() == MAX_DEVICE_INCIDENT_IDS,
            "the id list must be truncated to the bounded payload");
    require(bounded.value("device_ids_total", 0U) == 200U,
            "the total must stay truthful after truncation");
    require(is_valid_device_incident_request(bounded, kind, error),
            "a truncated payload must still be a valid event");

    // Non-integer ids are rejected by the schema.
    require(!is_valid_device_incident_request(
                nlohmann::json{{"command", "incident_device_missing"},
                               {"device_ids", nlohmann::json{"abc"}},
                               {"device_ids_total", 1U}},
                kind, error),
            "a non-integer id must be rejected");


    // ---- Acknowledgement validation (P2) --------------------------------
    using fic::device_control::DeviceIncidentAcknowledgement;
    using fic::device_control::parse_device_incident_acknowledgement;
    const auto parse_ack = [kind](const nlohmann::json& response) {
        return parse_device_incident_acknowledgement(response, kind);
    };

    // A durably persisted severity with a DEGRADED containment is STILL an
    // acknowledged event: containment owns its own retry lifecycle (R3).
    {
        const auto ack = parse_ack(nlohmann::json{
            {"ok", false},
            {"message", "device incident recorded; containment degraded"},
            {"command", "incident_device_missing"},
            {"acknowledged", true},
            {"persistence_confirmed", true},
            {"escalated", true},
            {"reason", "configured STANDARD"},
            {"response_mode", "ACTIVE"},
            {"requested_severity", "STANDARD"},
            {"effective_severity", "STANDARD"},
            {"ignored", false},
            {"runtime", "degraded"},
            {"api_version", 1}});
        require(ack.valid, "degraded containment must not break the ack: " + ack.error);
        require(ack.acknowledged && ack.persistenceConfirmed,
                "the acknowledged event must carry the confirmed persistence");
    }

    // A persistence failure is NOT an acknowledgement (G17).
    {
        const auto ack = parse_ack(nlohmann::json{
            {"ok", false},
            {"message", "device incident could not be recorded"},
            {"command", "incident_device_missing"},
            {"acknowledged", false},
            {"persistence_confirmed", false},
            {"escalated", false},
            {"response_mode", "ACTIVE"},
            {"requested_severity", "STANDARD"},
            {"effective_severity", "ISOLATE"},
            {"ignored", false},
            {"runtime", "degraded"},
            {"api_version", 1}});
        require(ack.valid && !ack.acknowledged && !ack.persistenceConfirmed,
                "a persistence failure must be a non-acknowledgement");
    }

    // A wrong command is never an acknowledgement (G19).
    {
        const auto ack = parse_ack(nlohmann::json{
            {"ok", true},
            {"message", "ok"},
            {"command", "something_else"},
            {"acknowledged", true},
            {"persistence_confirmed", true},
            {"escalated", true},
            {"response_mode", "ACTIVE"},
            {"ignored", false},
            {"api_version", 1}});
        require(!ack.valid,
                "a response naming a different command must be rejected");
    }

    // A missing strict field is rejected (G18).
    {
        const auto ack = parse_ack(nlohmann::json{
            {"ok", true},
            {"command", "incident_device_missing"},
            {"escalated", true},
            {"response_mode", "ACTIVE"},
            {"acknowledged", true},
            {"api_version", 1}});
        require(!ack.valid,
                "a response without persistence_confirmed must be rejected");
    }

    // An ignored event must NOT claim persistence.
    {
        const auto ack = parse_ack(nlohmann::json{
            {"ok", true},
            {"command", "incident_device_missing"},
            {"acknowledged", true},
            {"persistence_confirmed", true},
            {"ignored", true},
            {"response_mode", "OFF"},
            {"api_version", 1}});
        require(!ack.valid,
                "an ignored event claiming persistence must be rejected");
    }

    // A consistent OFF/NONE acknowledgement is valid.
    {
        const auto ack = parse_ack(nlohmann::json{
            {"ok", true},
            {"command", "incident_device_missing"},
            {"acknowledged", true},
            {"persistence_confirmed", false},
            {"ignored", true},
            {"response_mode", "OFF"},
            {"requested_severity", "NONE"},
            {"api_version", 1}});
        require(ack.valid && ack.ignored && !ack.persistenceConfirmed,
                "an intentional OFF/NONE ignore is a valid acknowledgement");
    }

    // Each kind owns its own command: an acknowledgement of another kind is a
    // delivery failure, so a successful check of one violation can never
    // discharge another kind's obligation.
    {
        const std::vector<PermanentViolation> blockingViolations{
            {7, 7, "/devices/usb1/1-7", "placement:7"}};
        const nlohmann::json blockFailedRequest = device_incident_request(
            fic::ipc::DeviceIncidentKind::DeviceBlockFailed,
            blockingViolations);
        require(blockFailedRequest.value("command", "") ==
                    "incident_device_block_failed",
                "the block-failed event must name its own command");
        require(is_valid_device_incident_request(
                    blockFailedRequest,
                    fic::ipc::DeviceIncidentKind::DeviceBlockFailed, error),
                "the block-failed event must satisfy its own schema: " + error);
        require(!is_valid_device_incident_request(
                    blockFailedRequest,
                    fic::ipc::DeviceIncidentKind::PermanentDeviceMissing, error),
                "a block-failed event must not validate as device-missing");

        const nlohmann::json staticPresentRequest = device_incident_request(
            fic::ipc::DeviceIncidentKind::StaticDevicePresent,
            std::vector<PermanentViolation>{{9, 9, "/cpu_list/cpu-9", "placement:9"}});
        require(staticPresentRequest.value("command", "") ==
                    "incident_device_present",
                "the static-present event must name its own command");

        const auto crossKind = parse_device_incident_acknowledgement(
            nlohmann::json{
                {"ok", true},
                {"command", "incident_device_present"},
                {"acknowledged", true},
                {"persistence_confirmed", true},
                {"ignored", false},
                {"response_mode", "PASSIVE"},
                {"api_version", 1}},
            fic::ipc::DeviceIncidentKind::DeviceBlockFailed);
        require(!crossKind.valid,
                "an acknowledgement of a different kind must be rejected");

        const auto ownKind = parse_device_incident_acknowledgement(
            nlohmann::json{
                {"ok", true},
                {"command", "incident_device_block_failed"},
                {"acknowledged", true},
                {"persistence_confirmed", true},
                {"ignored", false},
                {"response_mode", "PASSIVE"},
                {"api_version", 1}},
            fic::ipc::DeviceIncidentKind::DeviceBlockFailed);
        require(ownKind.valid && ownKind.acknowledged,
                "the matching acknowledgement must be accepted: " +
                    ownKind.error);
    }

    std::cout << "Permanent-device incident detector contract proven\n";
    return 0;
}
