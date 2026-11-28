#include "daemon/DeviceIncidentSender.h"

#include <fic/ipc/FicIpcClient.h>

#include <nlohmann/json.hpp>

namespace fic::device_control {

DeviceIncidentDelivery deliver_device_incident(
    fic::ipc::DeviceIncidentKind kind,
    const std::vector<PermanentViolation>& violations) {
    DeviceIncidentDelivery delivery;
    const nlohmann::json request = device_incident_request(kind, violations);
    std::string schemaError;
    if (!is_valid_device_incident_request(request, kind, schemaError)) {
        // A malformed detector event must never be sent: the main daemon would
        // correctly refuse it, but the bug should not be masked as a network
        // problem.
        delivery.message = "detector event schema is invalid: " + schemaError;
        return delivery;
    }
    const fic::ipc::Client::RequestResult result =
        fic::ipc::Client().requestWithStatus(request);
    if (!result.hasResponse) {
        delivery.message = result.error.empty()
            ? "main fic daemon did not respond"
            : result.error;
        return delivery;
    }
    // STRICT acknowledgement validation: the response must name THIS command,
    // be well-typed and carry a consistent acknowledged/persistence pair. A
    // response from an old daemon, a wrong command or a malformed shape is a
    // delivery failure, never a success.
    const DeviceIncidentAcknowledgement acknowledgement =
        parse_device_incident_acknowledgement(result.response, kind);
    if (!acknowledgement.valid) {
        delivery.message = acknowledgement.error;
        return delivery;
    }
    delivery.delivered = acknowledgement.acknowledged;
    delivery.escalated = acknowledgement.escalated;
    delivery.ignored = acknowledgement.ignored;
    delivery.mode = acknowledgement.mode;
    delivery.requestedSeverity = acknowledgement.requestedSeverity;
    delivery.effectiveSeverity = acknowledgement.effectiveSeverity;
    delivery.runtime = acknowledgement.runtime;
    delivery.message = acknowledgement.message;
    return delivery;
}

} // namespace fic::device_control
