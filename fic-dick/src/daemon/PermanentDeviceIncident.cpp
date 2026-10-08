#include "daemon/PermanentDeviceIncident.h"

#include <nlohmann/json.hpp>

#include <fic/ipc/FicIpcTransport.h>

#include <cstdint>
#include <limits>

namespace fic::device_control {

namespace {

using json = nlohmann::json;

} // namespace

json permanent_device_incident_request(
    const std::vector<PermanentViolation>& violations) {
    json ids = json::array();
    // Truncate, never drop: the fact of the violation is the security-relevant
    // part of the event, and the id list is bounded diagnostics.
    const std::size_t carried = violations.size() < MAX_DEVICE_INCIDENT_IDS
        ? violations.size()
        : MAX_DEVICE_INCIDENT_IDS;
    for (std::size_t index = 0; index < carried; ++index) {
        ids.push_back(violations[index].deviceId);
    }
    return json{
        {"command", "incident_device_missing"},
        {"device_ids", ids},
        {"device_ids_total", violations.size()}
    };
}

bool is_valid_permanent_device_incident_request(
    const json& request, std::string& error) {
    if (!request.is_object()) {
        error = "request must be an object";
        return false;
    }
    for (auto item = request.begin(); item != request.end(); ++item) {
        if (item.key() == "command" || item.key() == "device_ids" ||
            item.key() == "device_ids_total" || item.key() == "api_version") {
            continue;
        }
        error = "unknown request field: " + item.key();
        return false;
    }
    const auto command = request.find("command");
    if (command == request.end() || !command->is_string() ||
        command->get<std::string>() != "incident_device_missing") {
        error = "request.command must be \"incident_device_missing\"";
        return false;
    }
    const auto ids = request.find("device_ids");
    if (ids == request.end() || !ids->is_array()) {
        error = "request.device_ids must be an array";
        return false;
    }
    if (ids->empty()) {
        // An empty list is not a device-missing event: accepting it would let a
        // trusted peer's bug erase the violation instead of reporting it.
        error = "request.device_ids must not be empty";
        return false;
    }
    if (ids->size() > MAX_DEVICE_INCIDENT_IDS) {
        error = "request.device_ids exceeds the bounded payload";
        return false;
    }
    for (const auto& id : *ids) {
        if (!id.is_number_integer()) {
            error = "request.device_ids entries must be integers";
            return false;
        }
        const std::int64_t value = id.get<std::int64_t>();
        if (value <= 0 || value > std::numeric_limits<int>::max()) {
            error = "request.device_ids entries must be positive device ids";
            return false;
        }
    }
    const auto total = request.find("device_ids_total");
    if (total == request.end() || !total->is_number_unsigned() ||
        total->get<std::uint64_t>() >
            static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
        error = "request.device_ids_total must be a non-negative 32-bit integer";
        return false;
    }
    error.clear();
    return true;
}

} // namespace fic::device_control