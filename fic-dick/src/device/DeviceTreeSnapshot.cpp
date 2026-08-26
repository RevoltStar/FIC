#include "DeviceTreeSnapshot.h"

#include <fic/device-db/DB.h>
#include <fic/ipc/FicIpcClient.h>
#include <fic/ipc/FicIpcTransport.h>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

namespace fic::device_control {
namespace {

using json = nlohmann::json;

struct EffectivePolicy {
    std::string level = "allowed";
    std::string source = "default";
    int sourceDeviceId = -1;
    std::string reason = "default allow";
};

std::string attribute_value(const std::map<std::string, std::string>& attributes,
                            const std::string& name) {
    const auto it = attributes.find(name);
    return it == attributes.end() ? "" : it->second;
}

bool contains(const std::string& value, const std::string& needle) {
    return value.find(needle) != std::string::npos;
}

bool starts_with(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

std::optional<EffectivePolicy> category_policy(
    const DeviceInfo& device,
    const std::map<std::string, std::string>& attributes,
    const DeviceCategoryPolicyState& settings) {
    const std::string idBus = attribute_value(attributes, "ID_BUS");
    const std::string devtype = attribute_value(attributes, "DEVTYPE");
    const std::string type = attribute_value(attributes, "TYPE");
    const std::string interfaces = attribute_value(attributes, "ID_USB_INTERFACES");
    const std::string modalias = attribute_value(attributes, "MODALIAS");

    bool usbStorage = false;
    if (device.subsystem == "block") {
        usbStorage = idBus == "usb" || contains(device.devpath, "/usb");
    } else if (device.subsystem == "usb") {
        usbStorage = starts_with(type, "8/") || contains(interfaces, ":080") ||
            contains(interfaces, ":08");
    } else {
        usbStorage = devtype == "disk" && idBus == "usb";
    }
    if (settings.block_usb_storage && usbStorage) {
        return EffectivePolicy{"blocked", "dc:block_usb_storage", device.id,
                               "USB storage is blocked by DC settings"};
    }

    const bool printerOrScanner =
        (device.subsystem == "usb" || idBus == "usb") &&
        (starts_with(type, "7/") || starts_with(type, "6/") ||
         contains(interfaces, ":070") || contains(interfaces, ":07") ||
         contains(interfaces, ":060") || contains(interfaces, ":06") ||
         contains(modalias, "ic07") || contains(modalias, "ic06"));
    if (settings.block_printers_scanners && printerOrScanner) {
        return EffectivePolicy{"blocked", "dc:block_printers_scanners", device.id,
                               "printers/scanners are blocked by DC settings"};
    }

    const bool optical = device.subsystem == "block" &&
        (!attribute_value(attributes, "ID_CDROM").empty() ||
         !attribute_value(attributes, "ID_CDROM_CD").empty() ||
         attribute_value(attributes, "ID_TYPE") == "cd");
    if (settings.block_optical_drives && optical) {
        return EffectivePolicy{"blocked", "dc:block_optical_drives", device.id,
                               "optical drives are blocked by DC settings"};
    }
    return std::nullopt;
}

std::string identity_key(const DeviceInfo& device) {
    return device.device_hash + '\0' + device.subsystem;
}

bool effective_policy(
    const DeviceTreeEntry& entry,
    const std::map<int, const DeviceInfo*>& devicesById,
    const std::map<std::string, std::vector<const DeviceInfo*>>& identities,
    const DeviceCategoryPolicyState& categories,
    EffectivePolicy& policy,
    std::string& error) {
    const DeviceInfo& device = entry.device;
    const auto identity = identities.find(identity_key(device));
    if (identity != identities.end()) {
        for (const DeviceInfo* occurrence : identity->second) {
            if (occurrence->control_explicit && occurrence->ignore_hierarchy) {
                policy = {occurrence->control_level,
                          "identity:" + std::to_string(occurrence->id),
                          occurrence->id,
                          "explicit same-identity rule with ignore_hierarchy=true"};
                return true;
            }
        }
    }
    if (device.control_explicit) {
        policy = {device.control_level,
                  "placement:" + std::to_string(device.id), device.id,
                  "explicit placement rule"};
        return true;
    }
    if (const auto category = category_policy(device, entry.attributes, categories)) {
        policy = *category;
        return true;
    }

    std::set<int> visited{device.id};
    int parentId = device.parent_id;
    while (parentId > 0) {
        if (!visited.insert(parentId).second) {
            error = "cycle detected while evaluating device hierarchy";
            return false;
        }
        const auto parent = devicesById.find(parentId);
        if (parent == devicesById.end()) {
            error = "missing parent while evaluating device hierarchy";
            return false;
        }
        if (parent->second->children_control != "inherit") {
            policy = {parent->second->children_control == "deny" ? "blocked" : "allowed",
                      "children:" + std::to_string(parentId), parentId,
                      "nearest explicit ancestor children rule"};
            return true;
        }
        parentId = parent->second->parent_id;
    }
    return true;
}

json device_json(const DeviceTreeEntry& entry,
                 const EffectivePolicy& policy,
                 const std::string& bootId) {
    const DeviceInfo& device = entry.device;
    return {
        {"id", device.id}, {"device_hash", device.device_hash},
        {"devpath", device.devpath}, {"subsystem", device.subsystem},
        {"device_type", device.device_type}, {"parent_id", device.parent_id},
        {"control_level", device.control_level},
        {"control_explicit", device.control_explicit},
        {"ignore_hierarchy", device.ignore_hierarchy},
        {"children_control", device.children_control},
        {"effective_control_level", policy.level},
        {"effective_source", policy.source},
        {"effective_source_device_id", policy.sourceDeviceId},
        {"effective_reason", policy.reason},
        {"connected", !bootId.empty() && device.boot_id == bootId},
        {"boot_id", device.boot_id}, {"created_at", device.created_at},
        {"last_event_at", device.last_event_at}, {"notes", device.notes},
        {"attributes", entry.attributes}
    };
}

} // namespace

json device_tree_snapshot_response(DB& db,
                                   const json& request,
                                   const std::string& bootId) {
    if (request.contains("include_disconnected") &&
        !request["include_disconnected"].is_boolean()) {
        return fic::ipc::make_error_response("include_disconnected must be boolean");
    }
    const bool includeDisconnected = request.value("include_disconnected", false);
    const DeviceInfo root = db.getComputerRoot();
    if (root.id <= 0) {
        return fic::ipc::make_error_response("device root not found");
    }

    DeviceTreeSnapshot snapshot;
    std::string error;
    if (!db.getDeviceTreeSnapshot(root.id, includeDisconnected, bootId,
                                  snapshot, error)) {
        return fic::ipc::make_error_response("failed to build device tree snapshot: " + error);
    }

    std::map<int, const DeviceInfo*> devicesById;
    std::map<std::string, std::vector<const DeviceInfo*>> identities;
    for (const DeviceInfo& device : snapshot.identityOccurrences) {
        devicesById.emplace(device.id, &device);
        identities[identity_key(device)].push_back(&device);
    }

    json devices = json::array();
    for (const DeviceTreeEntry& entry : snapshot.entries) {
        EffectivePolicy policy;
        if (!effective_policy(entry, devicesById, identities,
                              snapshot.categoryPolicy, policy, error)) {
            return fic::ipc::make_error_response(
                "failed to evaluate device tree snapshot: " + error);
        }
        devices.push_back(device_json(entry, policy, bootId));
    }

    json response = {
        {"ok", true}, {"message", "device tree snapshot loaded"},
        {"revision", snapshot.revision}, {"boot_id", bootId},
        {"include_disconnected", includeDisconnected},
        {"devices", std::move(devices)}
    };
    if (response.dump().size() > fic::ipc::MAX_RESPONSE_BYTES) {
        return fic::ipc::make_error_response(
            "device tree snapshot exceeds the IPC response size limit");
    }
    return response;
}

} // namespace fic::device_control
