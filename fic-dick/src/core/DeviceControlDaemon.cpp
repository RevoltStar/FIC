#include "DeviceControlDaemon.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <grp.h>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <cctype>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

#include <nlohmann/json.hpp>

#include <fic/core/Logger.h>
#include <fic/core/ModuleConfigFileHandler.h>
#include <fic/core/SystemBootInfo.h>
#include <fic/device-db/DB.h>
#include <fic/ipc/FicIpcClient.h>

#include "modules/BlockInfoCollector.h"
#include "modules/PCIInfoCollector.h"
#include "modules/UDEVInfoCollector.h"
#include "modules/USBInfoCollector.h"

using json = nlohmann::json;

namespace fic::device_control {
namespace {

std::atomic_bool g_stop{false};

struct EffectivePolicy {
    std::string level = "allowed";
    std::string source = "default";
    int sourceDeviceId = -1;
    std::string reason;
};

struct ControlOverride {
    int deviceId = -1;
    std::string controlLevel;
    bool controlExplicit = false;
    bool ignoreHierarchy = false;
};

struct DcSettings {
    bool blockUsbStorage = false;
    bool blockPrintersScanners = false;
    bool blockOpticalDrives = false;
};

void handle_signal(int) {
    g_stop = true;
}

bool log_device(const std::string& message, logLevel level) {
    if (message.empty()) {
        return true;
    }
    return Logger::log(message, level, "devices");
}

std::string current_boot_id() {
    return SystemBootInfo::get_boot_id();
}

bool is_connected(const DeviceInfo& device, const std::string& bootId) {
    return !bootId.empty() && device.boot_id == bootId;
}

bool is_valid_control_level(const std::string& level) {
    return level == "blocked" || level == "allowed" || level == "permanent" || level == "ignored";
}

DeviceInfo with_override(DeviceInfo device, const std::optional<ControlOverride>& override) {
    if (override.has_value() && device.id == override->deviceId) {
        device.control_level = override->controlLevel;
        device.control_explicit = override->controlExplicit;
        device.ignore_hierarchy = override->ignoreHierarchy;
    }
    return device;
}

std::vector<DeviceInfo> device_path_to_root(DB& db,
                                            DeviceInfo device,
                                            const std::optional<ControlOverride>& override = std::nullopt) {
    std::vector<DeviceInfo> path;
    std::set<int> seen;

    device = with_override(device, override);
    while (device.id > 0 && seen.insert(device.id).second) {
        path.push_back(device);
        if (device.parent_id <= 0) {
            break;
        }
        device = with_override(db.getDeviceById(device.parent_id), override);
        if (device.id == -1) {
            break;
        }
    }

    return path;
}

bool truthy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value == "1" || value == "true" || value == "yes" || value == "on" || value == "enable" || value == "enabled";
}

bool dc_policy_enabled_and_true(ModuleConfigFileHandler& config, const std::string& policy) {
    return config.getPolicyStatus(policy) == "ENABLE" && truthy(config.getPolicyValue(policy));
}

DcSettings load_dc_settings() {
    DcSettings settings;
    ModuleConfigFileHandler config("DC");
    if (!config.loadConfig()) {
        return settings;
    }

    settings.blockUsbStorage = dc_policy_enabled_and_true(config, "block_usb_storage");
    settings.blockPrintersScanners = dc_policy_enabled_and_true(config, "block_printers_scanners");
    settings.blockOpticalDrives = dc_policy_enabled_and_true(config, "block_optical_drives");
    return settings;
}

std::string attribute_value(const std::map<std::string, std::string>& attributes,
                            const std::string& name) {
    auto it = attributes.find(name);
    return it == attributes.end() ? "" : it->second;
}

bool contains(const std::string& value, const std::string& needle) {
    return value.find(needle) != std::string::npos;
}

bool starts_with(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool is_usb_storage_device(const DeviceInfo& device,
                           const std::map<std::string, std::string>& attributes) {
    const std::string idBus = attribute_value(attributes, "ID_BUS");
    const std::string devtype = attribute_value(attributes, "DEVTYPE");
    const std::string type = attribute_value(attributes, "TYPE");
    const std::string interfaces = attribute_value(attributes, "ID_USB_INTERFACES");

    if (device.subsystem == "block") {
        return idBus == "usb" || contains(device.devpath, "/usb");
    }

    if (device.subsystem == "usb") {
        return starts_with(type, "8/") || contains(interfaces, ":080") || contains(interfaces, ":08");
    }

    return devtype == "disk" && idBus == "usb";
}

bool is_printer_or_scanner(const DeviceInfo& device,
                           const std::map<std::string, std::string>& attributes) {
    const std::string type = attribute_value(attributes, "TYPE");
    const std::string interfaces = attribute_value(attributes, "ID_USB_INTERFACES");
    const std::string modalias = attribute_value(attributes, "MODALIAS");

    if (device.subsystem != "usb" && attribute_value(attributes, "ID_BUS") != "usb") {
        return false;
    }

    return starts_with(type, "7/") || starts_with(type, "6/") ||
           contains(interfaces, ":070") || contains(interfaces, ":07") ||
           contains(interfaces, ":060") || contains(interfaces, ":06") ||
           contains(modalias, "ic07") || contains(modalias, "ic06");
}

bool is_optical_drive(const DeviceInfo& device,
                      const std::map<std::string, std::string>& attributes) {
    if (device.subsystem != "block") {
        return false;
    }

    return !attribute_value(attributes, "ID_CDROM").empty() ||
           !attribute_value(attributes, "ID_CDROM_CD").empty() ||
           attribute_value(attributes, "ID_TYPE") == "cd";
}

std::optional<EffectivePolicy> dc_category_policy(DB& db, const DeviceInfo& device) {
    const DcSettings settings = load_dc_settings();
    if (!settings.blockUsbStorage && !settings.blockPrintersScanners && !settings.blockOpticalDrives) {
        return std::nullopt;
    }

    const std::map<std::string, std::string> attributes = db.getDeviceAttributes(device.id);
    if (settings.blockUsbStorage && is_usb_storage_device(device, attributes)) {
        return EffectivePolicy{"blocked", "dc:block_usb_storage", device.id, "USB storage is blocked by DC settings"};
    }
    if (settings.blockPrintersScanners && is_printer_or_scanner(device, attributes)) {
        return EffectivePolicy{"blocked", "dc:block_printers_scanners", device.id, "printers/scanners are blocked by DC settings"};
    }
    if (settings.blockOpticalDrives && is_optical_drive(device, attributes)) {
        return EffectivePolicy{"blocked", "dc:block_optical_drives", device.id, "optical drives are blocked by DC settings"};
    }

    return std::nullopt;
}

EffectivePolicy effective_policy(DB& db,
                                 DeviceInfo device,
                                 const std::optional<ControlOverride>& override = std::nullopt) {
    device = with_override(device, override);
    if (device.id <= 0) {
        return {};
    }

    const std::vector<DeviceInfo> path = device_path_to_root(db, device, override);

    for (const DeviceInfo& pathDevice : path) {
        if (pathDevice.control_explicit && pathDevice.control_level == "ignored") {
            return EffectivePolicy{"ignored", "device:" + std::to_string(pathDevice.id), pathDevice.id, "ignored subtree"};
        }
    }

    if (device.control_explicit) {
        return EffectivePolicy{device.control_level, "device:" + std::to_string(device.id), device.id, "explicit device rule"};
    }

    for (DeviceInfo candidate : db.getDevicesByHashAndSubsystem(device.device_hash, device.subsystem)) {
        candidate = with_override(candidate, override);
        if (candidate.id == device.id) {
            continue;
        }
        if (candidate.control_explicit && candidate.ignore_hierarchy) {
            return EffectivePolicy{candidate.control_level,
                                   "identity:" + std::to_string(candidate.id),
                                   candidate.id,
                                   "explicit same-identity rule with ignore_hierarchy=true"};
        }
    }

    if (std::optional<EffectivePolicy> categoryPolicy = dc_category_policy(db, device)) {
        return categoryPolicy.value();
    }

    for (std::size_t i = 1; i < path.size(); ++i) {
        const DeviceInfo& parent = path[i];
        if (parent.control_explicit) {
            return EffectivePolicy{parent.control_level,
                                   "parent:" + std::to_string(parent.id),
                                   parent.id,
                                   "nearest explicit parent rule"};
        }
    }

    return EffectivePolicy{"allowed", "default", -1, "default allow"};
}

bool write_sysfs_value(const std::filesystem::path& path,
                       const std::string& value,
                       std::string& error) {
    std::ofstream out(path);
    if (!out.is_open()) {
        error = "failed to open " + path.string() + ": " + std::strerror(errno);
        return false;
    }

    out << value;
    if (!out.good()) {
        error = "failed to write " + path.string();
        return false;
    }

    return true;
}

std::optional<std::filesystem::path> find_parent_sysfs_file(const std::string& devpath,
                                                            const std::string& filename) {
    if (devpath.empty() || devpath[0] != '/') {
        return std::nullopt;
    }

    std::filesystem::path current = std::filesystem::path("/sys") / devpath.substr(1);
    while (!current.empty() && current != "/sys" && current != "/") {
        std::filesystem::path candidate = current / filename;
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
        current = current.parent_path();
    }

    return std::nullopt;
}

bool sysfs_file_exists_for_device(const DeviceInfo& device, const std::string& filename) {
    return find_parent_sysfs_file(device.devpath, filename).has_value();
}

bool authorize_usb(const DeviceInfo& device, bool authorize, std::string& details) {
    std::optional<std::filesystem::path> authorized = find_parent_sysfs_file(device.devpath, "authorized");
    if (!authorized.has_value()) {
        details = "USB authorized sysfs file not found";
        return false;
    }

    return write_sysfs_value(authorized.value(), authorize ? "1" : "0", details);
}

bool remove_via_sysfs(const DeviceInfo& device, std::string& details) {
    std::filesystem::path sysDevice = std::filesystem::path("/sys") / device.devpath.substr(1);
    const std::filesystem::path scsiDelete = sysDevice / "device" / "delete";
    if (std::filesystem::exists(scsiDelete)) {
        return write_sysfs_value(scsiDelete, "1", details);
    }

    std::optional<std::filesystem::path> remove = find_parent_sysfs_file(device.devpath, "remove");
    if (remove.has_value()) {
        return write_sysfs_value(remove.value(), "1", details);
    }

    details = "no supported sysfs remove/delete file found";
    return false;
}

bool enforce_allow(const DeviceInfo& device, std::string& details) {
    if (device.subsystem == "usb" || sysfs_file_exists_for_device(device, "authorized")) {
        if (authorize_usb(device, true, details)) {
            details = "USB device authorized";
            return true;
        }
        return true; // absence of USB authorization for non-USB children is not a denial error
    }

    details = "no allow action required";
    return true;
}

bool enforce_block(const DeviceInfo& device, std::string& details) {
    if (device.subsystem == "usb" || sysfs_file_exists_for_device(device, "authorized")) {
        if (authorize_usb(device, false, details)) {
            details = "USB device deauthorized";
            return true;
        }
    }

    if (device.subsystem == "block" || device.subsystem == "pci") {
        return remove_via_sysfs(device, details);
    }

    details = "unsupported subsystem for active enforcement: " + device.subsystem;
    return false;
}

bool call_fic_lock(std::string& message) {
    json response = fic::ipc::Client().request({{"command", "lock"}});
    message = response.value("message", "unknown fic daemon response");
    return response.value("ok", false);
}

void add_event(DB& db,
               int deviceId,
               const std::string& type,
               const std::string& result,
               const std::string& details) {
    db.addDeviceEvent(DeviceEvent{0, deviceId, type, result, details, ""});
}

bool reset_subtree_boot_id(DB& db, int deviceId) {
    bool ok = true;
    for (const DeviceInfo& child : db.getChildDevices(deviceId)) {
        ok = reset_subtree_boot_id(db, child.id) && ok;
    }
    return db.updateBootId(deviceId, "") && ok;
}

json device_to_json(DB& db, const DeviceInfo& device) {
    const EffectivePolicy policy = effective_policy(db, device);
    const std::string bootId = current_boot_id();
    return json{
        {"id", device.id},
        {"device_hash", device.device_hash},
        {"devpath", device.devpath},
        {"subsystem", device.subsystem},
        {"device_type", device.device_type},
        {"parent_id", device.parent_id},
        {"control_level", device.control_level},
        {"control_explicit", device.control_explicit},
        {"ignore_hierarchy", device.ignore_hierarchy},
        {"effective_control_level", policy.level},
        {"effective_source", policy.source},
        {"effective_source_device_id", policy.sourceDeviceId},
        {"effective_reason", policy.reason},
        {"connected", is_connected(device, bootId)},
        {"boot_id", device.boot_id},
        {"created_at", device.created_at},
        {"last_event_at", device.last_event_at},
        {"notes", device.notes}
    };
}

json event_to_json(const DeviceEvent& event) {
    return json{
        {"id", event.id},
        {"device_id", event.device_id},
        {"event_type", event.event_type},
        {"event_result", event.event_result},
        {"event_details", event.event_details},
        {"created_at", event.created_at}
    };
}

std::vector<DeviceInfo> affected_devices_for_override(DB& db, const DeviceInfo& target) {
    std::vector<DeviceInfo> devices;
    std::set<int> seen;

    auto addDevice = [&](const DeviceInfo& device) {
        if (device.id > 0 && seen.insert(device.id).second) {
            devices.push_back(device);
        }
    };

    addDevice(target);
    for (const DeviceInfo& child : db.getDescendantDevices(target.id)) {
        addDevice(child);
    }
    for (const DeviceInfo& occurrence : db.getDevicesByHashAndSubsystem(target.device_hash, target.subsystem)) {
        addDevice(occurrence);
    }

    return devices;
}

json connected_blockers_for_override(DB& db,
                                      const DeviceInfo& target,
                                      const ControlOverride& override) {
    const std::string bootId = current_boot_id();
    json blockers = json::array();

    for (const DeviceInfo& device : affected_devices_for_override(db, target)) {
        if (!is_connected(device, bootId)) {
            continue;
        }

        const EffectivePolicy after = effective_policy(db, device, override);
        if (after.level != "blocked") {
            continue;
        }

        blockers.push_back({
            {"device_id", device.id},
            {"devpath", device.devpath},
            {"source", after.source},
            {"reason", after.reason}
        });
    }

    return blockers;
}

bool permanent_satisfied(DB& db, const DeviceInfo& device, const EffectivePolicy& policy) {
    const std::string bootId = current_boot_id();
    if (bootId.empty()) {
        return false;
    }

    DeviceInfo source = policy.sourceDeviceId > 0 ? db.getDeviceById(policy.sourceDeviceId) : device;
    if (source.id == -1) {
        source = device;
    }

    if (source.ignore_hierarchy) {
        for (const DeviceInfo& occurrence : db.getDevicesByHashAndSubsystem(source.device_hash, source.subsystem)) {
            if (is_connected(occurrence, bootId)) {
                return true;
            }
        }
        return false;
    }

    DeviceInfo current = db.getDeviceById(device.id);
    return current.id != -1 && is_connected(current, bootId);
}

json check_permanent_devices(DB& db) {
    json missing = json::array();

    for (const DeviceInfo& device : db.getAllDevices()) {
        const EffectivePolicy policy = effective_policy(db, device);
        if (policy.level != "permanent") {
            continue;
        }
        if (permanent_satisfied(db, device, policy)) {
            continue;
        }

        missing.push_back({{"device_id", device.id}, {"devpath", device.devpath}, {"source", policy.source}});
    }

    if (missing.empty()) {
        return fic::ipc::make_ok_response("all permanent devices are connected");
    }

    std::string lockMessage;
    const bool locked = call_fic_lock(lockMessage);
    for (const auto& item : missing) {
        add_event(db,
                  item.value("device_id", -1),
                  "lock",
                  locked ? "success" : "error",
                  "permanent device is missing; fic lock: " + lockMessage);
    }

    return json{
        {"ok", locked},
        {"message", locked ? "missing permanent device; computer locked" : "missing permanent device; failed to lock computer"},
        {"missing", missing},
        {"lock_message", lockMessage}
    };
}

std::unique_ptr<UDEVInfoCollector> create_collector_for_subsystem(const std::string& subsystem) {
    if (subsystem == "usb") {
        return std::make_unique<USBInfoCollector>();
    }
    if (subsystem == "block") {
        return std::make_unique<BlockInfoCollector>();
    }
    if (subsystem == "pci") {
        return std::make_unique<PCIInfoCollector>();
    }
    return std::make_unique<UDEVInfoCollector>(
        std::vector<std::string>{"DEVPATH", "SUBSYSTEM", "DEVTYPE", "MODALIAS"}
    );
}

json handle_udev_event(const json& request) {
    const std::string action = request.value("action", "");
    const std::string devpath = request.value("devpath", "");
    const std::string subsystem = request.value("subsystem", "");

    if (action.empty() || devpath.empty() || subsystem.empty()) {
        return fic::ipc::make_error_response("action, devpath and subsystem are required");
    }

    std::map<std::string, std::string> env;
    if (request.contains("env") && request["env"].is_object()) {
        for (auto it = request["env"].begin(); it != request["env"].end(); ++it) {
            if (it.value().is_string()) {
                env[it.key()] = it.value().get<std::string>();
            }
        }
    }

    UDEVInfoCollector baseCollector;
    if (!baseCollector.check_devpath(devpath.c_str())) {
        return fic::ipc::make_ok_response("udev event ignored: non-physical devpath");
    }
    if (!baseCollector.check_excluded_subsystem(subsystem.c_str())) {
        return fic::ipc::make_ok_response("udev event ignored: excluded subsystem");
    }

    std::unique_ptr<UDEVInfoCollector> collector = create_collector_for_subsystem(subsystem);
    collector->set_udev_env(env);

    if (action == "add" || action == "change") {
        if (!collector->create_device_config(devpath, subsystem)) {
            return fic::ipc::make_error_response("failed to add/update device");
        }

        DB db(DEVICE_DB_PATH);
        db.initializeDatabase();
        DeviceInfo device = db.getDeviceByDevpathSubsystemAndBootId(devpath, subsystem, current_boot_id());
        if (device.id == -1) {
            device = db.getDeviceByDevpathAndSubsystem(devpath, subsystem);
        }
        if (device.id == -1) {
            return fic::ipc::make_error_response("device was updated but cannot be found in database");
        }

        const EffectivePolicy policy = effective_policy(db, device);
        add_event(db, device.id, "connect", "success", "effective=" + policy.level + "; source=" + policy.source);

        std::string enforcementDetails;
        if (policy.level == "blocked") {
            const bool enforced = enforce_block(device, enforcementDetails);
            add_event(db,
                      device.id,
                      "block",
                      enforced ? "success" : "error",
                      enforcementDetails + "; source=" + policy.source);
            if (enforced) {
                reset_subtree_boot_id(db, device.id);
                device = db.getDeviceById(device.id);
            }
            return json{
                {"ok", enforced},
                {"message", enforced ? "device blocked by policy" : "device is blocked but enforcement failed"},
                {"device", device_to_json(db, device)},
                {"enforcement", enforcementDetails}
            };
        }

        if (policy.level == "allowed" || policy.level == "permanent") {
            enforce_allow(device, enforcementDetails);
        }

        return json{
            {"ok", true},
            {"message", "device accepted"},
            {"device", device_to_json(db, device)},
            {"enforcement", enforcementDetails}
        };
    }

    if (action == "remove") {
        DB dbBefore(DEVICE_DB_PATH);
        dbBefore.initializeDatabase();
        DeviceInfo before = dbBefore.getDeviceByDevpathAndSubsystem(devpath, subsystem);
        EffectivePolicy beforePolicy;
        if (before.id != -1) {
            beforePolicy = effective_policy(dbBefore, before);
        }

        if (!collector->safe_remove_device(devpath, subsystem)) {
            return fic::ipc::make_error_response("failed to mark device as removed");
        }

        DB db(DEVICE_DB_PATH);
        db.initializeDatabase();
        DeviceInfo device = db.getDeviceByDevpathAndSubsystem(devpath, subsystem);
        if (device.id != -1) {
            add_event(db, device.id, "disconnect", "success", "device removed");
        }

        if (device.id != -1 && beforePolicy.level == "permanent" && !permanent_satisfied(db, device, beforePolicy)) {
            std::string lockMessage;
            const bool locked = call_fic_lock(lockMessage);
            add_event(db,
                      device.id,
                      "lock",
                      locked ? "success" : "error",
                      "permanent device disconnected; fic lock: " + lockMessage);
            return json{
                {"ok", locked},
                {"message", locked ? "permanent device disconnected; computer locked" : "permanent device disconnected; failed to lock computer"},
                {"device", device_to_json(db, device)},
                {"lock_message", lockMessage}
            };
        }

        return fic::ipc::make_ok_response("device removed");
    }

    return fic::ipc::make_error_response("unsupported udev action: " + action);
}

json update_device_control(DB& db, const json& request) {
    const int deviceId = request.value("device_id", 0);
    const std::string controlLevel = request.value("control_level", "");
    if (deviceId <= 0 || !is_valid_control_level(controlLevel)) {
        return fic::ipc::make_error_response("valid device_id and control_level are required");
    }

    DeviceInfo device = db.getDeviceById(deviceId);
    if (device.id == -1) {
        return fic::ipc::make_error_response("device not found");
    }

    const bool ignoreHierarchy = request.value("ignore_hierarchy", device.ignore_hierarchy);
    const std::string bootId = current_boot_id();
    if (controlLevel == "permanent" && !is_connected(device, bootId)) {
        return fic::ipc::make_error_response("cannot mark absent device as permanent");
    }

    ControlOverride override{deviceId, controlLevel, true, ignoreHierarchy};
    json blockers = connected_blockers_for_override(db, device, override);
    if (!blockers.empty()) {
        return json{
            {"ok", false},
            {"message", "operation would block an already connected device"},
            {"blockers", blockers}
        };
    }

    if (!db.updateDeviceControl(deviceId, controlLevel, true, ignoreHierarchy)) {
        return fic::ipc::make_error_response("failed to update device control");
    }

    DeviceInfo updated = db.getDeviceById(deviceId);
    return json{{"ok", true}, {"message", "device control updated"}, {"device", device_to_json(db, updated)}};
}

json update_device_ignore_hierarchy(DB& db, const json& request) {
    const int deviceId = request.value("device_id", 0);
    if (deviceId <= 0 || !request.contains("ignore_hierarchy") || !request["ignore_hierarchy"].is_boolean()) {
        return fic::ipc::make_error_response("device_id and boolean ignore_hierarchy are required");
    }

    DeviceInfo device = db.getDeviceById(deviceId);
    if (device.id == -1) {
        return fic::ipc::make_error_response("device not found");
    }

    const bool ignoreHierarchy = request.value("ignore_hierarchy", false);
    ControlOverride override{deviceId, device.control_level, device.control_explicit, ignoreHierarchy};
    json blockers = connected_blockers_for_override(db, device, override);
    if (!blockers.empty()) {
        return json{
            {"ok", false},
            {"message", "operation would block an already connected device"},
            {"blockers", blockers}
        };
    }

    if (!db.updateDeviceIgnoreHierarchy(deviceId, ignoreHierarchy)) {
        return fic::ipc::make_error_response("failed to update ignore_hierarchy");
    }

    DeviceInfo updated = db.getDeviceById(deviceId);
    return json{{"ok", true}, {"message", "ignore_hierarchy updated"}, {"device", device_to_json(db, updated)}};
}

json reset_device_control(DB& db, const json& request) {
    const int deviceId = request.value("device_id", 0);
    if (deviceId <= 0) {
        return fic::ipc::make_error_response("device_id is required");
    }

    DeviceInfo device = db.getDeviceById(deviceId);
    if (device.id == -1) {
        return fic::ipc::make_error_response("device not found");
    }

    ControlOverride override{deviceId, device.control_level, false, false};
    json blockers = connected_blockers_for_override(db, device, override);
    if (!blockers.empty()) {
        return json{
            {"ok", false},
            {"message", "operation would block an already connected device"},
            {"blockers", blockers}
        };
    }

    if (!db.updateDeviceControl(deviceId, device.control_level, false, false)) {
        return fic::ipc::make_error_response("failed to reset device control");
    }

    DeviceInfo updated = db.getDeviceById(deviceId);
    return json{{"ok", true}, {"message", "device control reset to inheritance"}, {"device", device_to_json(db, updated)}};
}

bool can_delete_subtree(DB& db, const DeviceInfo& device, const std::string& bootId) {
    if (device.id <= 0 || device.parent_id <= 0 || device.boot_id == "-1" || is_connected(device, bootId)) {
        return false;
    }

    for (const DeviceInfo& child : db.getChildDevices(device.id)) {
        if (!can_delete_subtree(db, child, bootId)) {
            return false;
        }
    }

    return true;
}

json handle_db_request(const json& request) {
    DB db(DEVICE_DB_PATH);
    if (!db.initializeDatabase()) {
        return fic::ipc::make_error_response("failed to initialize device database");
    }

    const std::string command = request.value("command", "");
    if (command == "boot_id") {
        return json{{"ok", true}, {"message", "boot id loaded"}, {"boot_id", current_boot_id()}};
    }
    if (command == "device_root") {
        DeviceInfo root = db.getComputerRoot();
        if (root.id == -1) {
            return fic::ipc::make_error_response("device root not found");
        }
        return json{{"ok", true}, {"message", "device root loaded"}, {"device", device_to_json(db, root)}};
    }
    if (command == "device_get") {
        const int deviceId = request.value("device_id", 0);
        if (deviceId <= 0) {
            return fic::ipc::make_error_response("device_id is required");
        }
        DeviceInfo device = db.getDeviceById(deviceId);
        if (device.id == -1) {
            return fic::ipc::make_error_response("device not found");
        }
        return json{{"ok", true}, {"message", "device loaded"}, {"device", device_to_json(db, device)}};
    }
    if (command == "device_children") {
        const int parentId = request.value("parent_id", 0);
        if (parentId <= 0) {
            return fic::ipc::make_error_response("parent_id is required");
        }
        json children = json::array();
        for (const DeviceInfo& child : db.getChildDevices(parentId)) {
            children.push_back(device_to_json(db, child));
        }
        return json{{"ok", true}, {"message", "children loaded"}, {"children", children}};
    }
    if (command == "device_attributes") {
        const int deviceId = request.value("device_id", 0);
        if (deviceId <= 0) {
            return fic::ipc::make_error_response("device_id is required");
        }
        json attributes = json::object();
        for (const auto& [name, value] : db.getDeviceAttributes(deviceId)) {
            attributes[name] = value;
        }
        return json{{"ok", true}, {"message", "attributes loaded"}, {"attributes", attributes}};
    }
    if (command == "device_update_control_level") {
        return update_device_control(db, request);
    }
    if (command == "device_update_ignore_hierarchy") {
        return update_device_ignore_hierarchy(db, request);
    }
    if (command == "device_reset_control") {
        return reset_device_control(db, request);
    }
    if (command == "device_delete") {
        const int deviceId = request.value("device_id", 0);
        if (deviceId <= 0) {
            return fic::ipc::make_error_response("device_id is required");
        }
        DeviceInfo device = db.getDeviceById(deviceId);
        if (device.id == -1) {
            return fic::ipc::make_error_response("device not found");
        }
        if (!can_delete_subtree(db, device, current_boot_id())) {
            return fic::ipc::make_error_response("only disconnected non-system device subtrees can be deleted");
        }
        return db.deleteDevice(deviceId)
            ? fic::ipc::make_ok_response("device deleted")
            : fic::ipc::make_error_response("failed to delete device");
    }
    if (command == "device_events") {
        const int deviceId = request.value("device_id", 0);
        const int limit = request.value("limit", 100);
        json events = json::array();
        if (deviceId > 0) {
            for (const DeviceEvent& event : db.getDeviceEvents(deviceId, limit)) {
                events.push_back(event_to_json(event));
            }
        } else {
            for (const DeviceEvent& event : db.getRecentEvents(request.value("event_type", ""), limit)) {
                events.push_back(event_to_json(event));
            }
        }
        return json{{"ok", true}, {"message", "device events loaded"}, {"events", events}};
    }
    if (command == "device_check_permanent") {
        return check_permanent_devices(db);
    }

    return fic::ipc::make_error_response("unknown device command: " + command);
}

json handle_request(const json& request) {
    const std::string command = request.value("command", "");
    if (command == "status") {
        return fic::ipc::make_ok_response("fic device daemon is running");
    }
    if (command == "shutdown") {
        g_stop = true;
        return fic::ipc::make_ok_response("shutdown requested");
    }
    if (command == "udev_event") {
        return handle_udev_event(request);
    }

    return handle_db_request(request);
}

bool serve_one_client(int clientFd) {
    std::string requestText;
    std::string error;
    if (!fic::ipc::read_until_eof(clientFd, requestText, error)) {
        json response = fic::ipc::make_error_response("read failed: " + error);
        std::string text = response.dump() + "\n";
        fic::ipc::write_all(clientFd, text, error);
        return false;
    }

    json response;
    try {
        response = handle_request(json::parse(requestText));
    } catch (const std::exception& e) {
        response = fic::ipc::make_error_response("invalid request: " + std::string(e.what()));
    }

    std::string responseText = response.dump() + "\n";
    return fic::ipc::write_all(clientFd, responseText, error);
}

std::string get_device_socket_path_from_env() {
    const char* envPath = std::getenv("FIC_DEVICE_SOCKET_PATH");
    if (envPath != nullptr && envPath[0] != '\0') {
        return envPath;
    }
    return fic::ipc::DEFAULT_DEVICE_SOCKET_PATH;
}

bool prepare_runtime_socket(const std::string& socketPath, int serverFd) {
    const std::filesystem::path socket = socketPath;
    const std::filesystem::path runtimeDir = socket.parent_path();
    std::filesystem::create_directories(runtimeDir);

    group* ficGroup = getgrnam("fic");
    if (runtimeDir == "/run/fic" && ficGroup != nullptr) {
        ::chown(runtimeDir.c_str(), 0, ficGroup->gr_gid);
        ::chmod(runtimeDir.c_str(), 0770);
    }

    ::unlink(socketPath.c_str());

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(addr.sun_path)) {
        std::cerr << "device socket path is too long: " << socketPath << std::endl;
        return false;
    }
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(serverFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind(" << socketPath << ") failed: " << std::strerror(errno) << std::endl;
        return false;
    }

    if (ficGroup != nullptr) {
        ::chown(socketPath.c_str(), geteuid(), ficGroup->gr_gid);
    }
    ::chmod(socketPath.c_str(), 0660);
    return true;
}

} // namespace

int run_daemon(const std::string& socketPathArg) {
    const std::string socketPath = socketPathArg.empty() ? get_device_socket_path_from_env() : socketPathArg;

    {
        DB db(DEVICE_DB_PATH);
        if (!db.initializeDatabase()) {
            std::cerr << "failed to initialize device database" << std::endl;
            return 1;
        }
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    int serverFd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverFd < 0) {
        std::cerr << "socket() failed: " << std::strerror(errno) << std::endl;
        return 1;
    }

    if (!prepare_runtime_socket(socketPath, serverFd)) {
        ::close(serverFd);
        return 1;
    }

    if (::listen(serverFd, 16) < 0) {
        std::cerr << "listen(" << socketPath << ") failed: " << std::strerror(errno) << std::endl;
        ::close(serverFd);
        ::unlink(socketPath.c_str());
        return 1;
    }

    log_device("fic-dick device daemon started on " + socketPath, logLevel::INFO);

    while (!g_stop) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(serverFd, &readSet);

        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ready = ::select(serverFd + 1, &readSet, nullptr, nullptr, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "select(" << socketPath << ") failed: " << std::strerror(errno) << std::endl;
            break;
        }
        if (ready == 0 || !FD_ISSET(serverFd, &readSet)) {
            continue;
        }

        int clientFd = ::accept(serverFd, nullptr, nullptr);
        if (clientFd < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "accept() failed: " << std::strerror(errno) << std::endl;
            break;
        }

        serve_one_client(clientFd);
        ::close(clientFd);
    }

    ::close(serverFd);
    ::unlink(socketPath.c_str());
    log_device("fic-dick device daemon stopped", logLevel::INFO);
    return 0;
}

int forward_udev_event_to_daemon(const std::map<std::string, std::string>& env) {
    auto value = [&](const std::string& key) {
        auto it = env.find(key);
        return it == env.end() ? std::string() : it->second;
    };

    json envJson = json::object();
    for (const auto& [key, val] : env) {
        envJson[key] = val;
    }

    json response = fic::ipc::Client(get_device_socket_path_from_env()).request({
        {"command", "udev_event"},
        {"action", value("ACTION")},
        {"devpath", value("DEVPATH")},
        {"subsystem", value("SUBSYSTEM")},
        {"env", envJson}
    });

    if (!response.value("ok", false)) {
        log_device("udev event failed: " + response.value("message", "unknown error"), logLevel::ERROR);
        return 1;
    }

    return 0;
}

int request_permanent_check() {
    json response = fic::ipc::Client(get_device_socket_path_from_env()).request({{"command", "device_check_permanent"}});
    if (!response.value("ok", false)) {
        log_device("permanent device check failed: " + response.value("message", "unknown error"), logLevel::ERROR);
        return 1;
    }
    return 0;
}

} // namespace fic::device_control
