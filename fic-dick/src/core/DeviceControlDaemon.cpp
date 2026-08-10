#include "DeviceControlDaemon.h"
#include "DevicePaths.h"
#include "DevicePolicyCompiler.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <iostream>
#include <map>
#include <memory>
#include <limits>
#include <optional>
#include <poll.h>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

#include <nlohmann/json.hpp>

#include <fic/core/Logger.h>
#include <fic/core/ProcessExecutor.h>
#include <fic/core/SystemBootInfo.h>
#include <fic/device-db/DB.h>
#include <fic/ipc/FicAdminSocket.h>
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
    std::string childrenControl = "inherit";
};

struct PeerCredentials {
    bool available = false;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    pid_t pid = -1;
    std::string error;
};

struct PermanentViolation {
    int deviceId = -1;
    int sourceDeviceId = -1;
    std::string devpath;
    std::string source;
};

struct DeviceEventEnvelope {
    std::string action;
    std::string devpath;
    std::string subsystem;
    std::map<std::string, std::string> env;
};

inline constexpr std::size_t MAX_DEVICE_EVENT_BYTES = 64U * 1024U;
inline constexpr std::size_t MAX_DEVICE_EVENT_QUEUE = 256U;
inline constexpr const char* DEVICE_EVENT_SOCKET_BASENAME = "fic-device-events.sock";
inline constexpr const char* DEVICE_RECONCILE_MARKER_BASENAME = "fic-device-reconcile.required";
const std::set<std::string> MANAGED_UDEV_SUBSYSTEMS = {"usb", "usbmisc", "pci", "block"};

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

bool is_static_container(const DeviceInfo& device) {
    return device.boot_id == "-1";
}

bool should_include_child_in_tree(const DeviceInfo& device,
                                  const std::string& bootId,
                                  bool includeDisconnected) {
    return includeDisconnected || is_static_container(device) || is_connected(device, bootId);
}

bool is_valid_control_level(const std::string& level) {
    return level == "blocked" || level == "allowed" || level == "permanent" || level == "ignored";
}

bool is_valid_children_control(const std::string& level) {
    return level == "allow" || level == "deny" || level == "inherit";
}

PeerCredentials peer_credentials(int fd) {
    PeerCredentials peer;
#ifdef SO_PEERCRED
    struct ucred credentials {};
    socklen_t credentialsLength = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialsLength) == 0) {
        peer.available = true;
        peer.uid = credentials.uid;
        peer.gid = credentials.gid;
        peer.pid = credentials.pid;
    } else {
        peer.error = std::strerror(errno);
    }
#else
    peer.error = "SO_PEERCRED is unavailable";
#endif
    return peer;
}

std::string sanitize_audit_value(std::string value) {
    for (char& ch : value) {
        if (ch == '\n' || ch == '\r' || ch == '\t') {
            ch = ' ';
        }
    }
    if (value.size() > 240) {
        value = value.substr(0, 240) + "...";
    }
    return value;
}

bool is_mutating_command(const std::string& command) {
    return command == "udev_event" ||
           command == "device_reconcile" ||
           command == "device_update_control_level" ||
           command == "device_update_ignore_hierarchy" ||
           command == "device_update_children_control" ||
           command == "device_regenerate_policy" ||
           command == "device_reset_control" ||
           command == "device_delete" ||
           command == "device_check_permanent" ||
           command == "shutdown";
}

std::string request_audit_summary(const json& request) {
    if (!request.is_object()) {
        return "command=<invalid-json>";
    }

    std::string summary = "command=" + sanitize_audit_value(request.value("command", ""));
    const std::vector<std::string> stringFields = {
        "action", "devpath", "subsystem", "control_level", "children_control"
    };
    for (const std::string& field : stringFields) {
        if (request.contains(field) && request[field].is_string()) {
            summary += " " + field + "=" + sanitize_audit_value(request[field].get<std::string>());
        }
    }

    const std::vector<std::string> integerFields = {"device_id", "parent_id"};
    for (const std::string& field : integerFields) {
        if (request.contains(field) && request[field].is_number_integer()) {
            summary += " " + field + "=" + std::to_string(request[field].get<int>());
        }
    }

    if (request.contains("ignore_hierarchy") && request["ignore_hierarchy"].is_boolean()) {
        summary += std::string(" ignore_hierarchy=") + (request["ignore_hierarchy"].get<bool>() ? "true" : "false");
    }
    for (const char* field : {
             "block_usb_storage", "block_printers_scanners", "block_optical_drives"}) {
        if (request.contains(field) && request[field].is_boolean()) {
            summary += std::string(" ") + field + "=" +
                (request[field].get<bool>() ? "true" : "false");
        }
    }

    return summary;
}

void write_device_audit_log(const std::string& message) {
    try {
        const std::string bootId = current_boot_id();
        const std::filesystem::path auditDir = DeviceRuntimePaths::get().logDir /
            (bootId.empty() ? "unknown_boot" : bootId) /
            "audit";
        std::filesystem::create_directories(auditDir);

        const std::filesystem::path auditFile = auditDir / ("device_audit_" + std::to_string(getpid()) + ".txt");
        std::ofstream stream(auditFile, std::ios::app);
        if (!stream.is_open()) {
            std::cerr << "failed to open device audit log: " << auditFile << std::endl;
            return;
        }

        stream << "[" << Logger::get_current_time() << "] " << message << '\n';
    } catch (const std::exception& e) {
        std::cerr << "device audit logging error: " << e.what() << std::endl;
    }
}

void audit_device_request(const PeerCredentials& peer, const json& request, const json& response) {
    const std::string command = request.is_object() ? request.value("command", "") : "";
    if (!is_mutating_command(command)) {
        return;
    }

    std::ostringstream out;
    out << "peer=";
    if (peer.available) {
        out << "uid:" << peer.uid << " gid:" << peer.gid << " pid:" << peer.pid;
    } else {
        out << "unavailable(" << sanitize_audit_value(peer.error) << ")";
    }
    out << " " << request_audit_summary(request)
        << " result=" << (response.value("ok", false) ? "ok" : "error")
        << " message=" << sanitize_audit_value(response.value("message", ""));
    write_device_audit_log(out.str());
}

DeviceInfo with_override(DeviceInfo device, const std::optional<ControlOverride>& override) {
    if (override.has_value() && device.id == override->deviceId) {
        device.control_level = override->controlLevel;
        device.control_explicit = override->controlExplicit;
        device.ignore_hierarchy = override->ignoreHierarchy;
        device.children_control = override->childrenControl;
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

std::optional<std::string> find_udevadm();

bool regenerate_device_policy(DB& db, const std::string& reason, std::string& error) {
    log_device("device policy compilation started: " + reason, logLevel::INFO);
    DevicePolicyCompiler compiler({
        std::string(FIC_PRIVATE_BINDIR) + "/fic-dick"
    });
    const DevicePolicyCompilation compilation = compiler.compile(db);
    if (!compilation.ok) {
        error = compilation.error;
        log_device("device policy compilation failed: " + error, logLevel::ERROR);
        return false;
    }
    log_device("device policy compilation succeeded", logLevel::INFO);

    const std::optional<std::string> udevadm = find_udevadm();
    if (!udevadm.has_value()) {
        error = "udevadm not found";
        log_device("device policy activation failed: " + error, logLevel::ERROR);
        return false;
    }
    DevicePolicyActivator activator({
        std::filesystem::path(FIC_UDEV_RULES_DIR) / "99-fic-devices.rules",
        udevadm.value()
    });
    if (!activator.activate(compilation.rules, error)) {
        log_device("device policy activation failed: " + error, logLevel::ERROR);
        return false;
    }
    log_device("device policy activation and udev reload succeeded", logLevel::INFO);

    const std::int64_t desiredRevision = db.getDesiredPolicyRevision();
    if (desiredRevision < 0 || !db.setActivePolicyRevision(desiredRevision)) {
        error = "active udev rules were published but active policy revision could not be recorded";
        log_device(error, logLevel::ERROR);
        return false;
    }
    return true;
}

json policy_activation_error(DB& db, const std::string& operation, const std::string& error) {
    return json{
        {"ok", false},
        {"message", operation + " was saved as desired policy, but udev policy activation failed: " + error},
        {"desired_policy_revision", db.getDesiredPolicyRevision()},
        {"active_policy_revision", db.getActivePolicyRevision()}
    };
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
    const DeviceCategoryPolicyState settings = db.getDeviceCategoryPolicyState();
    if (!settings.block_usb_storage && !settings.block_printers_scanners &&
        !settings.block_optical_drives) {
        return std::nullopt;
    }

    const std::map<std::string, std::string> attributes = db.getDeviceAttributes(device.id);
    if (settings.block_usb_storage && is_usb_storage_device(device, attributes)) {
        return EffectivePolicy{"blocked", "dc:block_usb_storage", device.id, "USB storage is blocked by DC settings"};
    }
    if (settings.block_printers_scanners && is_printer_or_scanner(device, attributes)) {
        return EffectivePolicy{"blocked", "dc:block_printers_scanners", device.id, "printers/scanners are blocked by DC settings"};
    }
    if (settings.block_optical_drives && is_optical_drive(device, attributes)) {
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

    for (DeviceInfo candidate : db.getDevicesByHashAndSubsystem(device.device_hash, device.subsystem)) {
        candidate = with_override(candidate, override);
        if (candidate.control_explicit && candidate.ignore_hierarchy) {
            return EffectivePolicy{candidate.control_level,
                                   "identity:" + std::to_string(candidate.id),
                                   candidate.id,
                                   "explicit same-identity rule with ignore_hierarchy=true"};
        }
    }

    if (device.control_explicit) {
        return EffectivePolicy{device.control_level,
                               "placement:" + std::to_string(device.id),
                               device.id,
                               "explicit placement rule"};
    }

    if (std::optional<EffectivePolicy> categoryPolicy = dc_category_policy(db, device)) {
        return categoryPolicy.value();
    }

    for (std::size_t i = 1; i < path.size(); ++i) {
        const DeviceInfo& parent = path[i];
        if (parent.children_control != "inherit") {
            return EffectivePolicy{parent.children_control == "deny" ? "blocked" : "allowed",
                                   "children:" + std::to_string(parent.id),
                                   parent.id,
                                   "nearest explicit ancestor children rule"};
        }
    }

    return EffectivePolicy{"allowed", "default", -1, "default allow"};
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

bool deny_enforcement_observed(const DeviceInfo& device, std::string& details) {
    const std::filesystem::path sysDevice =
        std::filesystem::path("/sys") / device.devpath.substr(1);
    std::error_code error;
    if (!std::filesystem::exists(sysDevice, error) && !error) {
        details = "device sysfs path is absent after udev enforcement";
        return true;
    }
    if (device.subsystem == "usb" || device.subsystem == "usbmisc") {
        const auto authorized = find_parent_sysfs_file(device.devpath, "authorized");
        if (!authorized.has_value()) {
            details = "USB authorized state is unavailable after udev enforcement";
            return false;
        }
        std::ifstream input(authorized.value());
        std::string value;
        input >> value;
        if (value == "0") {
            details = "USB authorized=0 observed after udev enforcement";
            return true;
        }
        details = "USB remains authorized after generated deny rule";
        return false;
    }
    details = "device sysfs path still exists after generated deny rule";
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

bool identity_connected(DB& db, const DeviceInfo& device, const std::string& bootId) {
    if (device.id <= 0 || bootId.empty()) {
        return false;
    }

    if (is_static_container(device)) {
        return true;
    }

    for (const DeviceInfo& occurrence : db.getDevicesByHashAndSubsystem(device.device_hash, device.subsystem)) {
        if (is_connected(occurrence, bootId)) {
            return true;
        }
    }

    return false;
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
        {"children_control", device.children_control},
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

void add_deferred_block_warning(json& response, const json& blockers) {
    if (!blockers.empty()) {
        response["deferred_block"] = true;
        response["deferred_blockers"] = blockers;
        response["warning"] =
            "connected devices were not deactivated; block will be enforced on reconnect";
    }
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

    return identity_connected(db, source, bootId);
}

std::vector<PermanentViolation> collect_missing_permanent_devices(DB& db,
                                                                  const std::optional<std::vector<int>>& candidateIds = std::nullopt) {
    std::vector<DeviceInfo> candidates;
    if (candidateIds.has_value()) {
        for (int deviceId : candidateIds.value()) {
            DeviceInfo device = db.getDeviceById(deviceId);
            if (device.id != -1) {
                candidates.push_back(device);
            }
        }
    } else {
        candidates = db.getAllDevices();
    }

    std::vector<PermanentViolation> missing;
    std::set<std::string> seenObligations;

    for (const DeviceInfo& device : candidates) {
        const EffectivePolicy policy = effective_policy(db, device);
        if (policy.level != "permanent") {
            continue;
        }
        if (permanent_satisfied(db, device, policy)) {
            continue;
        }

        DeviceInfo source = policy.sourceDeviceId > 0 ? db.getDeviceById(policy.sourceDeviceId) : device;
        if (source.id == -1) {
            source = device;
        }

        const std::string obligationKey = source.device_hash + "\n" + source.subsystem;
        if (!seenObligations.insert(obligationKey).second) {
            continue;
        }

        missing.push_back(PermanentViolation{device.id, source.id, device.devpath, policy.source});
    }

    return missing;
}

json missing_permanent_to_json(const std::vector<PermanentViolation>& violations) {
    json result = json::array();
    for (const PermanentViolation& violation : violations) {
        result.push_back({
            {"device_id", violation.deviceId},
            {"source_device_id", violation.sourceDeviceId},
            {"devpath", violation.devpath},
            {"source", violation.source}
        });
    }
    return result;
}

json check_permanent_devices(DB& db, const std::optional<std::vector<int>>& candidateIds = std::nullopt) {
    const std::vector<PermanentViolation> violations = collect_missing_permanent_devices(db, candidateIds);

    if (violations.empty()) {
        return fic::ipc::make_ok_response("all permanent devices are connected");
    }

    std::string lockMessage;
    const bool locked = call_fic_lock(lockMessage);
    for (const PermanentViolation& violation : violations) {
        add_event(db,
                  violation.deviceId,
                  "lock",
                  locked ? "success" : "error",
                  "permanent device is missing; fic lock: " + lockMessage);
    }

    return json{
        {"ok", locked},
        {"message", locked ? "missing permanent device; computer locked" : "missing permanent device; failed to lock computer"},
        {"missing", missing_permanent_to_json(violations)},
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
    if (subsystem == "usbmisc") {
        return std::make_unique<UDEVInfoCollector>(
            std::vector<std::string>{"DEVNAME", "DEVPATH", "MAJOR", "MINOR"}
        );
    }
    return std::make_unique<UDEVInfoCollector>(
        std::vector<std::string>{"DEVPATH", "SUBSYSTEM", "DEVTYPE", "MODALIAS"}
    );
}

bool is_managed_subsystem(const std::string& subsystem) {
    return MANAGED_UDEV_SUBSYSTEMS.find(subsystem) != MANAGED_UDEV_SUBSYSTEMS.end();
}

DeviceEventEnvelope envelope_from_request(const json& request) {
    DeviceEventEnvelope event;
    event.action = request.value("action", "");
    event.devpath = request.value("devpath", "");
    event.subsystem = request.value("subsystem", "");
    if (request.contains("env") && request["env"].is_object()) {
        for (auto it = request["env"].begin(); it != request["env"].end(); ++it) {
            if (it.value().is_string()) {
                event.env[it.key()] = it.value().get<std::string>();
            }
        }
    }
    return event;
}

json process_device_event(const DeviceEventEnvelope& event) {
    const std::string& action = event.action;
    const std::string& devpath = event.devpath;
    const std::string& subsystem = event.subsystem;

    if (action.empty() || devpath.empty() || subsystem.empty()) {
        return fic::ipc::make_error_response("action, devpath and subsystem are required");
    }
    if (!is_managed_subsystem(subsystem)) {
        return fic::ipc::make_ok_response("udev event ignored: unmanaged subsystem");
    }

    UDEVInfoCollector baseCollector;
    if (!baseCollector.check_devpath(devpath.c_str())) {
        return fic::ipc::make_ok_response("udev event ignored: non-physical devpath");
    }

    std::unique_ptr<UDEVInfoCollector> collector = create_collector_for_subsystem(subsystem);
    collector->set_udev_env(event.env);

    if (action == "add" || action == "change") {
        if (!collector->create_device_config(devpath, subsystem)) {
            return fic::ipc::make_error_response("failed to add/update device");
        }

        DB db(DeviceRuntimePaths::get().databaseOptions());
        db.initializeDatabase();
        DeviceInfo device = db.getDeviceByDevpathSubsystemAndBootId(devpath, subsystem, current_boot_id());
        if (device.id == -1) {
            device = db.getDeviceByDevpathAndSubsystem(devpath, subsystem);
        }
        if (device.id == -1) {
            return fic::ipc::make_error_response("device was updated but cannot be found in database");
        }

        const std::string generatedLevel = attribute_value(event.env, "FIC_EFFECTIVE_LEVEL");
        const std::string generatedSource = attribute_value(event.env, "FIC_POLICY_SOURCE");
        const std::string effectiveLevel = generatedLevel.empty() ? "ALLOW" : generatedLevel;
        const std::string effectiveSource = generatedSource.empty() ? "bootstrap-rule" : generatedSource;
        add_event(db, device.id, "connect", "success",
                  "generated_effective=" + effectiveLevel + "; source=" + effectiveSource);

        if (effectiveLevel == "DENY") {
            std::string enforcementDetails;
            const bool enforced = deny_enforcement_observed(device, enforcementDetails);
            add_event(db,
                      device.id,
                      "block",
                      enforced ? "success" : "error",
                      enforcementDetails + "; source=" + effectiveSource);
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

        add_event(db, device.id, "allow", "success",
                  "no deny enforcement requested; source=" + effectiveSource);

        return json{
            {"ok", true},
            {"message", "device accepted"},
            {"device", device_to_json(db, device)}
        };
    }

    if (action == "remove") {
        DB dbBefore(DeviceRuntimePaths::get().databaseOptions());
        dbBefore.initializeDatabase();
        DeviceInfo before = dbBefore.getDeviceByDevpathAndSubsystem(devpath, subsystem);
        std::vector<int> affectedIds;
        if (before.id != -1) {
            affectedIds.push_back(before.id);
            for (const DeviceInfo& descendant : dbBefore.getDescendantDevices(before.id)) {
                affectedIds.push_back(descendant.id);
            }
        }

        if (!collector->safe_remove_device(devpath, subsystem)) {
            return fic::ipc::make_error_response("failed to mark device as removed");
        }

        DB db(DeviceRuntimePaths::get().databaseOptions());
        db.initializeDatabase();
        DeviceInfo device = db.getDeviceByDevpathAndSubsystem(devpath, subsystem);
        if (device.id != -1) {
            add_event(db, device.id, "disconnect", "success", "device removed");
        }

        if (!affectedIds.empty()) {
            json permanentCheck = check_permanent_devices(db, affectedIds);
            if (!permanentCheck.value("ok", true)) {
                permanentCheck["message"] = permanentCheck.value(
                    "message",
                    "permanent device disconnected; failed to lock computer");
                if (device.id != -1) {
                    permanentCheck["device"] = device_to_json(db, device);
                }
                return permanentCheck;
            }
        }

        return fic::ipc::make_ok_response("device removed");
    }

    return fic::ipc::make_error_response("unsupported udev action: " + action);
}

json handle_udev_event(const json& request) {
    return process_device_event(envelope_from_request(request));
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
    if (controlLevel == "permanent" && !identity_connected(db, device, bootId)) {
        return fic::ipc::make_error_response("cannot mark absent device as permanent");
    }

    ControlOverride override{
        deviceId, controlLevel, true, ignoreHierarchy, device.children_control
    };
    const json blockers = connected_blockers_for_override(db, device, override);

    if (!db.updateDeviceControl(
            deviceId, controlLevel, true, ignoreHierarchy, device.children_control)) {
        return fic::ipc::make_error_response("failed to update device control");
    }

    std::string activationError;
    if (!regenerate_device_policy(db, "device control update", activationError)) {
        return policy_activation_error(db, "device control update", activationError);
    }

    DeviceInfo updated = db.getDeviceById(deviceId);
    json response = json{
        {"ok", true},
        {"message", "device control updated"},
        {"device", device_to_json(db, updated)},
        {"desired_policy_revision", db.getDesiredPolicyRevision()},
        {"active_policy_revision", db.getActivePolicyRevision()}
    };
    add_deferred_block_warning(response, blockers);
    return response;
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
    ControlOverride override{
        deviceId,
        device.control_level,
        device.control_explicit,
        ignoreHierarchy,
        device.children_control
    };
    const json blockers = connected_blockers_for_override(db, device, override);

    if (!db.updateDeviceIgnoreHierarchy(deviceId, ignoreHierarchy)) {
        return fic::ipc::make_error_response("failed to update ignore_hierarchy");
    }

    std::string activationError;
    if (!regenerate_device_policy(db, "ignore_hierarchy update", activationError)) {
        return policy_activation_error(db, "ignore_hierarchy update", activationError);
    }

    DeviceInfo updated = db.getDeviceById(deviceId);
    json response = json{
        {"ok", true},
        {"message", "ignore_hierarchy updated"},
        {"device", device_to_json(db, updated)},
        {"desired_policy_revision", db.getDesiredPolicyRevision()},
        {"active_policy_revision", db.getActivePolicyRevision()}
    };
    add_deferred_block_warning(response, blockers);
    return response;
}

json update_device_children_control(DB& db, const json& request) {
    const int deviceId = request.value("device_id", 0);
    const std::string childrenControl = request.value("children_control", "");
    if (deviceId <= 0 || !is_valid_children_control(childrenControl)) {
        return fic::ipc::make_error_response(
            "valid device_id and children_control are required");
    }
    DeviceInfo device = db.getDeviceById(deviceId);
    if (device.id == -1) {
        return fic::ipc::make_error_response("device not found");
    }

    ControlOverride override{
        deviceId,
        device.control_level,
        device.control_explicit,
        device.ignore_hierarchy,
        childrenControl
    };
    const json blockers = connected_blockers_for_override(db, device, override);
    if (!db.updateDeviceChildrenControl(deviceId, childrenControl)) {
        return fic::ipc::make_error_response("failed to update children_control");
    }
    std::string activationError;
    if (!regenerate_device_policy(db, "children_control update", activationError)) {
        return policy_activation_error(db, "children_control update", activationError);
    }

    json response = json{
        {"ok", true},
        {"message", "children_control updated"},
        {"device", device_to_json(db, db.getDeviceById(deviceId))},
        {"desired_policy_revision", db.getDesiredPolicyRevision()},
        {"active_policy_revision", db.getActivePolicyRevision()}
    };
    add_deferred_block_warning(response, blockers);
    return response;
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

    ControlOverride override{deviceId, device.control_level, false, false, "inherit"};
    const json blockers = connected_blockers_for_override(db, device, override);

    if (!db.updateDeviceControl(deviceId, device.control_level, false, false, "inherit")) {
        return fic::ipc::make_error_response("failed to reset device control");
    }

    std::string activationError;
    if (!regenerate_device_policy(db, "device policy reset", activationError)) {
        return policy_activation_error(db, "device policy reset", activationError);
    }

    DeviceInfo updated = db.getDeviceById(deviceId);
    json response = json{
        {"ok", true},
        {"message", "device control reset to inheritance"},
        {"device", device_to_json(db, updated)},
        {"desired_policy_revision", db.getDesiredPolicyRevision()},
        {"active_policy_revision", db.getActivePolicyRevision()}
    };
    add_deferred_block_warning(response, blockers);
    return response;
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
    DB db(DeviceRuntimePaths::get().databaseOptions());
    if (!db.initializeDatabase()) {
        return fic::ipc::make_error_response("failed to initialize device database");
    }

    const std::string command = request.value("command", "");
    if (command == "boot_id") {
        return json{{"ok", true}, {"message", "boot id loaded"}, {"boot_id", current_boot_id()}};
    }
    if (command == "device_tree_revision") {
        const std::int64_t revision = db.getDeviceTreeRevision();
        if (revision < 0) {
            return fic::ipc::make_error_response("failed to load device tree revision");
        }
        return json{
            {"ok", true},
            {"message", "device tree revision loaded"},
            {"revision", revision}
        };
    }
    if (command == "device_policy_status") {
        const std::int64_t desired = db.getDesiredPolicyRevision();
        const std::int64_t active = db.getActivePolicyRevision();
        if (desired < 0 || active < 0) {
            return fic::ipc::make_error_response("failed to load device policy revisions");
        }
        return json{
            {"ok", true},
            {"message", "device policy status loaded"},
            {"desired_policy_revision", desired},
            {"active_policy_revision", active},
            {"policy_active", desired == active}
        };
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
        const bool includeDisconnected = request.value("include_disconnected", false);
        if (parentId <= 0) {
            return fic::ipc::make_error_response("parent_id is required");
        }
        json children = json::array();
        const std::string bootId = current_boot_id();
        for (const DeviceInfo& child : db.getChildDevices(parentId)) {
            if (!should_include_child_in_tree(child, bootId, includeDisconnected)) {
                continue;
            }
            children.push_back(device_to_json(db, child));
        }
        return json{
            {"ok", true},
            {"message", "children loaded"},
            {"children", children},
            {"include_disconnected", includeDisconnected}
        };
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
    if (command == "device_update_children_control") {
        return update_device_children_control(db, request);
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
        if (!db.deleteDevice(deviceId)) {
            return fic::ipc::make_error_response("failed to delete device");
        }
        std::string activationError;
        if (!regenerate_device_policy(db, "device policy deletion", activationError)) {
            return policy_activation_error(db, "device deletion", activationError);
        }
        return fic::ipc::make_ok_response("device deleted and udev policy regenerated");
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
bool run_device_reconciliation(const std::string& reason);
json handle_request(
    const json& request,
    const PeerCredentials& peer) {

    const std::string command =
        request.value("command", "");

    if (command == "status") {
        return json{
            {"ok", true},
            {"message", "fic device daemon is running"},
            {"product_version", fic::version::PRODUCT_VERSION},
            {"database_schema_version",
             fic::version::DEVICE_DB_SCHEMA_VERSION}
        };
    }

    if (command == "shutdown") {
        g_stop = true;
        return fic::ipc::make_ok_response(
            "shutdown requested");
    }

    if (command == "udev_event") {
        if (!peer.available || peer.uid != 0) {
            return fic::ipc::make_error_response(
                "udev_event requires root peer credentials");
        }

        return handle_udev_event(request);
    }

    if (command == "device_reconcile") {
        if (!peer.available || peer.uid != 0) {
            return fic::ipc::make_error_response(
                "device_reconcile requires root peer credentials");
        }

        if (!run_device_reconciliation(
                "explicit reconciliation request")) {
            return fic::ipc::make_error_response(
                "device reconciliation failed");
        }

        return fic::ipc::make_ok_response(
            "device reconciliation completed");
    }

    if (command == "device_regenerate_policy") {
        if (!peer.available || peer.uid != 0) {
            return fic::ipc::make_error_response(
                "device_regenerate_policy requires root peer credentials");
        }
        DB db(DeviceRuntimePaths::get().databaseOptions());
        const DeviceCategoryPolicyState categories{
            request.value("block_usb_storage", false),
            request.value("block_printers_scanners", false),
            request.value("block_optical_drives", false)
        };
        if (!db.initializeDatabase() ||
            !db.updateDeviceCategoryPolicyState(categories)) {
            return fic::ipc::make_error_response(
                "failed to save category policy state in device database");
        }
        std::string activationError;
        if (!regenerate_device_policy(db, "DC configuration changed", activationError)) {
            return policy_activation_error(db, "DC configuration update", activationError);
        }
        return json{
            {"ok", true},
            {"message", "device policy regenerated"},
            {"desired_policy_revision", db.getDesiredPolicyRevision()},
            {"active_policy_revision", db.getActivePolicyRevision()}
        };
    }

    return handle_db_request(request);
}

bool validate_device_request_schema(const json& request, std::string& error) {
    for (const char* field : {
             "action", "devpath", "subsystem", "control_level",
             "children_control", "event_type"}) {
        if (request.contains(field) && !request[field].is_string()) {
            error = std::string("request.") + field + " must be a string";
            return false;
        }
    }
    for (const char* field : {"device_id", "parent_id", "limit"}) {
        if (!request.contains(field)) {
            continue;
        }
        const json& value = request[field];
        const bool inRange = value.is_number_unsigned()
            ? value.get<std::uint64_t>() <= static_cast<std::uint64_t>(std::numeric_limits<int>::max())
            : value.is_number_integer() &&
                value.get<std::int64_t>() >= std::numeric_limits<int>::min() &&
                value.get<std::int64_t>() <= std::numeric_limits<int>::max();
        if (!inRange) {
            error = std::string("request.") + field + " must be a 32-bit integer";
            return false;
        }
    }
    for (const char* field : {
             "include_disconnected", "ignore_hierarchy", "block_usb_storage",
             "block_printers_scanners", "block_optical_drives"}) {
        if (request.contains(field) && !request[field].is_boolean()) {
            error = std::string("request.") + field + " must be a boolean";
            return false;
        }
    }
    if (request.contains("env")) {
        if (!request["env"].is_object()) {
            error = "request.env must be an object";
            return false;
        }
        for (auto item = request["env"].begin(); item != request["env"].end(); ++item) {
            if (!item.value().is_string()) {
                error = "request.env values must be strings";
                return false;
            }
        }
    }
    if (request.contains("limit")) {
        const int limit = request["limit"].get<int>();
        if (limit < 1 || limit > 500) {
            error = "request.limit must be between 1 and 500";
            return false;
        }
    }

    const std::string command = request.at("command").get<std::string>();
    if (command == "shutdown" ||
        command == "device_check_permanent" ||
        command == "device_reconcile") {

        return fic::ipc::request_has_only_fields(
            request,
            {"command"},
            error);
    }
    if (command == "device_regenerate_policy") {
        for (const char* field : {
                 "block_usb_storage", "block_printers_scanners",
                 "block_optical_drives"}) {
            if (!request.contains(field) || !request[field].is_boolean()) {
                error = std::string("request.") + field + " must be present and boolean";
                return false;
            }
        }
        return fic::ipc::request_has_only_fields(
            request,
            {"command", "block_usb_storage", "block_printers_scanners",
             "block_optical_drives"},
            error);
    }
    if (command == "udev_event") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "action", "devpath", "subsystem", "env"}, error);
    }
    if (command == "device_update_control_level") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "device_id", "control_level", "ignore_hierarchy"}, error);
    }
    if (command == "device_update_ignore_hierarchy") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "device_id", "ignore_hierarchy"}, error);
    }
    if (command == "device_update_children_control") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "device_id", "children_control"}, error);
    }
    if (command == "device_reset_control" || command == "device_delete") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "device_id"}, error);
    }
    return true;
}

std::string handle_client_packet(int clientFd, const std::string& requestText) {
    const PeerCredentials peer = peer_credentials(clientFd);
    std::string error;
    json response;
    json request;
    if (fic::ipc::parse_request_json(requestText, request, error) &&
        validate_device_request_schema(request, error)) {
        response = handle_request(request, peer);
    } else {
        response = fic::ipc::make_error_response("invalid request: " + error);
    }

    audit_device_request(peer, request, response);
    response["api_version"] = fic::ipc::API_VERSION;
    return response.dump();
}

std::string get_device_socket_path_from_env() {
    return fic::ipc::endpoint_socket_path(fic::ipc::Endpoint::DeviceDaemon);
}

bool is_missing_device_socket_error(const json& response, const std::string& socketPath) {
    const std::string message = response.value("message", "");
    const std::string prefix = "connect(" + socketPath + ") failed: ";
    if (message.rfind(prefix, 0) != 0) {
        return false;
    }

    return message.find("No such file or directory", prefix.size()) != std::string::npos ||
           message.find("Нет такого файла", prefix.size()) != std::string::npos;
}

std::string device_event_socket_path() {
    const char* environmentPath = std::getenv("FIC_DEVICE_EVENT_SOCKET_PATH");
    if (environmentPath != nullptr && environmentPath[0] != '\0') {
        return environmentPath;
    }
    return (std::filesystem::path(fic::ipc::DEFAULT_RUNTIME_DIR) /
            DEVICE_EVENT_SOCKET_BASENAME).string();
}

std::filesystem::path device_reconcile_marker_path() {
    return std::filesystem::path(fic::ipc::DEFAULT_RUNTIME_DIR) /
           DEVICE_RECONCILE_MARKER_BASENAME;
}

bool write_reconcile_marker() {
    try {
        const std::filesystem::path marker = device_reconcile_marker_path();

        // Runtime directory is owned by the FIC/systemd lifecycle.
        // The udev helper must not manufacture the IPC/runtime directory itself.
        if (!std::filesystem::is_directory(marker.parent_path())) {
            return false;
        }

        const int fd = ::open(
            marker.c_str(),
            O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
            0600);

        if (fd < 0) {
            return false;
        }

        bool ok = true;

        struct stat st {};
        if (::fstat(fd, &st) != 0 ||
            !S_ISREG(st.st_mode) ||
            st.st_uid != 0) {
            ok = false;
        }

        if (ok && ::fchmod(fd, 0600) != 0) {
            ok = false;
        }

        // The file is a boolean marker, not an event log.
        // Keeping it empty guarantees bounded size even during an event storm.
        if (ok && ::ftruncate(fd, 0) != 0) {
            ok = false;
        }

        if (::close(fd) != 0) {
            ok = false;
        }

        return ok;
    } catch (const std::exception&) {
        return false;
    }
}

std::string event_key(const DeviceEventEnvelope& event) {
    return event.subsystem + "\n" + event.devpath;
}

bool parse_event_payload(const std::string& payload,
                         DeviceEventEnvelope& event,
                         std::string& error) {
    json request;
    try {
        request = json::parse(payload);
    } catch (const std::exception& exception) {
        error = exception.what();
        return false;
    }
    if (!request.is_object()) {
        error = "event payload must be a JSON object";
        return false;
    }
    for (const char* field : {"action", "devpath", "subsystem"}) {
        if (!request.contains(field) || !request[field].is_string() ||
            request[field].get_ref<const std::string&>().empty()) {
            error = std::string("event.") + field + " must be a non-empty string";
            return false;
        }
    }
    if (request["devpath"].get_ref<const std::string&>().size() > 4096 ||
        request["subsystem"].get_ref<const std::string&>().size() > 64 ||
        request["action"].get_ref<const std::string&>().size() > 32) {
        error = "event header exceeds size limit";
        return false;
    }
    if (request.contains("env")) {
        if (!request["env"].is_object() || request["env"].size() > 4096) {
            error = "event.env must be a bounded object";
            return false;
        }
        for (auto item = request["env"].begin(); item != request["env"].end(); ++item) {
            if (item.key().size() > 1024 || !item.value().is_string() ||
                item.value().get_ref<const std::string&>().size() > 16U * 1024U) {
                error = "event.env contains an invalid key or value";
                return false;
            }
        }
    }
    event = envelope_from_request(request);
    if (!is_managed_subsystem(event.subsystem)) {
        error = "event subsystem is unmanaged";
        return false;
    }
    return true;
}

int create_event_socket(const std::string& socketPath, std::string& error) {
    const std::filesystem::path path(socketPath);
    if (path.empty() || !path.is_absolute() || path.lexically_normal() != path) {
        error = "device event socket path must be absolute and normalized";
        return -1;
    }
    std::error_code fsError;
    std::filesystem::create_directories(path.parent_path(), fsError);
    if (fsError) {
        error = "could not create event socket runtime directory: " + fsError.message();
        return -1;
    }
    if (::chown(path.parent_path().c_str(), 0, 0) != 0 ||
        ::chmod(path.parent_path().c_str(), 0755) != 0) {
        error = "failed to enforce event socket runtime directory metadata: " +
                std::string(std::strerror(errno));
        return -1;
    }

    struct stat existing {};
    if (::lstat(socketPath.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid != geteuid()) {
            error = "refusing to replace unsafe device event socket path";
            return -1;
        }
        if (::unlink(socketPath.c_str()) != 0) {
            error = "could not remove stale device event socket: " +
                    std::string(std::strerror(errno));
            return -1;
        }
    } else if (errno != ENOENT) {
        error = "lstat event socket failed: " + std::string(std::strerror(errno));
        return -1;
    }

    const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        error = "event socket() failed: " + std::string(std::strerror(errno));
        return -1;
    }
    const int enable = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enable, sizeof(enable)) != 0) {
        error = "SO_PASSCRED failed: " + std::string(std::strerror(errno));
        ::close(fd);
        return -1;
    }

    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(address.sun_path)) {
        error = "event socket path is too long";
        ::close(fd);
        return -1;
    }
    std::strncpy(address.sun_path, socketPath.c_str(), sizeof(address.sun_path) - 1);
    const socklen_t addressLength = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + socketPath.size() + 1U);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), addressLength) != 0) {
        error = "bind event socket failed: " + std::string(std::strerror(errno));
        ::close(fd);
        return -1;
    }
    if (::chmod(socketPath.c_str(), 0600) != 0) {
        error = "chmod event socket failed: " + std::string(std::strerror(errno));
        ::close(fd);
        ::unlink(socketPath.c_str());
        return -1;
    }
    return fd;
}

class DeviceEventQueue {
public:
    bool enqueue(DeviceEventEnvelope event) {
        const std::string key = event_key(event);
        if (event.action == "change") {
            auto it = pendingChangeByKey_.find(key);
            if (it != pendingChangeByKey_.end() && it->second < queue_.size() &&
                queue_[it->second].action == "change") {
                queue_[it->second] = std::move(event);
                ++coalesced_;
                return true;
            }
        }
        if (queue_.size() >= MAX_DEVICE_EVENT_QUEUE) {
            reconciliationRequired_ = true;
            ++overflowed_;
            return false;
        }
        queue_.push_back(std::move(event));
        if (queue_.back().action == "change") {
            pendingChangeByKey_[key] = queue_.size() - 1;
        }
        return true;
    }

    bool pop(DeviceEventEnvelope& event) {
        if (queue_.empty()) {
            return false;
        }
        event = std::move(queue_.front());
        queue_.pop_front();
        rebuildChangeIndex();
        return true;
    }

    bool reconciliationRequired() const {
        return reconciliationRequired_;
    }

    void requestReconciliation() {
        reconciliationRequired_ = true;
    }

    void clearReconciliationRequired() {
        reconciliationRequired_ = false;
    }

    std::size_t coalesced() const {
        return coalesced_;
    }

    std::size_t overflowed() const {
        return overflowed_;
    }

private:
    void rebuildChangeIndex() {
        pendingChangeByKey_.clear();
        for (std::size_t i = 0; i < queue_.size(); ++i) {
            if (queue_[i].action == "change") {
                pendingChangeByKey_[event_key(queue_[i])] = i;
            }
        }
    }

    std::deque<DeviceEventEnvelope> queue_;
    std::unordered_map<std::string, std::size_t> pendingChangeByKey_;
    bool reconciliationRequired_ = false;
    std::size_t coalesced_ = 0;
    std::size_t overflowed_ = 0;
};

bool receive_event_datagrams(int eventFd, DeviceEventQueue& queue) {
    bool receivedAny = false;
    while (true) {
        std::vector<char> buffer(MAX_DEVICE_EVENT_BYTES + 1U);
        char control[CMSG_SPACE(sizeof(struct ucred))] {};
        iovec iov {buffer.data(), buffer.size()};
        msghdr message {};
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        const ssize_t received = ::recvmsg(eventFd, &message, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return receivedAny;
            }
            log_device("device event socket recvmsg failed: " + std::string(std::strerror(errno)), logLevel::ERROR);
            return receivedAny;
        }
        receivedAny = true;
        if ((message.msg_flags & MSG_TRUNC) != 0 ||
            received <= 0 ||
            static_cast<std::size_t>(received) > MAX_DEVICE_EVENT_BYTES) {
            queue.requestReconciliation();
            log_device("device event ingestion received oversized payload; reconciliation scheduled", logLevel::WARN);
            continue;
        }
        bool trustedRoot = false;
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&message); cmsg != nullptr; cmsg = CMSG_NXTHDR(&message, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
                cmsg->cmsg_len >= CMSG_LEN(sizeof(struct ucred))) {
                auto* credentials = reinterpret_cast<struct ucred*>(CMSG_DATA(cmsg));
                trustedRoot = credentials != nullptr && credentials->uid == 0;
            }
        }
        if (!trustedRoot) {
            log_device("device event rejected: sender is not root", logLevel::WARN);
            continue;
        }
        DeviceEventEnvelope event;
        std::string error;
        if (!parse_event_payload(std::string(buffer.data(), static_cast<std::size_t>(received)), event, error)) {
            queue.requestReconciliation();
            log_device("device event rejected: " + error + "; reconciliation scheduled", logLevel::WARN);
            continue;
        }
        if (!queue.enqueue(std::move(event))) {
            log_device("device event queue overflow; reconciliation scheduled", logLevel::WARN);
        }
    }
}

bool process_queued_event(DeviceEventQueue& queue) {
    DeviceEventEnvelope event;
    if (!queue.pop(event)) {
        return false;
    }
    json result = process_device_event(event);
    if (!result.value("ok", false)) {
        queue.requestReconciliation();
        log_device("queued udev event failed: " + result.value("message", "unknown error") +
                   "; reconciliation scheduled", logLevel::ERROR);
    }
    return true;
}

std::vector<DeviceEventEnvelope> parse_udevadm_export_db(const std::string& text) {
    std::vector<DeviceEventEnvelope> events;
    DeviceEventEnvelope current;
    auto flush = [&]() {
        if (!current.devpath.empty()) {
            if (current.env.count("DEVPATH") == 0) {
                current.env["DEVPATH"] = current.devpath;
            }
            if (current.env.count("SUBSYSTEM") > 0) {
                current.subsystem = current.env["SUBSYSTEM"];
            }
            current.action = "add";
            if (is_managed_subsystem(current.subsystem)) {
                events.push_back(current);
            }
        }
        current = DeviceEventEnvelope{};
    };

    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            flush();
            continue;
        }
        if (line.rfind("P: ", 0) == 0) {
            current.devpath = line.substr(3);
            current.env["DEVPATH"] = current.devpath;
        } else if (line.rfind("E: ", 0) == 0) {
            const std::string entry = line.substr(3);
            const std::size_t separator = entry.find('=');
            if (separator != std::string::npos && separator > 0) {
                current.env[entry.substr(0, separator)] = entry.substr(separator + 1);
            }
        }
    }
    flush();
    return events;
}

std::optional<std::string> find_udevadm() {
    for (const char* candidate : {"/usr/bin/udevadm", "/usr/sbin/udevadm", "/sbin/udevadm", "/bin/udevadm"}) {
        if (::access(candidate, X_OK) == 0) {
            return std::string(candidate);
        }
    }
    return std::nullopt;
}

bool sysfs_devpath_exists(const std::string& devpath) {
    if (devpath.empty() || devpath[0] != '/') {
        return false;
    }
    std::error_code error;
    return std::filesystem::exists(std::filesystem::path("/sys") / devpath.substr(1), error) && !error;
}
bool run_device_reconciliation(const std::string& reason) {
    log_device("device reconciliation started: " + reason, logLevel::INFO);
    const std::optional<std::string> udevadm = find_udevadm();
    if (!udevadm.has_value()) {
        log_device("device reconciliation failed: udevadm not found", logLevel::ERROR);
        return false;
    }

    ProcessOptions options;
    options.timeout = std::chrono::milliseconds(15000);
    ProcessResult result = ProcessExecutor::execute(udevadm.value(), {"info", "--export-db"}, options);
    if (!result.success()) {
        log_device("device reconciliation failed: udevadm info --export-db failed: " +
                   result.error + " " + result.standardError, logLevel::ERROR);
        return false;
    }

    std::size_t processed = 0;
    for (const DeviceEventEnvelope& event : parse_udevadm_export_db(result.standardOutput)) {
        UDEVInfoCollector checker;
        if (!checker.check_devpath(event.devpath.c_str())) {
            continue;
        }
        json response = process_device_event(event);
        if (response.value("ok", false)) {
            ++processed;
        } else {
            log_device("device reconciliation event failed: " +
                       response.value("message", "unknown error"), logLevel::ERROR);
        }
    }

    DB db(DeviceRuntimePaths::get().databaseOptions());
    db.initializeDatabase();
    const std::string bootId = current_boot_id();
    std::size_t removed = 0;
    for (const DeviceInfo& device : db.getAllDevices()) {
        if (device.boot_id != bootId || !is_managed_subsystem(device.subsystem) ||
            sysfs_devpath_exists(device.devpath)) {
            continue;
        }
        if (reset_subtree_boot_id(db, device.id)) {
            add_event(db, device.id, "disconnect", "success", "device absent during reconciliation");
            ++removed;
        }
    }

    json permanentCheck = check_permanent_devices(db);
    if (!permanentCheck.value("ok", true)) {
        log_device("device reconciliation permanent check failed: " +
                   permanentCheck.value("message", "unknown error"), logLevel::ERROR);
    }
    log_device("device reconciliation completed: processed=" + std::to_string(processed) +
               " removed=" + std::to_string(removed), logLevel::INFO);
    return true;
}

} // namespace

int run_daemon(const std::string& socketPathArg) {
    const std::string socketPath = socketPathArg.empty()
        ? std::string(fic::ipc::DEFAULT_DEVICE_SOCKET_PATH)
        : socketPathArg;

    {
        DB db(DeviceRuntimePaths::get().databaseOptions());
        if (!db.initializeDatabase()) {
            std::cerr << "failed to initialize device database" << std::endl;
            return 1;
        }
        std::string activationError;
        if (!regenerate_device_policy(db, "daemon startup", activationError)) {
            std::cerr << "failed to activate device policy: " << activationError << std::endl;
            return 1;
        }
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    fic::ipc::AdminSocketOptions socketOptions;
    socketOptions.socketPath = socketPath;
    socketOptions.security = socketPathArg.empty()
        ? fic::ipc::AdminSocketSecurityProfile::ProductionAdmin
        : fic::ipc::AdminSocketSecurityProfile::Development;
    socketOptions.backlog = 16;
    socketOptions.label = "fic device daemon socket";
    fic::ipc::AdminSocketResult socketResult =
        fic::ipc::create_admin_server_socket(socketOptions);
    if (socketResult.fileDescriptor < 0) {
        std::cerr << socketResult.error;
        if (socketResult.existingPeerPid.has_value()) {
            std::cerr << ", pid=" << socketResult.existingPeerPid.value();
        }
        std::cerr << std::endl;
        return 1;
    }
    const int serverFd = socketResult.fileDescriptor;
    fic::ipc::AdminSocketTransport transport(serverFd);

    std::string eventSocketError;
    const std::string eventSocketPath = device_event_socket_path();
    const int eventFd = create_event_socket(eventSocketPath, eventSocketError);
    if (eventFd < 0) {
        std::cerr << eventSocketError << std::endl;
        ::close(serverFd);
        ::unlink(socketPath.c_str());
        return 1;
    }

    DeviceEventQueue eventQueue;

    log_device("fic-dick device daemon started on " + socketPath +
               ", event_socket=" + eventSocketPath, logLevel::INFO);
    if (!run_device_reconciliation("daemon startup")) {
        eventQueue.requestReconciliation();
    }

    while (!g_stop) {
        receive_event_datagrams(eventFd, eventQueue);

        const std::filesystem::path marker = device_reconcile_marker_path();
        std::error_code markerError;

        const bool markerExists =
            std::filesystem::exists(marker, markerError);

        if (markerError) {
            log_device(
                "failed to inspect device reconciliation marker: " +
                markerError.message(),
                logLevel::ERROR);
        } else if (markerExists) {
            // Сам факт существования marker уже достаточен.
            eventQueue.requestReconciliation();

            std::filesystem::remove(marker, markerError);
            if (markerError) {
                log_device(
                    "device reconciliation marker could not be removed: " +
                    markerError.message(),
                    logLevel::WARN);
            } else {
                log_device(
                    "device reconciliation marker consumed",
                    logLevel::WARN);
            }
        }
        if (eventQueue.reconciliationRequired()) {
            if (run_device_reconciliation("event ingestion recovery")) {
                eventQueue.clearReconciliationRequired();
            } else {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(250));
            }
        }
        for (int i = 0; i < 8; ++i) {
            if (!process_queued_event(eventQueue)) {
                break;
            }
        }

        std::string transportError;
        if (!transport.pollOnce(50,
                [](int clientFd, const std::string& requestText) {
                    return handle_client_packet(clientFd, requestText);
                },
                transportError)) {
            std::cerr << transportError << std::endl;
            break;
        }
    }

    ::close(eventFd);
    ::unlink(eventSocketPath.c_str());
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

    const std::string action = value("ACTION");
    const std::string devpath = value("DEVPATH");
    const std::string subsystem = value("SUBSYSTEM");
    if (action.empty() || devpath.empty() || subsystem.empty()) {
        log_device("udev event not sent: ACTION, DEVPATH and SUBSYSTEM are required", logLevel::ERROR);
        return 1;
    }
    if (!is_managed_subsystem(subsystem)) {
        return 0;
    }

    json envJson = json::object();
    for (const auto& [key, val] : env) {
        envJson[key] = val;
    }

    json payload = {
        {"action", action},
        {"devpath", devpath},
        {"subsystem", subsystem},
        {"env", envJson}
    };
    const std::string payloadText = payload.dump();

    if (payloadText.empty() || payloadText.size() > MAX_DEVICE_EVENT_BYTES) {
        if (!write_reconcile_marker()) {
            log_device(
                "udev event not sent and reconciliation marker could not be created: "
                "payload exceeds event socket limit",
                logLevel::ERROR);
            return 1;
        }

        log_device(
            "udev event not sent: payload exceeds event socket limit; "
            "reconciliation marked",
            logLevel::WARN);
        return 0;
    }

    const std::string socketPath = device_event_socket_path();
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(250);

    std::string lastError;
    int lastErrno = 0;

    while (std::chrono::steady_clock::now() < deadline) {
        const int fd =
        ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);

        if (fd < 0) {
            lastErrno = errno;
            lastError = std::strerror(lastErrno);
            break;
        }

        sockaddr_un address {};
        address.sun_family = AF_UNIX;

        if (socketPath.size() >= sizeof(address.sun_path)) {
            ::close(fd);

            log_device(
                "udev event socket path is too long",
                logLevel::ERROR);

            return 1;
        }

        std::strncpy(
            address.sun_path,
            socketPath.c_str(),
            sizeof(address.sun_path) - 1);

        const socklen_t addressLength =
            static_cast<socklen_t>(
                offsetof(sockaddr_un, sun_path) +
                socketPath.size() +
                1U);

        if (::connect(
                fd,
                reinterpret_cast<sockaddr*>(&address),
                addressLength) == 0) {

        const ssize_t sent =
            ::send(
                fd,
                payloadText.data(),
                payloadText.size(),
                MSG_NOSIGNAL);

        if (sent ==
            static_cast<ssize_t>(payloadText.size())) {
            ::close(fd);
            return 0;
        }

        lastErrno = errno;
        lastError = std::strerror(lastErrno);
    } else {
        lastErrno = errno;
        lastError = std::strerror(lastErrno);
    }

    ::close(fd);

    /*
     * ENOENT/ENOTDIR means the runtime event endpoint does not
     * exist yet. This is normal during early boot or while the
     * device daemon is stopped.
     *
     * Every fic-device daemon start performs full reconciliation
     * from authoritative udev/sysfs state, therefore preserving
     * this individual incremental event is unnecessary.
     *
     * Do not create a reconciliation marker here: the runtime directory may
     * not exist yet either, and daemon startup itself is the
     * recovery guarantee.
     */
    if (lastErrno == ENOENT || lastErrno == ENOTDIR) {
        return 0;
    }

    std::this_thread::sleep_for(
        std::chrono::milliseconds(25));
}

const std::string reason =
    "udev event delivery failed: " + lastError;

/*
 * For failures where the runtime infrastructure exists but
 * incremental delivery failed, explicitly request reconciliation.
 */
if (!write_reconcile_marker()) {
    log_device(
        "udev event delivery failed and reconciliation marker "
        "could not be created: " +
        lastError,
        logLevel::ERROR);
    return 1;
}

log_device(
    reason + "; reconciliation marked",
    logLevel::WARN);

return 0;
}

int wait_for_daemon(int timeoutSeconds) {
    if (timeoutSeconds < 0) {
        timeoutSeconds = 0;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSeconds);
    json response;
    do {
        response = fic::ipc::Client(
            get_device_socket_path_from_env(),
            std::chrono::seconds(1)).request({{"command", "status"}});
        if (response.value("ok", false) &&
            response.value("product_version", "") ==
                fic::version::PRODUCT_VERSION &&
            response.value("database_schema_version", -1) ==
                fic::version::DEVICE_DB_SCHEMA_VERSION) {
            return 0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } while (std::chrono::steady_clock::now() < deadline);

    log_device("device daemon did not become ready: " + response.value("message", "unknown error"), logLevel::ERROR);
    return 1;
}

int request_permanent_check() {
    json response = fic::ipc::Client(get_device_socket_path_from_env()).request({{"command", "device_check_permanent"}});
    if (!response.value("ok", false)) {
        log_device("permanent device check failed: " + response.value("message", "unknown error"), logLevel::ERROR);
        return 1;
    }
    return 0;
}
int request_reconciliation() {
    json response =
        fic::ipc::Client(
            get_device_socket_path_from_env(),
            std::chrono::seconds(60))
            .request({
                {"command", "device_reconcile"}
            });

    if (!response.value("ok", false)) {
        log_device(
            "device reconciliation request failed: " +
            response.value(
                "message",
                "unknown error"),
            logLevel::ERROR);

        return 1;
    }

    return 0;
}

} // namespace fic::device_control
