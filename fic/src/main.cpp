#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <clocale>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <locale>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/select.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/main_function.h"
#include <fic/ipc/FicIpcClient.h>
#include <fic/device-db/DB.h>
#include <fic/core/Logger.h>
#include <fic/core/SystemBootInfo.h>

using json = nlohmann::json;

namespace {
std::atomic_bool g_stop{false};

struct PeerCredentials {
    bool available = false;
    pid_t pid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    std::string error;
};

void handle_signal(int) {
    g_stop = true;
}

std::string get_arg_value(int argc, char* argv[], int index) {
    if (index >= argc) {
        return "";
    }
    return argv[index];
}

int get_interval_seconds(int argc, char* argv[]) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--interval") {
            try {
                int value = std::stoi(argv[i + 1]);
                return value > 0 ? value : 1800;
            } catch (...) {
                return 1800;
            }
        }
    }
    return 1800;
}

std::string get_socket_path(int argc, char* argv[]) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--socket") {
            return argv[i + 1];
        }
    }
    return fic::ipc::DEFAULT_SOCKET_PATH;
}

std::string to_lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string sanitize_log_value(std::string value) {
    for (char& ch : value) {
        if (ch == '\n' || ch == '\r' || ch == '\t') {
            ch = ' ';
        }
    }
    return value;
}

std::string peer_credentials_to_string(const PeerCredentials& peer) {
    if (!peer.available) {
        return "peer=unknown error=\"" + sanitize_log_value(peer.error) + "\"";
    }

    return "peer_pid=" + std::to_string(peer.pid) +
           " peer_uid=" + std::to_string(peer.uid) +
           " peer_gid=" + std::to_string(peer.gid);
}

PeerCredentials get_peer_credentials(int fd) {
    PeerCredentials peer;
#ifdef SO_PEERCRED
    struct ucred credentials {};
    socklen_t credentialsLength = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialsLength) == 0) {
        peer.available = true;
        peer.pid = credentials.pid;
        peer.uid = credentials.uid;
        peer.gid = credentials.gid;
        return peer;
    }
    peer.error = std::strerror(errno);
#else
    peer.error = "SO_PEERCRED is unavailable";
#endif
    return peer;
}

std::string request_audit_summary(const json& request) {
    if (!request.is_object()) {
        return "command=<invalid-json>";
    }

    std::string summary = "command=" + sanitize_log_value(request.value("command", ""));

    const std::vector<std::string> stringFields = {"module", "policy", "control_level"};
    for (const std::string& field : stringFields) {
        if (request.contains(field) && request[field].is_string()) {
            summary += " " + field + "=" + sanitize_log_value(request[field].get<std::string>());
        }
    }

    const std::vector<std::string> integerFields = {"device_id", "parent_id"};
    for (const std::string& field : integerFields) {
        if (request.contains(field) && request[field].is_number_integer()) {
            summary += " " + field + "=" + std::to_string(request[field].get<int>());
        }
    }

    return summary;
}

void write_audit_log(const std::string& message) {
    try {
        const std::string bootId = SystemBootInfo::get_boot_id();
        const std::filesystem::path auditDir = std::filesystem::path("/opt/fic/log") /
            (bootId.empty() ? "unknown_boot" : bootId) /
            "audit";
        std::filesystem::create_directories(auditDir);

        const std::filesystem::path auditFile = auditDir / ("audit_" + std::to_string(getpid()) + ".txt");
        std::ofstream stream(auditFile, std::ios::app);
        if (!stream.is_open()) {
            std::cerr << "failed to open audit log: " << auditFile << std::endl;
            return;
        }

        stream << "[" << Logger::get_current_time() << "] " << message << '\n';
    } catch (const std::exception& e) {
        std::cerr << "audit logging error: " << e.what() << std::endl;
    }
}

void audit_ipc_request(const PeerCredentials& peer, const json& request, const json& response) {
    const bool ok = response.value("ok", false);
    const std::string responseMessage = response.value("message", "");

    write_audit_log(
        peer_credentials_to_string(peer) + " " +
        request_audit_summary(request) +
        " ok=" + std::string(ok ? "true" : "false") +
        " message=\"" + sanitize_log_value(responseMessage) + "\""
    );
}

std::string mode_to_octal(mode_t mode) {
    std::ostringstream out;
    out << "0" << std::oct << (mode & 07777);
    return out.str();
}

bool verify_path_permissions(const std::filesystem::path& path,
                             const std::string& label,
                             mode_t expectedType,
                             mode_t expectedMode,
                             uid_t expectedUid,
                             std::optional<gid_t> expectedGid) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        std::cerr << "lstat(" << path << ") failed while checking " << label
                  << ": " << std::strerror(errno) << std::endl;
        return false;
    }

    if ((info.st_mode & S_IFMT) != expectedType) {
        std::cerr << label << " has invalid type: " << path << std::endl;
        return false;
    }
    if (info.st_uid != expectedUid) {
        std::cerr << label << " has invalid owner: " << path
                  << ", expected uid=" << expectedUid
                  << ", actual uid=" << info.st_uid << std::endl;
        return false;
    }
    if (expectedGid.has_value() && info.st_gid != expectedGid.value()) {
        std::cerr << label << " has invalid group: " << path
                  << ", expected gid=" << expectedGid.value()
                  << ", actual gid=" << info.st_gid << std::endl;
        return false;
    }

    const mode_t actualMode = info.st_mode & 07777;
    if (actualMode != expectedMode) {
        std::cerr << label << " has invalid permissions: " << path
                  << ", expected mode=" << mode_to_octal(expectedMode)
                  << ", actual mode=" << mode_to_octal(actualMode) << std::endl;
        return false;
    }

    return true;
}

bool verify_runtime_socket_permissions(const std::string& socketPath, const group* ficGroup) {
    const auto runtimeDir = std::filesystem::path(socketPath).parent_path();
    const bool isDefaultRuntimeDir = runtimeDir == std::filesystem::path("/run/fic");

    std::optional<gid_t> expectedGid;
    if (ficGroup != nullptr) {
        expectedGid = ficGroup->gr_gid;
    }

    if (isDefaultRuntimeDir) {
        if (ficGroup == nullptr) {
            std::cerr << "group 'fic' does not exist; refusing to expose default daemon socket" << std::endl;
            return false;
        }
        if (!verify_path_permissions(runtimeDir, "fic runtime directory", S_IFDIR, 0770, 0, expectedGid)) {
            return false;
        }
    }

    return verify_path_permissions(socketPath, "fic daemon socket", S_IFSOCK, 0660, geteuid(), expectedGid);
}

std::string canonical_module_name(
    const std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<Policy>>>>& cafMap,
    const std::string& module
) {
    if (module.empty() || module == "all") {
        return module;
    }

    auto exact = cafMap.find(module);
    if (exact != cafMap.end()) {
        return module;
    }

    const std::string lowered = to_lower_ascii(module);
    for (const auto& [moduleName, _] : cafMap) {
        if (to_lower_ascii(moduleName) == lowered) {
            return moduleName;
        }
    }

    return module;
}
json policy_to_json(const std::string& module,
                    const std::string& submoduleName,
                    const std::string& policyName,
                    const std::shared_ptr<Policy>& policyClass) {
    const PolicyTypeValue& typeValue = policyClass->getPolicyTypeValue();
    const PolicyEditorSpec editorSpec = typeValue.getEditorSpec();
    const bool isSet = policyClass->hasConfiguredValue();
    bool valueValid = true;
    std::string value = policyClass->getDefaultValue();

    if (isSet) {
        try {
            std::optional<std::string> currentValue = policyClass->getValue();
            if (currentValue.has_value()) {
                value = currentValue.value();
            } else {
                valueValid = false;
            }
        } catch (const std::exception&) {
            valueValid = false;
        }
    }

    json possibleValues = json::array();
    for (const std::string& possibleValue : editorSpec.possibleValues) {
        possibleValues.push_back(possibleValue);
    }

    json item = {
        {"module", module},
        {"submodule", submoduleName},
        {"policy", policyName},
        {"enabled", policyClass->isEnabled()},
        {"set", isSet},
        {"value", value},
        {"value_valid", valueValid},
        {"default_value", policyClass->getDefaultValue()},
        {"editor", editorSpec.editor},
        {"possible_values", possibleValues},
        {"restriction", policyClass->getPolicyRestriction()}
    };

    if (editorSpec.min.has_value()) {
        item["min"] = editorSpec.min.value();
    }
    if (editorSpec.max.has_value()) {
        item["max"] = editorSpec.max.value();
    }
    if (editorSpec.textDelimiter.has_value()) {
        item["text_delimiter"] = editorSpec.textDelimiter.value();
    }

    return item;
}

json policy_list_json(const std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<Policy>>>>& cafMap,
                      const std::string& module) {
    json result = json::array();
    auto moduleIt = cafMap.find(module);
    if (moduleIt == cafMap.end()) {
        return result;
    }

    for (const auto& [submoduleName, policyMap] : moduleIt->second) {
        for (const auto& [policyName, policyClass] : policyMap) {
            result.push_back(policy_to_json(module, submoduleName, policyName, policyClass));
        }
    }
    return result;
}

json policy_status_json(
    std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<Policy>>>>& cafMap,
    const std::string& module,
    const std::string& policy
) {
    std::shared_ptr<Policy> policyClass = getPolicyClass(cafMap, module, policy);
    if (policyClass == nullptr) {
        return fic::ipc::make_error_response("policy not found: " + module + " " + policy);
    }

    const bool enabled = policyClass->isEnabled();
    return json{
        {"ok", true},
        {"message", "policy status loaded"},
        {"module", module},
        {"policy", policy},
        {"enabled", enabled},
        {"disabled", !enabled}
    };
}

json policy_value_json(
    std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<Policy>>>>& cafMap,
    const std::string& module,
    const std::string& policy
) {
    std::shared_ptr<Policy> policyClass = getPolicyClass(cafMap, module, policy);
    if (policyClass == nullptr) {
        return fic::ipc::make_error_response("policy not found: " + module + " " + policy);
    }
    if (!policyClass->hasConfiguredValue()) {
        return fic::ipc::make_error_response("policy value is not set: " + module + " " + policy);
    }

    std::optional<std::string> currentValue = policyClass->getValue();
    if (!currentValue.has_value()) {
        return fic::ipc::make_error_response("policy value is invalid: " + module + " " + policy);
    }

    return json{
        {"ok", true},
        {"message", "policy value loaded"},
        {"module", module},
        {"policy", policy},
        {"value", currentValue.value()}
    };
}

json policy_apply_result_json(const PolicyApplyResult& result) {
    return json{
        {"module", result.moduleName},
        {"submodule", result.submoduleName},
        {"policy", result.policyName},
        {"status", policyApplyStatusToString(result.status)},
        {"message", result.message}
    };
}

json policy_apply_summary_json(const PolicyApplySummary& summary, bool ok, const std::string& message) {
    json results = json::array();
    for (const PolicyApplyResult& result : summary.getResults()) {
        results.push_back(policy_apply_result_json(result));
    }

    return json{
        {"ok", ok},
        {"message", message},
        {"summary", {
            {"total", summary.totalCount()},
            {"applied", summary.appliedCount()},
            {"failed", summary.failedCount()},
            {"disabled", summary.disabledCount()},
            {"not_found", summary.notFoundCount()}
        }},
        {"results", results}
    };
}

std::string policy_apply_message(const PolicyApplySummary& summary,
                                 bool ok,
                                 const std::string& successMessage,
                                 const std::string& failureMessage) {
    if (ok) {
        return successMessage;
    }

    const std::vector<PolicyApplyResult>& results = summary.getResults();
    if (results.size() == 1 && !results.front().message.empty()) {
        return results.front().message;
    }

    return failureMessage;
}

constexpr const char* DEVICE_DB_PATH = "/opt/fic/db/devices.db";
constexpr const char* LOG_BASE_PATH = "/opt/fic/log";
constexpr const char* LOCK_STATUS_PATH = "/opt/fic/lockstatus";

json device_to_json(const DeviceInfo& device) {
    return json{
        {"id", device.id},
        {"device_hash", device.device_hash},
        {"devpath", device.devpath},
        {"subsystem", device.subsystem},
        {"device_type", device.device_type},
        {"parent_id", device.parent_id},
        {"control_level", device.control_level},
        {"ignore_hierarchy", device.ignore_hierarchy},
        {"boot_id", device.boot_id},
        {"created_at", device.created_at},
        {"last_event_at", device.last_event_at},
        {"notes", device.notes}
    };
}

json with_device_db(const std::function<json(DB&)>& action) {
    DB db(DEVICE_DB_PATH);
    if (!db.initializeDatabase()) {
        return fic::ipc::make_error_response("failed to initialize devices database");
    }
    if (!db.acquireLock()) {
        return fic::ipc::make_error_response("failed to lock devices database");
    }

    try {
        json response = action(db);
        db.releaseLock();
        return response;
    } catch (const std::exception& e) {
        db.releaseLock();
        return fic::ipc::make_error_response("device database error: " + std::string(e.what()));
    }
}

json log_records_json(const std::string& requestedBootId) {
    const std::string bootId = requestedBootId.empty()
        ? SystemBootInfo::get_boot_id()
        : requestedBootId;

    json categories = json::array();
    json records = json::array();
    if (bootId.empty()) {
        return json{{"ok", true}, {"message", "logs loaded"}, {"boot_id", bootId}, {"categories", categories}, {"records", records}};
    }

    const std::filesystem::path bootDir = std::filesystem::path(LOG_BASE_PATH) / bootId;
    if (!std::filesystem::exists(bootDir) || !std::filesystem::is_directory(bootDir)) {
        return json{{"ok", true}, {"message", "logs loaded"}, {"boot_id", bootId}, {"categories", categories}, {"records", records}};
    }

    std::vector<std::filesystem::path> categoryDirs;
    for (const auto& entry : std::filesystem::directory_iterator(bootDir)) {
        if (entry.is_directory()) {
            categoryDirs.push_back(entry.path());
        }
    }
    std::sort(categoryDirs.begin(), categoryDirs.end());

    for (const auto& categoryDir : categoryDirs) {
        const std::string category = categoryDir.filename().string();
        categories.push_back(category);

        std::vector<std::filesystem::path> logFiles;
        for (const auto& entry : std::filesystem::directory_iterator(categoryDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".txt") {
                logFiles.push_back(entry.path());
            }
        }
        std::sort(logFiles.begin(), logFiles.end());

        for (const auto& logFile : logFiles) {
            std::ifstream stream(logFile);
            if (!stream.is_open()) {
                continue;
            }

            std::string line;
            while (std::getline(stream, line)) {
                if (line.empty()) {
                    continue;
                }
                records.push_back({
                    {"category", category},
                    {"source_file", logFile.string()},
                    {"line", line},
                    {"byte_size", line.size()}
                });
            }
        }
    }

    return json{{"ok", true}, {"message", "logs loaded"}, {"boot_id", bootId}, {"categories", categories}, {"records", records}};
}

json lock_status_json() {
    SingleLineFileHandler lockStatus(LOCK_STATUS_PATH);
    if (!lockStatus.loadConfig()) {
        return fic::ipc::make_error_response("failed to read lock status");
    }

    const bool locked = lockStatus.getValue() != "0";
    return json{
        {"ok", true},
        {"message", locked ? "locked" : "unlocked"},
        {"locked", locked}
    };
}

json handle_request(json request,
                    std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<Policy>>>>& cafMap) {
    const std::string command = request.value("command", "");
    const std::string requestedModule = request.value("module", "");
    const std::string module = canonical_module_name(cafMap, requestedModule);
    const std::string policy = request.value("policy", "");
    const std::string value = request.value("value", "");

    try {
        if (command == "status") {
            return fic::ipc::make_ok_response("fic daemon is running");
        }
        if (command == "boot_id") {
            return json{
                {"ok", true},
                {"message", "boot id loaded"},
                {"boot_id", SystemBootInfo::get_boot_id()}
            };
        }
        if (command == "localization_bundle") {
            json translations = json::object();
            for (const auto& [key, value] : LocalizationManager::getTranslations()) {
                translations[key] = value;
            }
            return json{
                {"ok", true},
                {"message", "localization loaded"},
                {"language", LocalizationManager::getCurrentLanguage()},
                {"translations", translations}
            };
        }
        if (command == "shutdown") {
            g_stop = true;
            return fic::ipc::make_ok_response("shutdown requested");
        }
        if (command == "module_list") {
            json modules = json::array();
            for (const auto& [moduleName, _] : cafMap) {
                modules.push_back(moduleName);
            }
            return json{{"ok", true}, {"message", "modules listed"}, {"modules", modules}};
        }
        if (command == "policy_list") {
            if (module == "all") {
                json all = json::array();
                for (const auto& [moduleName, _] : cafMap) {
                    for (const auto& item : policy_list_json(cafMap, moduleName)) {
                        all.push_back(item);
                    }
                }
                return json{{"ok", true}, {"message", "policies listed"}, {"policies", all}};
            }
            if (module.empty()) {
                return fic::ipc::make_error_response("module is required");
            }
            return json{{"ok", true}, {"message", "policies listed"}, {"policies", policy_list_json(cafMap, module)}};
        }
        if (command == "policy_is_enabled" || command == "policy_is_disabled" || command == "policy_value") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            if (command == "policy_value") {
                return policy_value_json(cafMap, module, policy);
            }
            return policy_status_json(cafMap, module, policy);
        }
        if (command == "set_policy_value") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            bool ok = set(cafMap, module, policy, value);
            if (ok) {
                cafMap = init_cafMap();
            }
            return ok ? fic::ipc::make_ok_response("policy value updated")
                      : fic::ipc::make_error_response("failed to update policy value");
        }
        if (command == "enable_policy") {
            bool ok = enable(cafMap, module, policy);
            if (ok) {
                cafMap = init_cafMap();
            }
            return ok ? fic::ipc::make_ok_response("policy enabled")
                      : fic::ipc::make_error_response("failed to enable policy");
        }
        if (command == "disable_policy") {
            bool ok = disable(cafMap, module, policy);
            if (ok) {
                cafMap = init_cafMap();
            }
            return ok ? fic::ipc::make_ok_response("policy disabled")
                      : fic::ipc::make_error_response("failed to disable policy");
        }
        if (command == "reload_config") {
            cafMap = init_cafMap();
            return fic::ipc::make_ok_response("config reloaded");
        }
        if (command == "apply_all") {
            cafMap = init_cafMap();
            PolicyApplySummary summary = applyAllPolicies(cafMap);
            const bool ok = isPolicyApplySuccessful(summary, "all", "");
            return policy_apply_summary_json(
                summary,
                ok,
                policy_apply_message(summary, ok, "all enabled policies applied", "failed to apply one or more policies")
            );
        }
        if (command == "apply_module") {
            if (module.empty()) {
                return fic::ipc::make_error_response("module is required");
            }
            cafMap = init_cafMap();
            PolicyApplySummary summary = applyModulePolicies(cafMap, module);
            const bool ok = isPolicyApplySuccessful(summary, module, "all");
            return policy_apply_summary_json(
                summary,
                ok,
                policy_apply_message(summary, ok, "module policies applied", "failed to apply module policies")
            );
        }
        if (command == "apply_policy") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            cafMap = init_cafMap();
            PolicyApplySummary summary;
            summary.add(applyPolicy(cafMap, module, policy));
            const bool ok = isPolicyApplySuccessful(summary, module, policy);
            return policy_apply_summary_json(
                summary,
                ok,
                policy_apply_message(summary, ok, "policy applied", "failed to apply policy")
            );
        }
        if (command == "device_get") {
            int deviceId = request.value("device_id", 0);
            if (deviceId <= 0) {
                return fic::ipc::make_error_response("device_id is required");
            }
            return with_device_db([deviceId](DB& db) {
                DeviceInfo device = db.getDeviceById(deviceId);
                if (device.id == -1) {
                    return fic::ipc::make_error_response("device not found");
                }
                return json{{"ok", true}, {"message", "device loaded"}, {"device", device_to_json(device)}};
            });
        }
        if (command == "device_children") {
            int parentId = request.value("parent_id", 0);
            if (parentId <= 0) {
                return fic::ipc::make_error_response("parent_id is required");
            }
            return with_device_db([parentId](DB& db) {
                json children = json::array();
                for (const DeviceInfo& child : db.getChildDevices(parentId)) {
                    children.push_back(device_to_json(child));
                }
                return json{{"ok", true}, {"message", "children loaded"}, {"children", children}};
            });
        }
        if (command == "device_attributes") {
            int deviceId = request.value("device_id", 0);
            if (deviceId <= 0) {
                return fic::ipc::make_error_response("device_id is required");
            }
            return with_device_db([deviceId](DB& db) {
                json attributes = json::object();
                for (const auto& [name, value] : db.getDeviceAttributes(deviceId)) {
                    attributes[name] = value;
                }
                return json{{"ok", true}, {"message", "attributes loaded"}, {"attributes", attributes}};
            });
        }
        if (command == "device_update_control_level") {
            int deviceId = request.value("device_id", 0);
            std::string controlLevel = request.value("control_level", "");
            if (deviceId <= 0 || controlLevel.empty()) {
                return fic::ipc::make_error_response("device_id and control_level are required");
            }
            return with_device_db([deviceId, controlLevel](DB& db) {
                bool ok = db.updateDeviceControlLevel(deviceId, controlLevel);
                return ok ? fic::ipc::make_ok_response("device control level updated")
                          : fic::ipc::make_error_response("failed to update device control level");
            });
        }
        if (command == "device_delete") {
            int deviceId = request.value("device_id", 0);
            if (deviceId <= 0) {
                return fic::ipc::make_error_response("device_id is required");
            }
            return with_device_db([deviceId](DB& db) {
                bool ok = db.deleteDevice(deviceId);
                return ok ? fic::ipc::make_ok_response("device deleted")
                          : fic::ipc::make_error_response("failed to delete device");
            });
        }
        if (command == "log_records") {
            return log_records_json(request.value("boot_id", ""));
        }
        if (command == "calc_hash") {
            bool ok = calcHash(value);
            return ok ? fic::ipc::make_ok_response("command hash updated")
                      : fic::ipc::make_error_response("failed to update command hash");
        }
        if (command == "lock") {
            bool ok = lock();
            return ok ? fic::ipc::make_ok_response("computer locked")
                      : fic::ipc::make_error_response("failed to lock computer");
        }
        if (command == "unlock") {
            bool ok = unlock();
            return ok ? fic::ipc::make_ok_response("computer unlocked")
                      : fic::ipc::make_error_response("failed to unlock computer");
        }
        if (command == "lockstatus") {
            return lock_status_json();
        }

        return fic::ipc::make_error_response("unknown command: " + command);
    } catch (const std::exception& e) {
        return fic::ipc::make_error_response("exception: " + std::string(e.what()));
    }
}

bool serve_one_client(int clientFd,
                      std::map<std::string, std::map<std::string, std::map<std::string, std::shared_ptr<Policy>>>>& cafMap) {
    const PeerCredentials peer = get_peer_credentials(clientFd);
    std::string requestText;
    std::string error;
    if (!fic::ipc::read_until_eof(clientFd, requestText, error)) {
        json response = fic::ipc::make_error_response("read failed: " + error);
        audit_ipc_request(peer, json{}, response);
        std::string text = response.dump() + "\n";
        fic::ipc::write_all(clientFd, text, error);
        return false;
    }

    json request;
    json response;
    try {
        request = json::parse(requestText);
        response = handle_request(request, cafMap);
    } catch (const std::exception& e) {
        response = fic::ipc::make_error_response("invalid request: " + std::string(e.what()));
    }

    audit_ipc_request(peer, request, response);

    std::string responseText = response.dump() + "\n";
    return fic::ipc::write_all(clientFd, responseText, error);
}

bool probe_existing_daemon(const std::string& socketPath,
                           std::optional<pid_t>& daemonPid,
                           int& connectError,
                           std::string& error) {
    connectError = 0;

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = "socket() failed: " + std::string(std::strerror(errno));
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(addr.sun_path)) {
        error = "socket path is too long: " + socketPath;
        ::close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        connectError = errno;
        error = std::strerror(errno);
        ::close(fd);
        return false;
    }

#ifdef SO_PEERCRED
    struct ucred credentials {};
    socklen_t credentialsLength = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialsLength) == 0) {
        daemonPid = credentials.pid;
    }
#endif

    std::string ioError;
    const std::string requestText = json{{"command", "status"}}.dump() + "\n";
    fic::ipc::write_all(fd, requestText, ioError);
    ::shutdown(fd, SHUT_WR);

    std::string responseText;
    fic::ipc::read_until_eof(fd, responseText, ioError);
    ::close(fd);
    return true;
}

int create_server_socket(const std::string& socketPath) {
    const auto runtimeDir = std::filesystem::path(socketPath).parent_path();
    const bool runtimeDirAlreadyExisted = std::filesystem::exists(runtimeDir);
    std::filesystem::create_directories(runtimeDir);

    group* ficGroup = ::getgrnam("fic");
    if (runtimeDir == std::filesystem::path("/run/fic") && ficGroup == nullptr) {
        std::cerr << "group 'fic' does not exist; refusing to expose default daemon socket" << std::endl;
        return -1;
    }

    const bool manageRuntimeDirPermissions = !runtimeDirAlreadyExisted || runtimeDir == std::filesystem::path("/run/fic");
    if (manageRuntimeDirPermissions) {
        if (ficGroup != nullptr) {
            if (::chown(runtimeDir.c_str(), static_cast<uid_t>(-1), ficGroup->gr_gid) < 0) {
                std::cerr << "chown(" << runtimeDir << ") failed: " << std::strerror(errno) << std::endl;
                return -1;
            }
        }
        if (::chmod(runtimeDir.c_str(), 0770) < 0) {
            std::cerr << "chmod(" << runtimeDir << ") failed: " << std::strerror(errno) << std::endl;
            return -1;
        }
    }

    if (std::filesystem::exists(socketPath)) {
        std::optional<pid_t> daemonPid;
        int probeConnectError = 0;
        std::string probeError;
        if (probe_existing_daemon(socketPath, daemonPid, probeConnectError, probeError)) {
            std::cerr << "fic daemon is already running, socket=" << socketPath;
            if (daemonPid.has_value()) {
                std::cerr << ", pid=" << daemonPid.value();
            }
            std::cerr << std::endl;
            return -1;
        }
        if (probeConnectError != ECONNREFUSED && probeConnectError != ENOENT) {
            std::cerr << "socket exists but could not verify it is stale: " << socketPath
                      << ": " << probeError << std::endl;
            return -1;
        }
    }

    ::unlink(socketPath.c_str());

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "socket() failed: " << std::strerror(errno) << std::endl;
        return -1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(addr.sun_path)) {
        std::cerr << "socket path is too long: " << socketPath << std::endl;
        ::close(fd);
        return -1;
    }
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind(" << socketPath << ") failed: " << std::strerror(errno) << std::endl;
        ::close(fd);
        return -1;
    }

    if (ficGroup != nullptr) {
        if (::chown(socketPath.c_str(), static_cast<uid_t>(-1), ficGroup->gr_gid) < 0) {
            std::cerr << "chown(" << socketPath << ") failed: " << std::strerror(errno) << std::endl;
            ::close(fd);
            ::unlink(socketPath.c_str());
            return -1;
        }
    }
    if (::chmod(socketPath.c_str(), 0660) < 0) {
        std::cerr << "chmod(" << socketPath << ") failed: " << std::strerror(errno) << std::endl;
        ::close(fd);
        ::unlink(socketPath.c_str());
        return -1;
    }

    if (!verify_runtime_socket_permissions(socketPath, ficGroup)) {
        ::close(fd);
        ::unlink(socketPath.c_str());
        return -1;
    }

    if (::listen(fd, 32) < 0) {
        std::cerr << "listen() failed: " << std::strerror(errno) << std::endl;
        ::close(fd);
        return -1;
    }

    return fd;
}
} // namespace

int main(int argc, char* argv[]) {
    try {
        std::locale::global(std::locale("ru_RU.UTF-8"));
    } catch (const std::exception&) {
        std::setlocale(LC_ALL, "");
    }

    const bool once = get_arg_value(argc, argv, 1) == "--oneshot";
    auto cafMap = init_cafMap();

    if (once) {
        return apply(cafMap, "all", "") ? 0 : 1;
    }

    const std::string socketPath = get_socket_path(argc, argv);
    const int intervalSeconds = get_interval_seconds(argc, argv);

    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);

    int serverFd = create_server_socket(socketPath);
    if (serverFd < 0) {
        return 1;
    }

    std::cout << "fic daemon started, socket=" << socketPath
              << ", interval=" << intervalSeconds << "s" << std::endl;

    auto nextPeriodicApply = std::chrono::steady_clock::now() + std::chrono::seconds(intervalSeconds);

    while (!g_stop) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(serverFd, &readSet);

        timeval timeout{};
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int ready = ::select(serverFd + 1, &readSet, nullptr, nullptr, &timeout);
        if (ready > 0 && FD_ISSET(serverFd, &readSet)) {
            int clientFd = ::accept(serverFd, nullptr, nullptr);
            if (clientFd >= 0) {
                serve_one_client(clientFd, cafMap);
                ::close(clientFd);
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= nextPeriodicApply) {
            cafMap = init_cafMap();
            apply(cafMap, "all", "");
            nextPeriodicApply = now + std::chrono::seconds(intervalSeconds);
        }
    }

    ::close(serverFd);
    ::unlink(socketPath.c_str());
    std::cout << "fic daemon stopped" << std::endl;
    return 0;
}
