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
#include <fic/ipc/FicAdminSocket.h>
#include <fic/ipc/FicIpcClient.h>
#include <fic/core/Logger.h>
#include <fic/core/FicRuntimePaths.h>
#include <fic/core/SystemBootInfo.h>
#include "platform/PlatformCompatibility.h"
#include "platform/PlatformProfile.h"

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
        const std::filesystem::path auditDir = fic::core::FicRuntimePaths::get().logDir /
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

std::string canonical_module_name(
    const PolicyMap& policyMap,
    const std::string& module
) {
    if (module.empty() || module == "all") {
        return module;
    }

    auto exact = policyMap.find(module);
    if (exact != policyMap.end()) {
        return module;
    }

    const std::string lowered = to_lower_ascii(module);
    for (const auto& [moduleName, _] : policyMap) {
        if (to_lower_ascii(moduleName) == lowered) {
            return moduleName;
        }
    }

    return module;
}
json policy_to_json(const std::string& module,
                    const std::string& submoduleName,
                    const std::string& policyName,
                    Policy& policyClass) {
    const PolicyTypeValue& typeValue = policyClass.getPolicyTypeValue();
    const PolicyEditorSpec editorSpec = typeValue.getEditorSpec();
    const bool isSet = policyClass.hasConfiguredValue();
    bool valueValid = true;
    std::string value = policyClass.getDefaultValue();

    if (isSet) {
        try {
            std::optional<std::string> currentValue = policyClass.getValue();
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
        {"enabled", policyClass.isEnabled()},
        {"set", isSet},
        {"value", value},
        {"value_valid", valueValid},
        {"default_value", policyClass.getDefaultValue()},
        {"editor", editorSpec.editor},
        {"possible_values", possibleValues},
        {"restriction", policyClass.getPolicyRestriction()}
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

json policy_list_json(const PolicyMap& policyMap,
                      const std::string& module) {
    json result = json::array();
    auto moduleIt = policyMap.find(module);
    if (moduleIt == policyMap.end()) {
        return result;
    }

    for (const auto& [submoduleName, submodulePolicies] : moduleIt->second) {
        for (const auto& [policyName, policyClass] : submodulePolicies) {
            result.push_back(policy_to_json(module, submoduleName, policyName, *policyClass));
        }
    }
    return result;
}

json policy_status_json(
    PolicyMap& policyMap,
    const std::string& module,
    const std::string& policy
) {
    Policy* policyClass = getPolicyClass(policyMap, module, policy);
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
    PolicyMap& policyMap,
    const std::string& module,
    const std::string& policy
) {
    Policy* policyClass = getPolicyClass(policyMap, module, policy);
    if (policyClass == nullptr) {
        return fic::ipc::make_error_response("policy not found: " + module + " " + policy);
    }

    const bool configured = policyClass->hasConfiguredValue();
    std::optional<std::string> currentValue = policyClass->getValue();
    if (!currentValue.has_value()) {
        return fic::ipc::make_error_response(
            configured
                ? "policy value is invalid: " + module + " " + policy
                : "policy value is not set: " + module + " " + policy
        );
    }

    return json{
        {"ok", true},
        {"message", "policy value loaded"},
        {"module", module},
        {"policy", policy},
        {"value", currentValue.value()}
    };
}

constexpr std::size_t MAX_POLICY_DIAGNOSTICS_RESPONSE_BYTES = 256 * 1024;

json policy_apply_result_json(const PolicyApplyResult& result,
                              std::size_t& remainingDiagnosticsBytes,
                              bool& responseDiagnosticsTruncated) {
    json diagnostics = json::array();
    bool diagnosticsTruncated = result.diagnosticsTruncated;
    for (const PolicyDiagnostic& diagnostic : result.diagnostics) {
        json item = {
            {"timestamp", diagnostic.timestamp},
            {"level", diagnostic.level},
            {"category", diagnostic.category},
            {"message", diagnostic.message}
        };
        const std::size_t serializedSize = item.dump().size();
        if (serializedSize > remainingDiagnosticsBytes) {
            diagnosticsTruncated = true;
            break;
        }
        remainingDiagnosticsBytes -= serializedSize;
        diagnostics.push_back(std::move(item));
    }

    responseDiagnosticsTruncated = responseDiagnosticsTruncated || diagnosticsTruncated;
    return json{
        {"module", result.moduleName},
        {"submodule", result.submoduleName},
        {"policy", result.policyName},
        {"status", policyApplyStatusToString(result.status)},
        {"message", result.message},
        {"diagnostics", std::move(diagnostics)},
        {"diagnostics_truncated", diagnosticsTruncated}
    };
}

json policy_apply_summary_json(const PolicyApplySummary& summary, bool ok, const std::string& message) {
    json results = json::array();
    std::size_t remainingDiagnosticsBytes = MAX_POLICY_DIAGNOSTICS_RESPONSE_BYTES;
    bool responseDiagnosticsTruncated = false;
    for (const PolicyApplyResult& result : summary.getResults()) {
        results.push_back(policy_apply_result_json(
            result,
            remainingDiagnosticsBytes,
            responseDiagnosticsTruncated
        ));
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
        {"diagnostics_truncated", responseDiagnosticsTruncated},
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

json log_records_json(const std::string& requestedBootId) {
    const std::string bootId = requestedBootId.empty()
        ? SystemBootInfo::get_boot_id()
        : requestedBootId;

    json categories = json::array();
    json records = json::array();
    if (bootId.empty()) {
        return json{{"ok", true}, {"message", "logs loaded"}, {"boot_id", bootId}, {"categories", categories}, {"records", records}};
    }

    const std::filesystem::path bootDir = fic::core::FicRuntimePaths::get().logDir / bootId;
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
    SingleLineFileHandler lockStatus(fic::core::FicRuntimePaths::get().lockStatusFile.string());
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
                    PolicyMap& policyMap,
                    const fic::platform::PlatformProfile& platform) {
    const std::string command = request.value("command", "");
    const std::string requestedModule = request.value("module", "");
    const std::string module = canonical_module_name(policyMap, requestedModule);
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
            for (const auto& [moduleName, _] : policyMap) {
                modules.push_back(moduleName);
            }
            return json{{"ok", true}, {"message", "modules listed"}, {"modules", modules}};
        }
        if (command == "policy_list") {
            if (module == "all") {
                json all = json::array();
                for (const auto& [moduleName, _] : policyMap) {
                    for (const auto& item : policy_list_json(policyMap, moduleName)) {
                        all.push_back(item);
                    }
                }
                return json{{"ok", true}, {"message", "policies listed"}, {"policies", all}};
            }
            if (module.empty()) {
                return fic::ipc::make_error_response("module is required");
            }
            return json{{"ok", true}, {"message", "policies listed"}, {"policies", policy_list_json(policyMap, module)}};
        }
        if (command == "policy_is_enabled" || command == "policy_is_disabled" || command == "policy_value") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            if (command == "policy_value") {
                return policy_value_json(policyMap, module, policy);
            }
            return policy_status_json(policyMap, module, policy);
        }
        if (command == "set_policy_value") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            bool ok = set(policyMap, module, policy, value);
            if (ok) {
                policyMap = init_policyMap(platform);
            }
            return ok ? fic::ipc::make_ok_response("policy value updated")
                      : fic::ipc::make_error_response("failed to update policy value");
        }
        if (command == "enable_policy") {
            bool ok = enable(policyMap, module, policy);
            if (ok) {
                policyMap = init_policyMap(platform);
            }
            return ok ? fic::ipc::make_ok_response("policy enabled")
                      : fic::ipc::make_error_response("failed to enable policy");
        }
        if (command == "disable_policy") {
            bool ok = disable(policyMap, module, policy);
            if (ok) {
                policyMap = init_policyMap(platform);
            }
            return ok ? fic::ipc::make_ok_response("policy disabled")
                      : fic::ipc::make_error_response("failed to disable policy");
        }
        if (command == "reload_config") {
            policyMap = init_policyMap(platform);
            return fic::ipc::make_ok_response("config reloaded");
        }
        if (command == "apply_all") {
            policyMap = init_policyMap(platform);
            PolicyApplySummary summary = applyAllPolicies(policyMap);
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
            policyMap = init_policyMap(platform);
            PolicyApplySummary summary = applyModulePolicies(policyMap, module);
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
            policyMap = init_policyMap(platform);
            PolicyApplySummary summary;
            summary.add(applyPolicy(policyMap, module, policy));
            const bool ok = isPolicyApplySuccessful(summary, module, policy);
            return policy_apply_summary_json(
                summary,
                ok,
                policy_apply_message(summary, ok, "policy applied", "failed to apply policy")
            );
        }
        if (command.rfind("device_", 0) == 0) {
            return fic::ipc::make_error_response(
                "device tree API is served by fic-dick on " +
                std::string(fic::ipc::DEFAULT_DEVICE_SOCKET_PATH)
            );
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
            bool ok = lock(platform);
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
                      PolicyMap& policyMap,
                      const fic::platform::PlatformProfile& platform) {
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
        response = handle_request(request, policyMap, platform);
    } catch (const std::exception& e) {
        response = fic::ipc::make_error_response("invalid request: " + std::string(e.what()));
    }

    audit_ipc_request(peer, request, response);

    std::string responseText = response.dump() + "\n";
    return fic::ipc::write_all(clientFd, responseText, error);
}

bool custom_socket_requested(int argc, char* argv[]) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--socket") {
            return true;
        }
    }
    return false;
}
} // namespace

int main(int argc, char* argv[]) {
    const fic::platform::PlatformProfile platform =
        fic::platform::makeBuildPlatformProfile();
    std::string platformError;
    if (!fic::platform::validatePlatformProfile(platform, platformError)) {
        std::cerr << "invalid compiled platform profile: " << platformError << std::endl;
        return 1;
    }
    if (get_arg_value(argc, argv, 1) == "--version") {
        std::cout << "fic 2.0 target-platform=" << platform.id << std::endl;
        return 0;
    }
    if (!fic::platform::validateHostCompatibility(
            platform, "/etc/os-release", platformError)) {
        std::cerr << "incompatible host platform: " << platformError << std::endl;
        return 1;
    }

    std::string pathError;
    if (!fic::core::FicRuntimePaths::initializeProduction(pathError)) {
        std::cerr << "failed to initialize FIC runtime paths: " << pathError << std::endl;
        return 1;
    }

    try {
        std::locale::global(std::locale("ru_RU.UTF-8"));
    } catch (const std::exception&) {
        std::setlocale(LC_ALL, "");
    }

    const bool once = get_arg_value(argc, argv, 1) == "--oneshot";
    auto policyMap = init_policyMap(platform);

    if (once) {
        return apply(policyMap, "all", "") ? 0 : 1;
    }

    const std::string socketPath = get_socket_path(argc, argv);
    const int intervalSeconds = get_interval_seconds(argc, argv);

    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);

    fic::ipc::AdminSocketOptions socketOptions;
    socketOptions.socketPath = socketPath;
    socketOptions.security = custom_socket_requested(argc, argv)
        ? fic::ipc::AdminSocketSecurityProfile::Development
        : fic::ipc::AdminSocketSecurityProfile::ProductionAdmin;
    socketOptions.backlog = 32;
    socketOptions.label = "fic daemon socket";
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

    std::cout << "fic daemon started, socket=" << socketPath
              << ", interval=" << intervalSeconds << "s"
              << ", target-platform=" << platform.id << std::endl;

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
                serve_one_client(clientFd, policyMap, platform);
                ::close(clientFd);
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= nextPeriodicApply) {
            policyMap = init_policyMap(platform);
            apply(policyMap, "all", "");
            nextPeriodicApply = now + std::chrono::seconds(intervalSeconds);
        }
    }

    ::close(serverFd);
    ::unlink(socketPath.c_str());
    std::cout << "fic daemon stopped" << std::endl;
    return 0;
}
