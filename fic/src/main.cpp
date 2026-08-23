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
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <grp.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/main_function.h"
#include "core/PolicyRegistryJson.h"
#include <fic/ipc/FicAdminSocket.h>
#include <fic/ipc/FicIpcClient.h>
#include <fic/version/BuildInfo.h>
#include <fic/version/ProductVersion.h>
#include <fic/core/Logger.h>
#include <fic/core/FicRuntimePaths.h>
#include <fic/core/SystemBootInfo.h>
#include <fic/core/ConfigSchemaManager.h>
#include "platform/PlatformCompatibility.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"
#include "trust/PackageTrustSelection.h"
#include "trust/PackageTrustSync.h"

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
    // Security audit is always-on and intentionally bypasses Logger and
    // AUDIT/log_level, including its NoLog value.
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

bool should_audit_ipc_request(const json& request) {
    if (!request.is_object()) {
        return true;
    }

    const std::string command = request.value("command", "");
    return command != "boot_id" && command != "log_records";
}

std::string canonical_module_name(
    const PolicyRegistry& policyRegistry,
    const std::string& module
) {
    if (module.empty() || module == "all") {
        return module;
    }

    auto exact = policyRegistry.find(module);
    if (exact != policyRegistry.end()) {
        return module;
    }

    const std::string lowered = to_lower_ascii(module);
    for (const auto& [moduleName, _] : policyRegistry) {
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

json policy_list_json(const PolicyRegistry& policyRegistry,
                      const std::string& module) {
    json result = json::array();
    auto moduleIt = policyRegistry.find(module);
    if (moduleIt == policyRegistry.end()) {
        return result;
    }

    for (const auto& [submoduleName, submodulePolicies] : moduleIt->second.submodules) {
        for (const auto& [policyName, policyClass] : submodulePolicies) {
            result.push_back(policy_to_json(module, submoduleName, policyName, *policyClass));
        }
    }
    return result;
}

json policy_status_json(
    PolicyRegistry& policyRegistry,
    const std::string& module,
    const std::string& policy
) {
    Policy* policyClass = getPolicyClass(policyRegistry, module, policy);
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
    PolicyRegistry& policyRegistry,
    const std::string& module,
    const std::string& policy
) {
    Policy* policyClass = getPolicyClass(policyRegistry, module, policy);
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

std::string policy_apply_summary_text(const PolicyApplySummary& summary) {
    return "total=" + std::to_string(summary.totalCount()) +
           " applied=" + std::to_string(summary.appliedCount()) +
           " failed=" + std::to_string(summary.failedCount()) +
           " disabled=" + std::to_string(summary.disabledCount()) +
           " not_found=" + std::to_string(summary.notFoundCount());
}

bool run_daemon_apply_all_pass(
    PolicyRegistry& policyRegistry,
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::string& reason,
    bool* registryReloadFailed = nullptr
) {
    if (registryReloadFailed != nullptr) {
        *registryReloadFailed = false;
    }
    std::string registryError;
    if (!initPolicyRegistry(
            platform, executables, policyRegistry, registryError)) {
        if (registryReloadFailed != nullptr) {
            *registryReloadFailed = true;
        }
        const std::string message =
            "policy apply pass reason=" + sanitize_log_value(reason) +
            " ok=false registry_reload=failed error=\"" +
            sanitize_log_value(registryError) + "\"";
        std::cerr << message << std::endl;
        write_audit_log(message);
        return false;
    }
    const PolicyApplySummary summary = applyAllPoliciesExceptModule(
        policyRegistry, "FIREWALL");
    std::string firewallError;
    const bool firewallOk = fic::firewall::reconcileFirewall(
        executables, firewallError);
    const bool ok = isPolicyApplySuccessful(summary, "all", "") && firewallOk;
    const std::string message = "policy apply pass reason=" + sanitize_log_value(reason) +
        " ok=" + std::string(ok ? "true" : "false") +
        " firewall_reconciliation=" + std::string(firewallOk ? "ok" : "failed") +
        " " + policy_apply_summary_text(summary) +
        (firewallError.empty()
            ? ""
            : " firewall_error=" + sanitize_log_value(firewallError));

    if (ok) {
        std::cout << message << std::endl;
    } else {
        std::cerr << message << std::endl;
    }
    write_audit_log(message);
    return ok;
}

constexpr int MAX_LOG_RECORDS_PER_PAGE = 500;
constexpr std::size_t MAX_LOG_LINE_BYTES = 16U * 1024U;
constexpr std::size_t MAX_LOG_PAGE_BYTES = 768U * 1024U;

bool valid_boot_id(const std::string& bootId) {
    return !bootId.empty() && std::all_of(bootId.begin(), bootId.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '-' || ch == '_';
    });
}

json log_records_json(const std::string& requestedBootId, int offset, int limit) {
    const std::string bootId = requestedBootId.empty()
        ? SystemBootInfo::get_boot_id()
        : requestedBootId;

    json categories = json::array();
    json records = json::array();
    if (bootId.empty()) {
        return json{{"ok", true}, {"message", "logs loaded"}, {"boot_id", bootId},
                    {"categories", categories}, {"records", records}, {"has_more", false}};
    }
    if (!valid_boot_id(bootId)) {
        return fic::ipc::make_error_response("invalid boot_id");
    }

    const std::filesystem::path bootDir = fic::core::FicRuntimePaths::get().logDir / bootId;
    if (!std::filesystem::exists(bootDir) || !std::filesystem::is_directory(bootDir)) {
        return json{{"ok", true}, {"message", "logs loaded"}, {"boot_id", bootId},
                    {"categories", categories}, {"records", records}, {"has_more", false}};
    }

    std::vector<std::filesystem::path> categoryDirs;
    for (const auto& entry : std::filesystem::directory_iterator(bootDir)) {
        if (entry.is_directory()) {
            categoryDirs.push_back(entry.path());
        }
    }
    std::sort(categoryDirs.begin(), categoryDirs.end());

    std::size_t recordIndex = 0;
    std::size_t responseBytes = 0;
    bool hasMore = false;
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
                if (recordIndex++ < static_cast<std::size_t>(offset)) {
                    continue;
                }
                const std::size_t originalBytes = line.size();
                const bool lineTruncated = line.size() > MAX_LOG_LINE_BYTES;
                if (lineTruncated) {
                    line.resize(MAX_LOG_LINE_BYTES);
                }
                json item = {
                    {"category", category},
                    {"source_file", logFile.string()},
                    {"line", line},
                    {"byte_size", originalBytes},
                    {"line_truncated", lineTruncated}
                };
                const std::size_t itemBytes = item.dump().size();
                if (records.size() >= static_cast<std::size_t>(limit) ||
                    responseBytes + itemBytes > MAX_LOG_PAGE_BYTES) {
                    hasMore = true;
                    break;
                }
                responseBytes += itemBytes;
                records.push_back(std::move(item));
            }
            if (hasMore) {
                break;
            }
        }
        if (hasMore) {
            break;
        }
    }

    const int nextOffset = hasMore
    ? offset + static_cast<int>(records.size())
    : static_cast<int>(recordIndex);

    return json{
        {"ok", true},
        {"message", "logs loaded"},
        {"boot_id", bootId},
        {"categories", categories},
        {"records", records},
        {"has_more", hasMore},
        {"next_offset", nextOffset}
    };
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
                    PolicyRegistry& policyRegistry,
                    const fic::platform::PlatformProfile& platform,
                    const fic::platform::PlatformExecutableResolver& executables) {
    const std::string command = request.value("command", "");
    const std::string requestedModule = request.value("module", "");
    const std::string module = canonical_module_name(policyRegistry, requestedModule);
    const std::string policy = request.value("policy", "");
    const std::string value = request.value("value", "");

    auto regenerateDevicePolicyIfNeeded = [&](bool required) -> std::optional<json> {
        if (!required) {
            return std::nullopt;
        }
        auto enabled = [&](const std::string& name) {
            Policy* devicePolicy = getPolicyClass(policyRegistry, "DC", name);
            return devicePolicy != nullptr && devicePolicy->isEnabled();
        };
        const json response = fic::ipc::Client(fic::ipc::Endpoint::DeviceDaemon).request({
            {"command", "device_regenerate_policy"},
            {"block_usb_storage", enabled("block_usb_storage")},
            {"block_printers_scanners", enabled("block_printers_scanners")},
            {"block_optical_drives", enabled("block_optical_drives")}
        });
        if (response.value("ok", false)) {
            return std::nullopt;
        }
        return fic::ipc::make_error_response(
            "DC configuration was saved, but generated device policy was not activated: " +
            response.value("message", "unknown device daemon error"));
    };
    auto reloadRegistry = [&]() -> std::optional<std::string> {
        std::string reloadError;
        if (initPolicyRegistry(
                platform, executables, policyRegistry, reloadError)) {
            return std::nullopt;
        }
        return reloadError.empty()
            ? std::optional<std::string>("unknown PolicyRegistry initialization error")
            : std::optional<std::string>(std::move(reloadError));
    };

    try {
        if (command == "status") {
            return json{
                {"ok", true},
                {"message", "fic daemon is running"},
                {"product_version", fic::version::PRODUCT_VERSION},
                {"config_schema_version", fic::version::CONFIG_SCHEMA_VERSION}
            };
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
            return json{
                {"ok", true},
                {"message", "modules listed"},
                {"modules", moduleDescriptorsJson(policyRegistry)}
            };
        }
        if (command == "policy_list") {
            if (module == "all") {
                json all = json::array();
                for (const auto& [moduleName, _] : policyRegistry) {
                    for (const auto& item : policy_list_json(policyRegistry, moduleName)) {
                        all.push_back(item);
                    }
                }
                return json{{"ok", true}, {"message", "policies listed"}, {"policies", all}};
            }
            if (module.empty()) {
                return fic::ipc::make_error_response("module is required");
            }
            return json{{"ok", true}, {"message", "policies listed"}, {"policies", policy_list_json(policyRegistry, module)}};
        }
        if (command == "policy_is_enabled" || command == "policy_is_disabled" || command == "policy_value") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            if (command == "policy_value") {
            return policy_value_json(policyRegistry, module, policy);
            }
            return policy_status_json(policyRegistry, module, policy);
        }
        if (command == "set_policy_value") {
            if (module.empty() || policy.empty()) {
                return fic::ipc::make_error_response("module and policy are required");
            }
            bool ok = set(policyRegistry, module, policy, value);
            if (ok) {
                if (auto reloadError = reloadRegistry()) {
                    return fic::ipc::make_error_response(
                        "policy value was saved, but PolicyRegistry reload failed: " +
                        reloadError.value());
                }
                if (auto failure = regenerateDevicePolicyIfNeeded(module == "DC")) {
                    return failure.value();
                }
            }
            return ok ? fic::ipc::make_ok_response("policy value updated")
                      : fic::ipc::make_error_response("failed to update policy value");
        }
        if (command == "enable_policy") {
            bool ok = enable(policyRegistry, module, policy);
            if (ok) {
                if (auto reloadError = reloadRegistry()) {
                    return fic::ipc::make_error_response(
                        "policy was enabled in configuration, but PolicyRegistry reload failed: " +
                        reloadError.value());
                }
                if (auto failure = regenerateDevicePolicyIfNeeded(module == "DC")) {
                    return failure.value();
                }
            }
            return ok ? fic::ipc::make_ok_response("policy enabled")
                      : fic::ipc::make_error_response("failed to enable policy");
        }
        if (command == "disable_policy") {
            bool ok = disable(policyRegistry, module, policy);
            if (ok) {
                if (auto reloadError = reloadRegistry()) {
                    return fic::ipc::make_error_response(
                        "policy was disabled in configuration, but PolicyRegistry reload failed: " +
                        reloadError.value());
                }
                if (auto failure = regenerateDevicePolicyIfNeeded(module == "DC")) {
                    return failure.value();
                }
            }
            return ok ? fic::ipc::make_ok_response("policy disabled")
                      : fic::ipc::make_error_response("failed to disable policy");
        }
        if (command == "reload_config") {
            if (auto reloadError = reloadRegistry()) {
                return fic::ipc::make_error_response(
                    "failed to reload PolicyRegistry: " + reloadError.value());
            }
            if (auto failure = regenerateDevicePolicyIfNeeded(true)) {
                return failure.value();
            }
            return fic::ipc::make_ok_response("config reloaded");
        }
        if (command == "apply_all") {
            if (auto reloadError = reloadRegistry()) {
                return fic::ipc::make_error_response(
                    "policies were not applied because PolicyRegistry reload failed: " +
                    reloadError.value());
            }
            PolicyApplySummary summary = applyAllPolicies(policyRegistry);
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
            if (auto reloadError = reloadRegistry()) {
                return fic::ipc::make_error_response(
                    "module policies were not applied because PolicyRegistry reload failed: " +
                    reloadError.value());
            }
            PolicyApplySummary summary = applyModulePolicies(policyRegistry, module);
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
            if (auto reloadError = reloadRegistry()) {
                return fic::ipc::make_error_response(
                    "policy was not applied because PolicyRegistry reload failed: " +
                    reloadError.value());
            }
            PolicyApplySummary summary =
                applyPolicy(policyRegistry, module, policy);
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
            return log_records_json(
                request.value("boot_id", ""),
                request.value("offset", 0),
                request.value("limit", MAX_LOG_RECORDS_PER_PAGE));
        }
        if (command == "calc_hash") {
            bool ok = calcHash(value);
            return ok ? fic::ipc::make_ok_response("command hash updated")
                      : fic::ipc::make_error_response("failed to update command hash");
        }
        if (command == "lock") {
            bool ok = lock(executables);
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

bool validate_policy_request_schema(const json& request, std::string& error) {
    for (const char* field : {"module", "policy", "value", "boot_id"}) {
        if (request.contains(field) && !request[field].is_string()) {
            error = std::string("request.") + field + " must be a string";
            return false;
        }
    }
    for (const char* field : {"offset", "limit"}) {
        if (!request.contains(field)) {
            continue;
        }
        const json& value = request[field];
        const bool inRange = value.is_number_unsigned()
            ? value.get<std::uint64_t>() <= static_cast<std::uint64_t>(std::numeric_limits<int>::max())
            : value.is_number_integer() && value.get<std::int64_t>() >= 0 &&
                value.get<std::int64_t>() <= std::numeric_limits<int>::max();
        if (!inRange) {
            error = std::string("request.") + field + " must be a non-negative 32-bit integer";
            return false;
        }
    }
    if (request.contains("limit")) {
        const int limit = request["limit"].get<int>();
        if (limit < 1 || limit > MAX_LOG_RECORDS_PER_PAGE) {
            error = "request.limit must be between 1 and 500";
            return false;
        }
    }

    const std::string command = request.at("command").get<std::string>();
    if (command == "shutdown" || command == "reload_config" ||
        command == "apply_all" || command == "lock" || command == "unlock") {
        return fic::ipc::request_has_only_fields(request, {"command"}, error);
    }
    if (command == "set_policy_value") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "module", "policy", "value"}, error);
    }
    if (command == "enable_policy" || command == "disable_policy" ||
        command == "apply_policy") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "module", "policy"}, error);
    }
    if (command == "apply_module") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "module"}, error);
    }
    if (command == "calc_hash") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "value"}, error);
    }
    if (command == "log_records") {
        return fic::ipc::request_has_only_fields(
            request, {"command", "boot_id", "offset", "limit"}, error);
    }
    return true;
}

std::string handle_client_packet(
                      int clientFd,
                      const std::string& requestText,
                      PolicyRegistry& policyRegistry,
                      const fic::platform::PlatformProfile& platform,
                      const fic::platform::PlatformExecutableResolver& executables) {
    const PeerCredentials peer = get_peer_credentials(clientFd);
    std::string error;
    json request;
    json response;
    if (fic::ipc::parse_request_json(requestText, request, error) &&
        validate_policy_request_schema(request, error)) {
        response = handle_request(request, policyRegistry, platform, executables);
    } else {
        response = fic::ipc::make_error_response("invalid request: " + error);
    }

    if (should_audit_ipc_request(request)) {
        audit_ipc_request(peer, request, response);
    }
    response["api_version"] = fic::ipc::API_VERSION;
    return response.dump();
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
        std::cout << "fic " << fic::version::PRODUCT_VERSION
                  << " target-platform=" << platform.id
                  << " ipc-api=" << fic::version::IPC_API_VERSION
                  << " config-schema=" << fic::version::CONFIG_SCHEMA_VERSION
                  << std::endl;
        return 0;
    }
    if (get_arg_value(argc, argv, 1) == "--build-info") {
        fic::version::writeBuildInfo(std::cout, "fic");
        std::cout << "target_platform=" << platform.id << std::endl;
        return 0;
    }
    if (get_arg_value(argc, argv, 1) == "--trust-list-platform-paths") {
        for (const fic::platform::PlatformExecutableSpec& spec :
             platform.executables.entries) {
            for (const std::filesystem::path& candidate : spec.candidates) {
                std::cout << candidate.string() << '\n';
            }
        }
        return 0;
    }
    const bool packageTrustSync =
        get_arg_value(argc, argv, 1) == "--trust-sync-platform";
    const bool affectedPackageTrustSync =
        get_arg_value(argc, argv, 1) == "--trust-sync-platform-affected";
    std::vector<fic::platform::ExecutableId> affectedExecutableIds;
    if (affectedPackageTrustSync) {
        if (::geteuid() != 0) {
            std::cerr << "package trust sync must be run as root" << std::endl;
            return 1;
        }
        affectedExecutableIds =
            fic::trust::selectAffectedExecutableIds(
                platform.executables, std::cin);
        if (affectedExecutableIds.empty()) {
            return 0;
        }
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

    if (get_arg_value(argc, argv, 1) == "--maintenance") {
        const std::string command = get_arg_value(argc, argv, 2);
        const auto& paths = fic::core::FicRuntimePaths::get();
        std::string maintenanceError;
        if (command == "ensure-config") {
            if (!fic::core::ConfigSchemaManager::ensureConfigs(
                    paths.defaultConfigDir, paths.configDir,
                    maintenanceError)) {
                std::cerr << "configuration bootstrap failed: "
                          << maintenanceError << std::endl;
                return 1;
            }
            std::cout << "working configuration is present" << std::endl;
            return 0;
        }
        if (command == "check-config") {
            if (!fic::core::ConfigSchemaManager::verifyConfigs(
                    paths.configDir, maintenanceError)) {
                std::cerr << "configuration schema check failed: "
                          << maintenanceError << std::endl;
                return 1;
            }
            std::cout << "configuration schema is current: "
                      << fic::version::CONFIG_SCHEMA_VERSION << std::endl;
            return 0;
        }
        if (command == "wait-daemon") {
            int timeoutSeconds = 10;
            const std::string timeoutArgument = get_arg_value(argc, argv, 3);
            if (!timeoutArgument.empty()) {
                try {
                    timeoutSeconds = std::max(0, std::stoi(timeoutArgument));
                } catch (const std::exception&) {
                    std::cerr << "invalid daemon readiness timeout: "
                              << timeoutArgument << std::endl;
                    return 1;
                }
            }
            const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::seconds(timeoutSeconds);
            json response;
            do {
                response = fic::ipc::Client(
                    std::string(fic::ipc::DEFAULT_SOCKET_PATH),
                    std::chrono::seconds(1)).request({{"command", "status"}});
                if (response.value("ok", false) &&
                    response.value("product_version", "") ==
                        fic::version::PRODUCT_VERSION &&
                    response.value("config_schema_version", -1) ==
                        fic::version::CONFIG_SCHEMA_VERSION) {
                    return 0;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            } while (std::chrono::steady_clock::now() < deadline);
            std::cerr << "fic daemon did not become version-compatible and ready: "
                      << response.value("message", "unknown error") << std::endl;
            return 1;
        }
        std::cerr << "unknown maintenance command: " << command << std::endl;
        return 1;
    }

    if (!packageTrustSync && !affectedPackageTrustSync) {
        std::string configError;
        if (!fic::core::ConfigSchemaManager::verifyConfigs(
                fic::core::FicRuntimePaths::get().configDir, configError)) {
            std::cerr << "refusing to start with incompatible configuration: "
                      << configError << std::endl;
            return 1;
        }
    }

    const fic::platform::PlatformExecutableResolver executables(
        platform.executables);
    if (packageTrustSync || affectedPackageTrustSync) {
        if (::geteuid() != 0) {
            std::cerr << "package trust sync must be run as root" << std::endl;
            return 1;
        }
        fic::trust::PackageTrustSyncResult result;
        std::string syncError;
        const bool synchronized =
            affectedPackageTrustSync
                ? fic::trust::syncSelectedPackageManagedExecutables(
                      platform, executables, affectedExecutableIds,
                      result, syncError)
                : fic::trust::syncPackageManagedExecutables(
                      platform, executables, result, syncError);
        if (!synchronized) {
            std::cerr << "package trust sync failed: " << syncError << std::endl;
            return 1;
        }
        std::cout << "package trust sync completed: updated=" << result.updated
                  << ", unavailable=" << result.unavailable << std::endl;
        return 0;
    }

    try {
        std::locale::global(std::locale("ru_RU.UTF-8"));
    } catch (const std::exception&) {
        std::setlocale(LC_ALL, "");
    }

    PolicyRegistry policyRegistry;
    std::string registryError;
    if (!initPolicyRegistry(
            platform, executables, policyRegistry, registryError)) {
        std::cerr << "failed to initialize PolicyRegistry: "
                  << registryError << std::endl;
        return 1;
    }

    const std::string socketPath = get_socket_path(argc, argv);
    const int intervalSeconds = get_interval_seconds(argc, argv);

    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);

    bool startupRegistryReloadFailed = false;
    const bool startupApplyOk = run_daemon_apply_all_pass(
        policyRegistry, platform, executables, "startup",
        &startupRegistryReloadFailed);
    if (startupRegistryReloadFailed) {
        std::cerr << "fic daemon startup aborted because PolicyRegistry reload failed"
                  << std::endl;
        return 1;
    }
    if (!startupApplyOk) {
        std::cerr << "fic daemon startup policy apply completed with errors; "
                     "daemon will continue running"
                  << std::endl;
    }

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
    fic::ipc::AdminSocketTransport transport(serverFd);

    std::cout << "fic daemon started, socket=" << socketPath
              << ", interval=" << intervalSeconds << "s"
              << ", target-platform=" << platform.id << std::endl;

    auto nextPeriodicApply = std::chrono::steady_clock::now() + std::chrono::seconds(intervalSeconds);

    while (!g_stop) {
        std::string transportError;
        if (!transport.pollOnce(1000,
                [&](int clientFd, const std::string& requestText) {
                    return handle_client_packet(clientFd, requestText,
                        policyRegistry, platform, executables);
                },
                transportError)) {
            std::cerr << transportError << std::endl;
            break;
        }

        auto now = std::chrono::steady_clock::now();
        if (now >= nextPeriodicApply) {
            run_daemon_apply_all_pass(policyRegistry, platform, executables, "periodic");
            nextPeriodicApply = now + std::chrono::seconds(intervalSeconds);
        }
    }

    ::close(serverFd);
    ::unlink(socketPath.c_str());
    std::cout << "fic daemon stopped" << std::endl;
    return 0;
}
