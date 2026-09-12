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
#include <string>
#include <sys/socket.h>
#include <grp.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <systemd/sd-daemon.h>
#include <systemd/sd-login.h>

#include "daemon/main_function.h"
#include "daemon/AdminAudit.h"
#include "daemon/CalcHashCommand.h"
#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"
#include "policy/registry/PolicyRegistryJson.h"
#include <fic/ipc/FicAdminSocket.h>
#include <fic/ipc/FicIpcClient.h>
#include <fic/ipc/FicIpcPathDefaults.h>
#include <fic/version/BuildInfo.h>
#include <fic/version/ProductVersion.h>
#include <fic/core/logging/SecurityAudit.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/runtime/SystemBootInfo.h>
#include <fic/core/config/ConfigSchemaManager.h>
#include "platform/PlatformCompatibility.h"
#include "platform/PlatformExecutableResolver.h"
#include "platform/PlatformProfile.h"
#include "trust/PackageTrustSelection.h"
#include "trust/PackageTrustSync.h"
#include "session/SessionAgentClient.h"
#include "session/SessionAgentClientInternal.h"
#include "session/SessionEventServer.h"
#include "session/SessionReadyValidation.h"
#include "session/SystemGraphicalSessionInventory.h"
#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"
#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"

using json = nlohmann::json;

namespace {
std::atomic_bool g_stop{false};

using PeerCredentials = fic::core::security_audit::PeerCredentials;

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

PeerCredentials get_peer_credentials(int fd) {
    PeerCredentials peer;
#ifdef SO_PEERCRED
    struct ucred credentials {};
    socklen_t credentialsLength = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialsLength) == 0) {
        peer.available = true;
        peer.pid = static_cast<std::int64_t>(credentials.pid);
        peer.uid = static_cast<std::int64_t>(credentials.uid);
        peer.gid = static_cast<std::int64_t>(credentials.gid);
        return peer;
    }
    peer.error = std::strerror(errno);
#else
    peer.error = "SO_PEERCRED is unavailable";
#endif
    return peer;
}

void write_audit_log(const json& event) {
    // Security audit is always-on and intentionally bypasses Logger and
    // AUDIT/log_level, including its NoLog value.
    try {
        const std::string bootId = SystemBootInfo::get_boot_id();
        const std::filesystem::path auditDir = fic::core::FicRuntimePaths::get().logDir /
            (bootId.empty() ? "unknown_boot" : bootId) /
            "audit";
        std::filesystem::create_directories(auditDir);

        const std::filesystem::path auditFile = auditDir / ("audit_" + std::to_string(getpid()) + ".txt");
        std::string error;
        if (!fic::core::security_audit::appendJsonLine(auditFile, event, error)) {
            std::cerr << error << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "audit logging error: " << e.what() << std::endl;
    }
}

void audit_ipc_request(const PeerCredentials& peer, const json& request, const json& response) {
    write_audit_log(make_admin_ipc_audit_event(peer, request, response));
}

bool should_audit_ipc_request(const json& request) {
    if (!request.is_object()) {
        return true;
    }

    const std::string command = admin_audit_command(request);
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

json policy_apply_summary_json(const PolicyApplySummary& summary) {
    return {
        {"total", summary.totalCount()},
        {"applied", summary.appliedCount()},
        {"failed", summary.failedCount()},
        {"disabled", summary.disabledCount()},
        {"not_found", summary.notFoundCount()}
    };
}

void install_desktop_global_report(
    PolicyRegistry& registry,
    const DesktopGlobalReconcileReport& report)
{
    for (Policy* policy : registry.capabilityPolicies(
             PolicyCapability::SessionAware)) {
        auto* sessionAware = dynamic_cast<SessionAwarePolicy*>(policy);
        if (sessionAware == nullptr) continue;
        sessionAware->setGlobalEnforcementResults(report.resultsFor({
            policy->moduleName, policy->submoduleName, policy->policyName}));
    }
}

bool run_daemon_apply_all_pass(
    PolicyRegistry& policyRegistry,
    DesktopGlobalConfigReconciler& desktopGlobalConfig,
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
        const json event = fic::core::security_audit::makeEvent("fic", {
            {"event", "policy_apply_pass"},
            {"reason", reason},
            {"result", {
                {"ok", false},
                {"registry_reload", false},
                {"message", registryError}
            }}
        });
        std::cerr << fic::core::security_audit::serializeJsonLine(event) << std::endl;
        write_audit_log(event);
        return false;
    }
    const DesktopGlobalReconcileReport desktopGlobalReport =
        desktopGlobalConfig.reconcile(policyRegistry);
    install_desktop_global_report(policyRegistry, desktopGlobalReport);
    const bool desktopGlobalConfigOk = desktopGlobalReport.successful();
    const std::string desktopGlobalConfigError =
        desktopGlobalReport.diagnostic();
    const PolicyApplySummary summary = applyAllPoliciesExceptModule(
        policyRegistry, "FIREWALL");
    std::string firewallError;
    const bool firewallOk = fic::firewall::reconcileFirewall(
        executables, firewallError);
    const bool ok = isPolicyApplySuccessful(summary, "all", "") &&
        desktopGlobalConfigOk && firewallOk;
    json result = {
        {"ok", ok},
        {"registry_reload", true},
        {"desktop_global_configuration", desktopGlobalConfigOk},
        {"firewall_reconciliation", firewallOk}
    };
    if (!desktopGlobalConfigError.empty()) {
        result["desktop_global_configuration_error"] =
            desktopGlobalConfigError;
    }
    if (!firewallError.empty()) {
        result["firewall_error"] = firewallError;
    }
    const json event = fic::core::security_audit::makeEvent("fic", {
        {"event", "policy_apply_pass"},
        {"reason", reason},
        {"summary", policy_apply_summary_json(summary)},
        {"result", std::move(result)}
    });

    if (ok) {
        std::cout << fic::core::security_audit::serializeJsonLine(event) << std::endl;
    } else {
        std::cerr << fic::core::security_audit::serializeJsonLine(event) << std::endl;
    }
    write_audit_log(event);
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
                    DesktopGlobalConfigReconciler& desktopGlobalConfig,
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
    DesktopGlobalReconcileReport latestGlobalReport;
    auto reloadRegistryAndGlobalConfig =
        [&](bool requireAllBackends = true) -> std::optional<std::string> {
        std::string reloadError;
        if (!initPolicyRegistry(
                platform, executables, policyRegistry, reloadError)) {
            return "PolicyRegistry reload failed: " +
                (reloadError.empty()
                    ? std::string("unknown initialization error")
                    : reloadError);
        }
        latestGlobalReport = desktopGlobalConfig.reconcile(policyRegistry);
        install_desktop_global_report(policyRegistry, latestGlobalReport);
        if (!latestGlobalReport.requirementsValid ||
            (requireAllBackends && !latestGlobalReport.successful())) {
            return "desktop global configuration reconciliation failed: " +
                latestGlobalReport.diagnostic();
        }
        return std::nullopt;
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
                    for (const auto& item : policyListJson(policyRegistry, moduleName)) {
                        all.push_back(item);
                    }
                }
                return json{{"ok", true}, {"message", "policies listed"}, {"policies", all}};
            }
            if (module.empty()) {
                return fic::ipc::make_error_response("module is required");
            }
            return json{{"ok", true}, {"message", "policies listed"}, {"policies", policyListJson(policyRegistry, module)}};
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
                if (auto reloadError = reloadRegistryAndGlobalConfig()) {
                    return fic::ipc::make_error_response(
                        "policy value was saved, but reconciliation failed: " +
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
                if (auto reloadError = reloadRegistryAndGlobalConfig()) {
                    return fic::ipc::make_error_response(
                        "policy was enabled in configuration, but reconciliation failed: " +
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
                if (auto reloadError = reloadRegistryAndGlobalConfig()) {
                    return fic::ipc::make_error_response(
                        "policy was disabled in configuration, but reconciliation failed: " +
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
            if (auto reloadError = reloadRegistryAndGlobalConfig()) {
                return fic::ipc::make_error_response(
                    "failed to reload configuration: " + reloadError.value());
            }
            if (auto failure = regenerateDevicePolicyIfNeeded(true)) {
                return failure.value();
            }
            return fic::ipc::make_ok_response("config reloaded");
        }
        if (command == "apply_all") {
            if (auto reloadError = reloadRegistryAndGlobalConfig(false)) {
                return fic::ipc::make_error_response(
                    "policies were not applied because reconciliation failed: " +
                    reloadError.value());
            }
            PolicyApplySummary summary = applyAllPolicies(policyRegistry);
            const bool ok = isPolicyApplySuccessful(summary, "all", "") &&
                latestGlobalReport.successful();
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
            if (auto reloadError = reloadRegistryAndGlobalConfig(false)) {
                return fic::ipc::make_error_response(
                    "module policies were not applied because reconciliation failed: " +
                    reloadError.value());
            }
            PolicyApplySummary summary = applyModulePolicies(policyRegistry, module);
            const bool ok = isPolicyApplySuccessful(summary, module, "all") &&
                latestGlobalReport.successfulForModule(module);
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
            if (auto reloadError = reloadRegistryAndGlobalConfig(false)) {
                return fic::ipc::make_error_response(
                    "policy was not applied because reconciliation failed: " +
                    reloadError.value());
            }
            PolicyApplySummary summary =
                applyPolicy(policyRegistry, module, policy);
            Policy* requested = getPolicyClass(policyRegistry, module, policy);
            const bool globalOk = requested == nullptr ||
                latestGlobalReport.successfulForPolicy({
                    requested->moduleName, requested->submoduleName,
                    requested->policyName});
            const bool ok = isPolicyApplySuccessful(summary, module, policy) &&
                globalOk;
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
            return calcHashCommandResponse(value);
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
                      DesktopGlobalConfigReconciler& desktopGlobalConfig,
                      const fic::platform::PlatformProfile& platform,
                      const fic::platform::PlatformExecutableResolver& executables) {
    const PeerCredentials peer = get_peer_credentials(clientFd);
    std::string error;
    json request;
    json response;
    if (fic::ipc::parse_request_json(requestText, request, error) &&
        validate_policy_request_schema(request, error)) {
        response = handle_request(
            request, policyRegistry, desktopGlobalConfig, platform,
            executables);
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

bool validate_session_ready(
    uid_t peerUid,
    const std::string& sessionId,
    ClassifiedGraphicalSession& classified,
    std::string& error)
{
    uid_t sessionUid = 0;
    if (::sd_session_get_uid(sessionId.c_str(), &sessionUid) < 0) {
        error = "session does not belong to the event peer";
        return false;
    }
    char* sessionClass = nullptr;
    char* state = nullptr;
    char* type = nullptr;
    const int classResult = ::sd_session_get_class(sessionId.c_str(), &sessionClass);
    const int stateResult = ::sd_session_get_state(sessionId.c_str(), &state);
    const int typeResult = ::sd_session_get_type(sessionId.c_str(), &type);
    const std::string classValue = sessionClass == nullptr ? "" : sessionClass;
    const std::string stateValue = state == nullptr ? "" : state;
    const std::string typeValue = type == nullptr ? "" : type;
    std::free(sessionClass);
    std::free(state);
    std::free(type);
    const bool safeAgentEndpointPresent = typeValue == "tty" &&
        session_agent_client_detail::safeEndpointPresent(
            SessionAgentClient::socketPath(
                UserSession{sessionId, peerUid, {}, typeValue}),
            peerUid);
    if (classResult < 0 || stateResult < 0 || typeResult < 0 ||
        !session_ready_validation::validLogindClaim(
            peerUid, sessionUid, classValue, stateValue, typeValue,
            safeAgentEndpointPresent)) {
        error = "session is not a live graphical user session";
        return false;
    }

    classified.session.id = sessionId;
    classified.session.uid = peerUid;
    classified.session.type = typeValue;
    error.clear();
    return true;
}

void reconcile_session_ready(
    PolicyRegistry& registry,
    DesktopGlobalConfigReconciler& desktopGlobalConfig,
    GraphicalSessionInventory& inventory,
    const ClassifiedGraphicalSession& queuedSession)
{
    ClassifiedGraphicalSession session = queuedSession;
    std::string error;
    std::vector<ClassifiedGraphicalSession> current;
    const bool inventoryLoaded = inventory.currentSessions(current, error);
    for (Policy* policy : registry.capabilityPolicies(
             PolicyCapability::SessionInventoryCompliance)) {
        if (!policy->isEnabled()) continue;
        auto* compliance = dynamic_cast<SessionInventoryCompliancePolicy*>(policy);
        if (compliance == nullptr || !inventoryLoaded ||
            !compliance->evaluateSessionInventory(current, error)) {
            policy->log("Runtime desktop session compliance failed: " + error,
                        logLevel::ERROR);
        }
    }

    if (!SessionAgentClient::query(
            session.session, session.context, error)) {
        write_audit_log(fic::core::security_audit::makeEvent("fic", {
            {"event", "session_ready"},
            {"session_id", session.session.id},
            {"phase", "context_query"},
            {"result", {{"ok", false}, {"message", error}}}
        }));
        return;
    }
    session.desktop = DesktopEnvironmentBackend::kindFromName(
        session.context.desktop);
    if (session.desktop == DesktopEnvironmentKind::Unknown) {
        write_audit_log(fic::core::security_audit::makeEvent("fic", {
            {"event", "session_ready"},
            {"session_id", session.session.id},
            {"phase", "desktop_classification"},
            {"result", {{"ok", false}, {"message", "unknown desktop environment"}}}
        }));
        return;
    }
    const SessionReconcileContext reconcileContext{
        session, current, inventoryLoaded};
    const DesktopGlobalReconcileReport globalReport =
        desktopGlobalConfig.reconcile(registry);
    if (!globalReport.successful()) {
        write_audit_log(fic::core::security_audit::makeEvent("fic", {
            {"event", "session_ready"},
            {"session_id", session.session.id},
            {"phase", "desktop_global_configuration"},
            {"result", {
                {"ok", false}, {"message", globalReport.diagnostic()}}}
        }));
    }
    for (Policy* policy : registry.capabilityPolicies(PolicyCapability::SessionAware)) {
        if (!policy->isEnabled()) continue;
        auto* sessionAware = dynamic_cast<SessionAwarePolicy*>(policy);
        if (sessionAware == nullptr) continue;
        const PolicyRef owner{
            policy->moduleName, policy->submoduleName, policy->policyName};
        const SessionReconcileResult result =
            sessionAware->reconcileSession(
                reconcileContext,
                globalReport.resultFor(owner, session.desktop));
        if (result.status == SessionReconcileStatus::NotApplicable ||
            result.status == SessionReconcileStatus::MandatoryGlobalConverged ||
            result.status == SessionReconcileStatus::SessionOnlyConverged) {
            continue;
        }
        if (result.status ==
            SessionReconcileStatus::MandatoryGlobalRuntimeWarning) {
            policy->log("Runtime session reconciliation warning for session " +
                            session.session.id + ": " + result.diagnostic,
                        logLevel::WARN);
        } else {
            policy->log("Runtime session reconciliation failed for session " +
                            session.session.id + ": " + result.diagnostic,
                        logLevel::ERROR);
        }
    }
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
        if (command == "pam-alt-faillock") {
            if (::geteuid() != 0) {
                std::cerr << "ALT PAM topology maintenance must be run as root"
                          << std::endl;
                return 1;
            }
            fic::identity::pam::AltPamFaillockTopologyOptions options;
            options.lockFilePath =
                paths.runtimeDir / "pam-alt-faillock-topology.lock";
            options.lockDebugLogPath = paths.lockDebugLogFile;
            fic::identity::pam::AltPamFaillockTopologyManager manager(
                platform.pam, std::move(options));
            const std::string action = get_arg_value(argc, argv, 3);
            if (action == "status") {
                fic::identity::pam::AltPamFaillockTopologyState state;
                if (!manager.status(state, maintenanceError)) {
                    std::cerr << "ALT pam_faillock topology status failed: "
                              << maintenanceError << std::endl;
                    return 1;
                }
                std::cout <<
                    fic::identity::pam::altPamFaillockTopologyStateName(state)
                          << std::endl;
                return 0;
            }
            if (action == "enable") {
                if (!manager.enable(maintenanceError)) {
                    std::cerr << "ALT pam_faillock topology enable failed: "
                              << maintenanceError << std::endl;
                    return 1;
                }
                return 0;
            }
            if (action == "disable") {
                if (!manager.disable(maintenanceError)) {
                    std::cerr << "ALT pam_faillock topology disable failed: "
                              << maintenanceError << std::endl;
                    return 1;
                }
                return 0;
            }
            std::cerr << "unknown ALT pam_faillock topology action: "
                      << action << std::endl;
            return 1;
        }
        if (command == "pam-alt-pwhistory") {
            if (::geteuid() != 0) {
                std::cerr << "ALT PAM topology maintenance must be run as root"
                          << std::endl;
                return 1;
            }
            const struct group* shadowGroup = ::getgrnam("shadow");
            if (shadowGroup == nullptr) {
                std::cerr << "ALT pam_pwhistory requires the shadow group"
                          << std::endl;
                return 1;
            }
            fic::identity::pam::AltPamPasswordHistoryTopologyOptions options;
            options.lockFilePath =
                paths.runtimeDir / "pam-alt-pwhistory-topology.lock";
            options.lockDebugLogPath = paths.lockDebugLogFile;
            options.storageGroup = shadowGroup->gr_gid;
            fic::identity::pam::AltPamPasswordHistoryTopologyManager manager(
                platform.pam, std::move(options));
            const std::string action = get_arg_value(argc, argv, 3);
            if (action == "prepare") {
                if (!manager.prepareStorage(maintenanceError)) {
                    std::cerr << "ALT pam_pwhistory storage preparation failed: "
                              << maintenanceError << std::endl;
                    return 1;
                }
                return 0;
            }
            if (action == "status") {
                fic::identity::pam::AltPamPasswordHistoryTopologyState state;
                if (!manager.status(state, maintenanceError)) {
                    std::cerr << "ALT pam_pwhistory topology status failed: "
                              << maintenanceError << std::endl;
                    return 1;
                }
                std::cout << fic::identity::pam::
                    altPamPasswordHistoryTopologyStateName(state) << std::endl;
                return 0;
            }
            if (action == "enable") {
                if (!manager.enable(maintenanceError)) {
                    std::cerr << "ALT pam_pwhistory topology enable failed: "
                              << maintenanceError << std::endl;
                    return 1;
                }
                return 0;
            }
            if (action == "disable") {
                if (!manager.disable(maintenanceError)) {
                    std::cerr << "ALT pam_pwhistory topology disable failed: "
                              << maintenanceError << std::endl;
                    return 1;
                }
                return 0;
            }
            std::cerr << "unknown ALT pam_pwhistory topology action: "
                      << action << std::endl;
            return 1;
        }
        std::cerr << "unknown maintenance command: " << command << std::endl;
        return 1;
    }

    if (!packageTrustSync && !affectedPackageTrustSync) {
        if (get_arg_value(argc, argv, 1) != "--maintenance") {
            (void)::sd_notify(0, "STATUS=Validating startup configuration");
        }
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

    (void)::sd_notify(0, "STATUS=Initializing policy registry");
    PolicyRegistry policyRegistry;
    auto gnomeSystemBackend =
        std::make_shared<GnomeSystemBackend>(executables);
    auto flySystemBackend = std::make_shared<FlySystemBackend>();
    DesktopGlobalConfigReconciler desktopGlobalConfig(
        {gnomeSystemBackend, flySystemBackend});
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

    (void)::sd_notify(0, "STATUS=Applying startup policies");
    bool startupRegistryReloadFailed = false;
    const bool startupApplyOk = run_daemon_apply_all_pass(
        policyRegistry, desktopGlobalConfig, platform, executables, "startup",
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

    (void)::sd_notify(
        0,
        startupApplyOk
            ? "STATUS=Creating administrative socket"
            : "STATUS=Startup policy apply completed with errors; creating administrative socket");
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

    (void)::sd_notify(
        0,
        startupApplyOk
            ? "STATUS=Creating session event socket"
            : "STATUS=Startup policy apply completed with errors; creating session event socket");
    const bool developmentSocket = custom_socket_requested(argc, argv);
    const std::string sessionEventSocketPath = developmentSocket
        ? (std::filesystem::path(socketPath).parent_path() /
           "fic-session-events.sock").string()
        : fic::ipc::path_defaults::SESSION_EVENT_SOCKET;
    fic::ipc::AdminSocketOptions eventSocketOptions;
    eventSocketOptions.socketPath = sessionEventSocketPath;
    eventSocketOptions.security = developmentSocket
        ? fic::ipc::AdminSocketSecurityProfile::Development
        : fic::ipc::AdminSocketSecurityProfile::ProductionSessionEvents;
    eventSocketOptions.backlog = 32;
    eventSocketOptions.label = "FIC session event socket";
    const fic::ipc::AdminSocketResult eventSocketResult =
        fic::ipc::create_admin_server_socket(eventSocketOptions);
    if (eventSocketResult.fileDescriptor < 0) {
        std::cerr << eventSocketResult.error << std::endl;
        ::close(serverFd);
        ::unlink(socketPath.c_str());
        return 1;
    }
    const int sessionEventFd = eventSocketResult.fileDescriptor;
    SystemGraphicalSessionInventory runtimeInventory(executables);
    SessionEventServer sessionEvents(
        sessionEventFd,
        [&](uid_t uid, const std::string& sessionId,
            ClassifiedGraphicalSession& session, std::string& error) {
            return validate_session_ready(
                uid, sessionId, session, error);
        },
        [&](const ClassifiedGraphicalSession& session) {
            reconcile_session_ready(
                policyRegistry, desktopGlobalConfig, runtimeInventory, session);
        });

    (void)::sd_notify(
        0,
        startupApplyOk
            ? "READY=1\nSTATUS=Running"
            : "READY=1\nSTATUS=Running; startup policy apply completed with errors");

    std::cout << "fic daemon started, socket=" << socketPath
              << ", interval=" << intervalSeconds << "s"
              << ", target-platform=" << platform.id << std::endl;

    auto nextPeriodicApply = std::chrono::steady_clock::now() + std::chrono::seconds(intervalSeconds);

    while (!g_stop) {
        std::string transportError;
        if (!transport.pollOnce(100,
                [&](int clientFd, const std::string& requestText) {
                    return handle_client_packet(clientFd, requestText,
                        policyRegistry, desktopGlobalConfig, platform,
                        executables);
                },
                transportError)) {
            std::cerr << transportError << std::endl;
            break;
        }
        if (!sessionEvents.pollOnce(0, transportError)) {
            std::cerr << transportError << std::endl;
            break;
        }
        sessionEvents.processOne();

        auto now = std::chrono::steady_clock::now();
        if (now >= nextPeriodicApply) {
            run_daemon_apply_all_pass(
                policyRegistry, desktopGlobalConfig, platform, executables,
                "periodic");
            nextPeriodicApply = now + std::chrono::seconds(intervalSeconds);
        }
    }

    ::close(serverFd);
    ::unlink(socketPath.c_str());
    ::close(sessionEventFd);
    ::unlink(sessionEventSocketPath.c_str());
    std::cout << "fic daemon stopped" << std::endl;
    return 0;
}
