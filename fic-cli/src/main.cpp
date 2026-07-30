#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include <fic/ipc/FicIpcClient.h>

using json = nlohmann::json;

namespace {
std::string arg(int argc, char* argv[], int index) {
    if (index >= argc) {
        return "";
    }
    return argv[index];
}

void print_help() {
    std::cout << "FREE INTEGRITY CONTROL CLI\n"
              << "Commands:\n"
              << "  policy set <module> <policy> <value>\n"
              << "  policy enable <module> <policy>\n"
              << "  policy disable <module> <policy>\n"
              << "  policy isenable <module> <policy>\n"
              << "  policy isdisable <module> <policy>\n"
              << "  policy value <module> <policy>\n"
              << "  policy apply all\n"
              << "  policy apply <module> all\n"
              << "  policy apply <module> <policy>\n"
              << "  policy list <module|all>\n"
              << "  policy info restriction <module> <policy>\n"
              << "  module list\n"
              << "  device revision\n"
              << "  device root\n"
              << "  device get <id>\n"
              << "  device children <parent_id> [--all]\n"
              << "  device set <id> <blocked|allowed|permanent|ignored>\n"
              << "  device ignore-hierarchy <id> <true|false>\n"
              << "  device reset <id>\n"
              << "  device check-permanent\n"
              << "  hash calc <path>\n"
              << "  lock | unlock | lockstatus | status | shutdown\n";
}

int print_response(const json& response) {
    bool ok = response.value("ok", false);

    if (response.contains("modules")) {
        bool first = true;
        for (const auto& module : response["modules"]) {
            if (!first) std::cout << ' ';
            std::cout << module.get<std::string>();
            first = false;
        }
        std::cout << std::endl;
    }

    if (response.contains("policies")) {
        for (const auto& item : response["policies"]) {
            std::cout << item.value("module", "") << ":"
                      << item.value("submodule", "") << ":"
                      << item.value("policy", "") << " "
                      << (item.value("enabled", false) ? "ENABLE" : "DISABLE")
                      << std::endl;
        }
    }

    if (!response.contains("modules") && !response.contains("policies")) {
        std::cout << response.value("message", ok ? "OK" : "ERROR") << std::endl;
    }

    return ok ? 0 : 1;
}

std::string format_policy_ref(const json& item) {
    std::ostringstream out;
    out << item.value("module", "");
    const std::string submodule = item.value("submodule", "");
    if (!submodule.empty()) {
        out << ":" << submodule;
    }
    out << ":" << item.value("policy", "");
    return out.str();
}

int print_policy_apply_response(const json& response) {
    const bool ok = response.value("ok", false);

    std::cout << response.value("message", ok ? "OK" : "ERROR") << std::endl;

    if (response.contains("summary") && response["summary"].is_object()) {
        const auto& summary = response["summary"];
        std::cout << "summary: total=" << summary.value("total", 0)
                  << ", applied=" << summary.value("applied", 0)
                  << ", failed=" << summary.value("failed", 0)
                  << ", disabled=" << summary.value("disabled", 0)
                  << ", not_found=" << summary.value("not_found", 0)
                  << std::endl;
    }

    if (response.contains("results") && response["results"].is_array()) {
        for (const auto& item : response["results"]) {
            std::cout << format_policy_ref(item) << " "
                      << item.value("status", "unknown");

            const std::string message = item.value("message", "");
            if (!message.empty()) {
                std::cout << " - " << message;
            }
            std::cout << std::endl;

            if (item.contains("diagnostics") && item["diagnostics"].is_array()) {
                for (const auto& diagnostic : item["diagnostics"]) {
                    std::cout << "  [" << diagnostic.value("timestamp", "") << "]"
                              << " [" << diagnostic.value("level", "UNKNOWN") << "]";
                    const std::string category = diagnostic.value("category", "");
                    if (!category.empty()) {
                        std::cout << " [" << category << "]";
                    }
                    std::cout << " " << diagnostic.value("message", "") << std::endl;
                }
            }
            if (item.value("diagnostics_truncated", false)) {
                std::cout << "  ... diagnostics truncated" << std::endl;
            }
        }
    }

    return ok ? 0 : 1;
}

int print_policy_restriction(const json& response, const std::string& module, const std::string& policy) {
    if (!response.value("ok", false)) {
        return print_response(response);
    }

    if (!response.contains("policies") || !response["policies"].is_array()) {
        std::cout << "policy information is unavailable" << std::endl;
        return 1;
    }

    for (const auto& item : response["policies"]) {
        if (item.value("policy", "") != policy) {
            continue;
        }

        const std::string restriction = item.value("restriction", "");
        std::cout << restriction;
        if (restriction.empty() || restriction.back() != '\n') {
            std::cout << std::endl;
        }
        return 0;
    }

    std::cout << "policy not found: " << module << " " << policy << std::endl;
    return 1;
}

int print_policy_state(const json& response, bool expectedEnabled) {
    if (!response.value("ok", false)) {
        return print_response(response);
    }
    if (!response.contains("enabled")) {
        std::cout << "policy status is unavailable" << std::endl;
        return 1;
    }

    std::cout << (response.value("enabled", false) == expectedEnabled ? "true" : "false") << std::endl;
    return 0;
}

int print_policy_value(const json& response) {
    if (!response.value("ok", false)) {
        return print_response(response);
    }
    if (!response.contains("value")) {
        std::cout << "policy value is unavailable" << std::endl;
        return 1;
    }

    std::cout << response.value("value", "") << std::endl;
    return 0;
}

fic::ipc::Client device_client()
{
    return fic::ipc::Client(fic::ipc::Endpoint::DeviceDaemon);
}

void print_device_item(const json& item)
{
    std::cout << item.value("id", 0)
              << " parent=" << item.value("parent_id", 0)
              << " subsystem=" << item.value("subsystem", "")
              << " assigned=" << item.value("control_level", "")
              << (item.value("control_explicit", true) ? "(explicit)" : "(inherited)")
              << " effective=" << item.value("effective_control_level", "")
              << " ignore_hierarchy=" << (item.value("ignore_hierarchy", false) ? "true" : "false")
              << " connected=" << (item.value("connected", false) ? "true" : "false")
              << " devpath=" << item.value("devpath", "")
              << std::endl;
}

int print_device_response(const json& response)
{
    const bool ok = response.value("ok", false);
    if (!ok) {
        std::cout << response.value("message", "ERROR") << std::endl;
        if (response.contains("blockers") && response["blockers"].is_array()) {
            for (const auto& blocker : response["blockers"]) {
                std::cout << "blocker: id=" << blocker.value("device_id", 0)
                          << " source=" << blocker.value("source", "")
                          << " devpath=" << blocker.value("devpath", "")
                          << std::endl;
            }
        }
        return 1;
    }

    std::cout << response.value("message", "OK") << std::endl;
    if (response.contains("revision") && response["revision"].is_number_integer()) {
        std::cout << "revision=" << response["revision"].get<std::int64_t>() << std::endl;
    }
    if (response.contains("device") && response["device"].is_object()) {
        print_device_item(response["device"]);
    }
    if (response.contains("children") && response["children"].is_array()) {
        for (const auto& child : response["children"]) {
            if (child.is_object()) {
                print_device_item(child);
            }
        }
    }
    if (response.contains("missing") && response["missing"].is_array()) {
        for (const auto& missing : response["missing"]) {
            std::cout << "missing: id=" << missing.value("device_id", 0)
                      << " source=" << missing.value("source", "")
                      << " devpath=" << missing.value("devpath", "")
                      << std::endl;
        }
    }
    return 0;
}

bool parse_bool_arg(const std::string& value, bool& result)
{
    if (value == "true" || value == "1" || value == "yes" || value == "on") {
        result = true;
        return true;
    }
    if (value == "false" || value == "0" || value == "no" || value == "off") {
        result = false;
        return true;
    }
    return false;
}
} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    fic::ipc::Client client;
    const std::string command = arg(argc, argv, 1);

    if (command == "help") {
        print_help();
        return 0;
    }

    if (command == "status" || command == "shutdown") {
        return print_response(client.request({{"command", command}}));
    }

    if (command == "policy") {
        const std::string action = arg(argc, argv, 2);
        const std::string module = arg(argc, argv, 3);
        const std::string policy = arg(argc, argv, 4);

        if (action == "info") {
            const std::string infoType = arg(argc, argv, 3);
            const std::string infoModule = arg(argc, argv, 4);
            const std::string infoPolicy = arg(argc, argv, 5);
            if (infoType != "restriction" || infoModule.empty() || infoPolicy.empty()) {
                print_help();
                return 1;
            }
            return print_policy_restriction(
                client.request({{"command", "policy_list"}, {"module", infoModule}}),
                infoModule,
                infoPolicy
            );
        }

        if (action == "set") {
            const std::string value = arg(argc, argv, 5);
            if (module.empty() || policy.empty() || value.empty()) {
                print_help();
                return 1;
            }
            return print_response(client.request({{"command", "set_policy_value"}, {"module", module}, {"policy", policy}, {"value", value}}));
        }
        if (action == "enable") {
            return print_response(client.request({{"command", "enable_policy"}, {"module", module}, {"policy", policy}}));
        }
        if (action == "disable") {
            return print_response(client.request({{"command", "disable_policy"}, {"module", module}, {"policy", policy}}));
        }
        if (action == "isenable" || action == "isdisable" || action == "value") {
            if (module.empty() || policy.empty()) {
                print_help();
                return 1;
            }
            if (action == "value") {
                return print_policy_value(client.request({{"command", "policy_value"}, {"module", module}, {"policy", policy}}));
            }
            return print_policy_state(
                client.request({{"command", action == "isenable" ? "policy_is_enabled" : "policy_is_disabled"}, {"module", module}, {"policy", policy}}),
                action == "isenable"
            );
        }
        if (action == "apply") {
            if (module == "all") {
                return print_policy_apply_response(client.request({{"command", "apply_all"}}));
            }
            if (policy == "all") {
                return print_policy_apply_response(client.request({{"command", "apply_module"}, {"module", module}}));
            }
            return print_policy_apply_response(client.request({{"command", "apply_policy"}, {"module", module}, {"policy", policy}}));
        }
        if (action == "list") {
            return print_response(client.request({{"command", "policy_list"}, {"module", module.empty() ? "all" : module}}));
        }
    }

    if (command == "module" && arg(argc, argv, 2) == "list") {
        return print_response(client.request({{"command", "module_list"}}));
    }

    if (command == "device") {
        const std::string action = arg(argc, argv, 2);
        fic::ipc::Client devices = device_client();

        if (action == "revision") {
            return print_device_response(devices.request({{"command", "device_tree_revision"}}));
        }
        if (action == "root") {
            return print_device_response(devices.request({{"command", "device_root"}}));
        }
        if (action == "get") {
            const std::string id = arg(argc, argv, 3);
            if (id.empty()) {
                print_help();
                return 1;
            }
            return print_device_response(devices.request({{"command", "device_get"}, {"device_id", std::stoi(id)}}));
        }
        if (action == "children") {
            const std::string id = arg(argc, argv, 3);
            if (id.empty()) {
                print_help();
                return 1;
            }
            const std::string mode = arg(argc, argv, 4);
            const bool includeDisconnected = mode == "--all" || mode == "--history" || mode == "all" || mode == "history";
            if (!mode.empty() && !includeDisconnected) {
                print_help();
                return 1;
            }
            return print_device_response(devices.request({
                {"command", "device_children"},
                {"parent_id", std::stoi(id)},
                {"include_disconnected", includeDisconnected}
            }));
        }
        if (action == "set") {
            const std::string id = arg(argc, argv, 3);
            const std::string level = arg(argc, argv, 4);
            if (id.empty() || level.empty()) {
                print_help();
                return 1;
            }
            return print_device_response(devices.request({{"command", "device_update_control_level"}, {"device_id", std::stoi(id)}, {"control_level", level}}));
        }
        if (action == "ignore-hierarchy") {
            const std::string id = arg(argc, argv, 3);
            bool ignoreHierarchy = false;
            if (id.empty() || !parse_bool_arg(arg(argc, argv, 4), ignoreHierarchy)) {
                print_help();
                return 1;
            }
            return print_device_response(devices.request({{"command", "device_update_ignore_hierarchy"}, {"device_id", std::stoi(id)}, {"ignore_hierarchy", ignoreHierarchy}}));
        }
        if (action == "reset") {
            const std::string id = arg(argc, argv, 3);
            if (id.empty()) {
                print_help();
                return 1;
            }
            return print_device_response(devices.request({{"command", "device_reset_control"}, {"device_id", std::stoi(id)}}));
        }
        if (action == "check-permanent") {
            return print_device_response(devices.request({{"command", "device_check_permanent"}}));
        }
    }

    if (command == "hash" && arg(argc, argv, 2) == "calc") {
        const std::string path = arg(argc, argv, 3);
        if (path.empty()) {
            print_help();
            return 1;
        }
        return print_response(client.request({{"command", "calc_hash"}, {"value", path}}));
    }

    if (command == "lock" || command == "unlock" || command == "lockstatus") {
        return print_response(client.request({{"command", command}}));
    }

    std::cout << "Unknown command" << std::endl;
    print_help();
    return 1;
}
