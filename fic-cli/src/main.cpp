#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

#include "ipc/FicIpcClient.h"

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
                return print_response(client.request({{"command", "apply_all"}}));
            }
            if (policy == "all") {
                return print_response(client.request({{"command", "apply_module"}, {"module", module}}));
            }
            return print_response(client.request({{"command", "apply_policy"}, {"module", module}, {"policy", policy}}));
        }
        if (action == "list") {
            return print_response(client.request({{"command", "policy_list"}, {"module", module.empty() ? "all" : module}}));
        }
    }

    if (command == "module" && arg(argc, argv, 2) == "list") {
        return print_response(client.request({{"command", "module_list"}}));
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
