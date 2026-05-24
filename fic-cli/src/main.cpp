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
              << "  policy check all\n"
              << "  policy check <module> all\n"
              << "  policy check <module> <policy>\n"
              << "  policy list <module|all>\n"
              << "  module list\n"
              << "  hash calc <path>\n"
              << "  lock | unlock | lockstatus | status | shutdown\n";
}

int print_response(const json& response) {
    bool ok = response.value("ok", false);
    std::cout << response.value("message", ok ? "OK" : "ERROR") << std::endl;

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

    return ok ? 0 : 1;
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
        if (action == "check") {
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
