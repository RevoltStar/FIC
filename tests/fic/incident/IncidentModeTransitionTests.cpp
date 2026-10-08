#include "incident/IncidentModeTransition.h"

#include <stdexcept>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    using fic::incident::managedModeMutationMayActivate;
    using fic::incident::runGuardedModeMutation;

    require(managedModeMutationMayActivate("set_policy_value", "GLOBAL",
                "incident_response_mode", "ACTIVE", true, "PASSIVE"),
            "PASSIVE to ACTIVE must be guarded");
    require(managedModeMutationMayActivate("enable_policy", "GLOBAL",
                "incident_response_mode", "", false, "ACTIVE"),
            "OFF with stored ACTIVE must be guarded");
    require(!managedModeMutationMayActivate("set_policy_value", "GLOBAL",
                "incident_response_mode", "ACTIVE", false, "PASSIVE"),
            "disabled policy value edit must leave SSH alone");
    require(!managedModeMutationMayActivate("disable_policy", "GLOBAL",
                "incident_response_mode", "", true, "ACTIVE"),
            "leaving ACTIVE must not preblock SSH");

    std::vector<std::string> events;
    const auto run = [&](bool entering, bool blockSucceeds) {
        events.clear();
        return runGuardedModeMutation<int>(entering,
            [&](std::string& error) {
                events.emplace_back("block");
                if (!blockSucceeds) error = "stop failed";
                return blockSucceeds;
            },
            [&] {
                events.emplace_back("write GLOBAL");
                return 1;
            },
            [&](const std::string& error) {
                require(error == "stop failed", "block diagnostic lost");
                events.emplace_back("failed");
                return 0;
            });
    };
    require(run(true, true) == 1 &&
            events == std::vector<std::string>({"block", "write GLOBAL"}),
            "ACTIVE must be blocked before configuration write");
    require(run(true, false) == 0 &&
            events == std::vector<std::string>({"block", "failed"}),
            "failed block must prevent configuration write");
    require(run(false, true) == 1 &&
            events == std::vector<std::string>({"write GLOBAL"}),
            "unchanged effective mode must not block SSH");

    // Follow the production packet order with a controlled module resolver.
    const auto packet = [&](const std::string& module,
                            const std::string& command,
                            const std::string& policy,
                            const std::string& value,
                            bool enabled, const std::string& stored,
                            bool guardSucceeds) {
        nlohmann::json request = nlohmann::json::parse(
            nlohmann::json{{"command", command}, {"module", module},
                           {"policy", policy}, {"value", value}}.dump());
        require(request["module"].is_string() && request["policy"].is_string() &&
                request["value"].is_string(), "packet schema rejected");
        fic::incident::canonicalizePolicyRequest(request,
            [](const std::string& name) {
                if (name == "GLOBAL" || name == "global" || name == "Global")
                    return std::string("GLOBAL");
                return name;
            });
        const bool known = request["module"] == "GLOBAL";
        const bool entering = managedModeMutationMayActivate(
            request["command"], request["module"], request["policy"],
            request["value"], enabled, stored);
        std::vector<std::string> trace;
        const int result = runGuardedModeMutation<int>(entering,
            [&](std::string& error) {
                trace.emplace_back("block");
                if (!guardSucceeds) error = "SSH guard failed";
                return guardSucceeds;
            },
            [&] {
                if (!known) return -1;
                trace.emplace_back("write");
                trace.emplace_back("recompute");
                return 1;
            },
            [&](const std::string& error) {
                require(error == "SSH guard failed", "wrong guard error");
                trace.emplace_back("error");
                return 0;
            });
        return std::pair<int, std::vector<std::string>>(result, trace);
    };
    for (const std::string& alias : {"GLOBAL", "global", "Global"}) {
        require(packet(alias, "set_policy_value", "incident_response_mode",
                       "ACTIVE", true, "PASSIVE", true) ==
                    std::make_pair(1, std::vector<std::string>{"block", "write", "recompute"}),
                "alias ACTIVE transition must block before write");
        require(packet(alias, "enable_policy", "incident_response_mode",
                       "", false, "ACTIVE", true).second.front() == "block",
                "alias enable of stored ACTIVE must block");
        require(packet(alias, "set_policy_value", "incident_response_mode",
                       "ACTIVE", false, "PASSIVE", true).second.front() == "write",
                "disabled value edit must not block");
        require(packet(alias, "set_policy_value", "incident_response_mode",
                       "PASSIVE", true, "ACTIVE", true).second.front() == "write",
                "ACTIVE to PASSIVE must not preblock");
        require(packet(alias, "disable_policy", "incident_response_mode",
                       "", true, "ACTIVE", true).second.front() == "write",
                "ACTIVE to OFF must not preblock");
        require(packet(alias, "set_policy_value", "incident_response_mode",
                       "PASSIVE", true, "PASSIVE", true).second.front() == "write",
                "unchanged PASSIVE must not block");
        require(packet(alias, "set_policy_value", "other_policy",
                       "ACTIVE", true, "PASSIVE", true).second.front() == "write",
                "other GLOBAL policy must not be classified as mode");
        require(packet(alias, "set_policy_value", "incident_response_mode",
                       "ACTIVE", true, "PASSIVE", false) ==
                    std::make_pair(0, std::vector<std::string>{"block", "error"}),
                "failed guard must prevent write and return error");
    }
    require(packet("UNKNOWN", "set_policy_value", "incident_response_mode",
                   "ACTIVE", true, "PASSIVE", true) ==
                std::make_pair(-1, std::vector<std::string>{}),
            "unknown module must neither block nor mutate");
}
