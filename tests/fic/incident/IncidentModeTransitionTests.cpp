#include "incident/IncidentModeTransition.h"

#include <stdexcept>
#include <string>
#include <vector>

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
}
