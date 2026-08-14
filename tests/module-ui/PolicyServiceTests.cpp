#include "services/PolicyService.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

int main()
{
    nlohmann::json applyResponse;
    QString error;

    PolicyService daemonFailure([](const nlohmann::json&) {
        return nlohmann::json{{"ok", false}, {"message", "daemon apply failed"}};
    });
    assert(!daemonFailure.applyChanges("DAC", {}, applyResponse, error));
    assert(error == "daemon apply failed");
    assert(applyResponse["ok"] == false);

    PolicyService transportFailure([](const nlohmann::json&) {
        return nlohmann::json{{"ok", false}, {"message", "connect failed: refused"}};
    });
    assert(!transportFailure.applyChanges("DAC", {}, applyResponse, error));
    assert(error == "connect failed: refused");

    PolicyService malformed([](const nlohmann::json&) {
        return nlohmann::json{{"ok", "yes"}, {"message", "invalid"}};
    });
    assert(!malformed.applyChanges("DAC", {}, applyResponse, error));
    assert(error.contains("apply_module protocol error"));

    std::vector<std::string> commands;
    PolicyService success([&commands](const nlohmann::json& request) {
        commands.push_back(request.at("command").get<std::string>());
        return nlohmann::json{{"ok", true}, {"message", "accepted"}};
    });
    const std::vector<PolicyChange> changes = {
        {"sudo_timeout", "10", true, true},
        {"sudo_env_reset", "", false, false}
    };
    assert(success.applyChanges("DAC", changes, applyResponse, error));
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy", "disable_policy", "apply_module"}));
    assert(error.isEmpty());

    PolicyService stateFailure([](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        if (command == "enable_policy") {
            return nlohmann::json{{"ok", false}, {"message", "enable denied"}};
        }
        return nlohmann::json{{"ok", true}, {"message", "accepted"}};
    });
    assert(!stateFailure.applyChanges("DAC", {changes.front()}, applyResponse, error));
    assert(error == "enable denied");

    return 0;
}
