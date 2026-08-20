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
    const PolicyChange enabledValue{"sudo_timeout", "10", true, true};
    const PolicyChange disabled{"sudo_env_reset", "", false, false};
    const std::vector<PolicyChange> changes = {enabledValue, disabled};

    PolicyService daemonFailure([](const nlohmann::json&) {
        return nlohmann::json{{"ok", false}, {"message", "daemon apply failed"}};
    });
    assert(!daemonFailure.saveAndApplyChanges("DAC", {}, applyResponse, error));
    assert(error == "daemon apply failed");
    assert(applyResponse["ok"] == false);

    PolicyService transportFailure([](const nlohmann::json&) {
        return nlohmann::json{{"ok", false}, {"message", "connect failed: refused"}};
    });
    assert(!transportFailure.saveAndApplyChanges("DAC", {}, applyResponse, error));
    assert(error == "connect failed: refused");

    PolicyService malformed([](const nlohmann::json&) {
        return nlohmann::json{{"ok", "yes"}, {"message", "invalid"}};
    });
    assert(!malformed.saveAndApplyChanges("DAC", {}, applyResponse, error));
    assert(error.contains("apply_module protocol error"));

    std::vector<std::string> commands;
    PolicyService success([&commands](const nlohmann::json& request) {
        commands.push_back(request.at("command").get<std::string>());
        return nlohmann::json{{"ok", true}, {"message", "accepted"}};
    });
    assert(success.saveChanges("DAC", {enabledValue}, error));
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy"}));
    assert(error.isEmpty());

    commands.clear();
    assert(success.saveChanges("DAC", {disabled}, error));
    assert((commands == std::vector<std::string>{"disable_policy"}));
    assert(error.isEmpty());

    commands.clear();
    assert(success.saveAndApplyChanges("DAC", changes, applyResponse, error));
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy", "disable_policy", "apply_module"}));
    assert(error.isEmpty());

    commands.clear();
    PolicyService valueFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "set_policy_value") {
            return nlohmann::json{{"ok", false}, {"message", "value denied"}};
        }
        return nlohmann::json{{"ok", true}, {"message", "accepted"}};
    });
    assert(!valueFailure.saveAndApplyChanges(
        "DAC", {enabledValue}, applyResponse, error));
    assert(error == "value denied");
    assert((commands == std::vector<std::string>{"set_policy_value"}));

    commands.clear();
    PolicyService stateFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "enable_policy") {
            return nlohmann::json{{"ok", false}, {"message", "enable denied"}};
        }
        return nlohmann::json{{"ok", true}, {"message", "accepted"}};
    });
    assert(!stateFailure.saveAndApplyChanges(
        "DAC", {enabledValue}, applyResponse, error));
    assert(error == "enable denied");
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy"}));

    commands.clear();
    PolicyService disableFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "disable_policy") {
            return nlohmann::json{{"ok", false}, {"message", "disable denied"}};
        }
        return nlohmann::json{{"ok", true}, {"message", "accepted"}};
    });
    assert(!disableFailure.saveAndApplyChanges(
        "DAC", {disabled}, applyResponse, error));
    assert(error == "disable denied");
    assert((commands == std::vector<std::string>{"disable_policy"}));

    commands.clear();
    PolicyService applyFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "apply_module") {
            return nlohmann::json{{"ok", false}, {"message", "apply denied"}};
        }
        return nlohmann::json{{"ok", true}, {"message", "accepted"}};
    });
    assert(!applyFailure.saveAndApplyChanges(
        "DAC", changes, applyResponse, error));
    assert(error == "apply denied");
    assert(applyResponse["ok"] == false);
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy", "disable_policy", "apply_module"}));

    return 0;
}
