#include "features/policies/services/PolicyService.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <utility>
#include <vector>

namespace {
PolicyService::RequestResult completed(nlohmann::json response)
{
    return {true, std::move(response), {}};
}

PolicyService::RequestResult serviceError(std::string error)
{
    return {false, {}, std::move(error)};
}
}

int main()
{
    QString error;
    const PolicyChange enabledValue{"sudo_timeout", "10", true, true};
    const PolicyChange disabled{"sudo_env_reset", "", false, false};
    const std::vector<PolicyChange> changes = {enabledValue, disabled};

    const nlohmann::json failedApply = {
        {"ok", false},
        {"message", "daemon apply failed"},
        {"summary", {{"total", 1}, {"failed", 1}}},
        {"results", {{{"module", "DAC"}, {"policy", "sudo_timeout"},
                      {"status", "failed"}}}}
    };
    PolicyService daemonFailure([&failedApply](const nlohmann::json&) {
        return completed(failedApply);
    });
    PolicyService::ApplyResult applyResult =
        daemonFailure.saveAndApplyChanges("DAC", {});
    assert(applyResult.status == PolicyService::ApplyStatus::Completed);
    assert(applyResult.error.isEmpty());
    assert(applyResult.response == failedApply);
    assert(applyResult.response["summary"]["failed"] == 1);
    assert(applyResult.response["results"].size() == 1);

    PolicyService transportFailure([](const nlohmann::json&) {
        return serviceError("connect failed: refused");
    });
    applyResult = transportFailure.saveAndApplyChanges("DAC", {});
    assert(applyResult.status == PolicyService::ApplyStatus::ServiceError);
    assert(applyResult.error == "connect failed: refused");
    assert(applyResult.response.is_null());

    PolicyService malformed([](const nlohmann::json&) {
        return completed({{"ok", "yes"}, {"message", "invalid"}});
    });
    applyResult = malformed.saveAndApplyChanges("DAC", {});
    assert(applyResult.status == PolicyService::ApplyStatus::ServiceError);
    assert(applyResult.error.contains("apply_module protocol error"));
    assert(applyResult.response.is_null());

    PolicyService malformedDetails([](const nlohmann::json&) {
        return completed({
            {"ok", false}, {"message", "invalid details"},
            {"results", {{{"diagnostics", {7}}}}}
        });
    });
    applyResult = malformedDetails.saveAndApplyChanges("DAC", {});
    assert(applyResult.status == PolicyService::ApplyStatus::ServiceError);
    assert(applyResult.error.contains("invalid diagnostic"));
    assert(applyResult.response.is_null());

    std::vector<std::string> commands;
    PolicyService success([&commands](const nlohmann::json& request) {
        commands.push_back(request.at("command").get<std::string>());
        return completed({{"ok", true}, {"message", "accepted"}});
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
    applyResult = success.saveAndApplyChanges("DAC", changes);
    assert(applyResult.status == PolicyService::ApplyStatus::Completed);
    assert(applyResult.response["ok"] == true);
    assert(applyResult.error.isEmpty());
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy", "disable_policy", "apply_module"}));
    assert(error.isEmpty());

    commands.clear();
    PolicyService valueFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "set_policy_value") {
            return completed({{"ok", false}, {"message", "value denied"}});
        }
        return completed({{"ok", true}, {"message", "accepted"}});
    });
    applyResult = valueFailure.saveAndApplyChanges("DAC", {enabledValue});
    assert(applyResult.status == PolicyService::ApplyStatus::ServiceError);
    assert(applyResult.error == "value denied");
    assert((commands == std::vector<std::string>{"set_policy_value"}));

    commands.clear();
    PolicyService stateFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "enable_policy") {
            return completed({{"ok", false}, {"message", "enable denied"}});
        }
        return completed({{"ok", true}, {"message", "accepted"}});
    });
    applyResult = stateFailure.saveAndApplyChanges("DAC", {enabledValue});
    assert(applyResult.status == PolicyService::ApplyStatus::ServiceError);
    assert(applyResult.error == "enable denied");
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy"}));

    commands.clear();
    PolicyService disableFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "disable_policy") {
            return completed({{"ok", false}, {"message", "disable denied"}});
        }
        return completed({{"ok", true}, {"message", "accepted"}});
    });
    applyResult = disableFailure.saveAndApplyChanges("DAC", {disabled});
    assert(applyResult.status == PolicyService::ApplyStatus::ServiceError);
    assert(applyResult.error == "disable denied");
    assert((commands == std::vector<std::string>{"disable_policy"}));

    commands.clear();
    PolicyService applyFailure([&commands](const nlohmann::json& request) {
        const std::string command = request.at("command").get<std::string>();
        commands.push_back(command);
        if (command == "apply_module") {
            return completed({{"ok", false}, {"message", "apply denied"}});
        }
        return completed({{"ok", true}, {"message", "accepted"}});
    });
    applyResult = applyFailure.saveAndApplyChanges("DAC", changes);
    assert(applyResult.status == PolicyService::ApplyStatus::Completed);
    assert(applyResult.error.isEmpty());
    assert(applyResult.response["ok"] == false);
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy", "disable_policy", "apply_module"}));

    return 0;
}
