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
    const PolicyChange unchanged{
        "sssd_offline_credentials_expiration", "30", false, true,
        false, false};
    const PolicyChange valueOnly{
        "sudo_timeout", "60", false, true, false, true};
    const PolicyChange enableOnly{
        "sudo_timeout", "30", true, true, true, false};
    const PolicyChange disableOnly{
        "sudo_env_reset", "", false, false, true, false};
    const PolicyChange both{
        "sudo_timeout", "60", true, true, true, true};
    const std::vector<PolicyChange> changes = {both, disableOnly};

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
    assert(applyResult.status == PolicyService::ApplyStatus::ApplyFailed);
    assert(applyResult.error == "connect failed: refused");
    assert(applyResult.response.is_null());

    PolicyService malformed([](const nlohmann::json&) {
        return completed({{"ok", "yes"}, {"message", "invalid"}});
    });
    applyResult = malformed.saveAndApplyChanges("DAC", {});
    assert(applyResult.status == PolicyService::ApplyStatus::ApplyFailed);
    assert(applyResult.error.contains("apply_module protocol error"));
    assert(applyResult.response.is_null());

    PolicyService malformedDetails([](const nlohmann::json&) {
        return completed({
            {"ok", false}, {"message", "invalid details"},
            {"results", {{{"diagnostics", {7}}}}}
        });
    });
    applyResult = malformedDetails.saveAndApplyChanges("DAC", {});
    assert(applyResult.status == PolicyService::ApplyStatus::ApplyFailed);
    assert(applyResult.error.contains("invalid diagnostic"));
    assert(applyResult.response.is_null());

    std::vector<std::string> commands;
    PolicyService success([&commands](const nlohmann::json& request) {
        commands.push_back(request.at("command").get<std::string>());
        return completed({{"ok", true}, {"message", "accepted"}});
    });
    assert(success.saveChanges("DAC", {unchanged}, error));
    assert(commands.empty());
    assert(error.isEmpty());

    assert(success.saveChanges("DAC", {valueOnly}, error));
    assert((commands == std::vector<std::string>{"set_policy_value"}));
    assert(error.isEmpty());

    commands.clear();
    assert(success.saveChanges("DAC", {enableOnly}, error));
    assert((commands == std::vector<std::string>{"enable_policy"}));
    assert(error.isEmpty());

    commands.clear();
    assert(success.saveChanges("DAC", {disableOnly}, error));
    assert((commands == std::vector<std::string>{"disable_policy"}));
    assert(error.isEmpty());

    commands.clear();
    assert(success.saveChanges("DAC", {both}, error));
    assert((commands == std::vector<std::string>{
        "set_policy_value", "enable_policy"}));
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
    applyResult = valueFailure.saveAndApplyChanges("DAC", {both});
    assert(applyResult.status == PolicyService::ApplyStatus::SaveFailed);
    assert(applyResult.error.contains(
        "set_policy_value failed for sudo_timeout: value denied"));
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
    applyResult = stateFailure.saveAndApplyChanges("DAC", {both});
    assert(applyResult.status == PolicyService::ApplyStatus::SaveFailed);
    assert(applyResult.error.contains(
        "enable_policy failed for sudo_timeout: enable denied"));
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
    applyResult = disableFailure.saveAndApplyChanges("DAC", {disableOnly});
    assert(applyResult.status == PolicyService::ApplyStatus::SaveFailed);
    assert(applyResult.error.contains(
        "disable_policy failed for sudo_env_reset: disable denied"));
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
