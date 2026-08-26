#include "features/policies/models/PolicyDescriptor.h"

#include <cstdint>
#include <limits>

#include <nlohmann/json.hpp>

namespace {
bool fail(std::vector<PolicyDescriptor>& policies,
          std::string& error,
          const std::string& message)
{
    policies.clear();
    error = "policy_list protocol error: " + message;
    return false;
}

bool requireField(const nlohmann::json& item,
                  const char* field,
                  nlohmann::json::value_t type,
                  std::size_t index,
                  std::vector<PolicyDescriptor>& policies,
                  std::string& error)
{
    const auto value = item.find(field);
    if (value == item.end()) {
        return fail(policies, error, "descriptor " + std::to_string(index) +
            " is missing required field '" + field + "'");
    }
    if (value->type() != type) {
        return fail(policies, error, "descriptor " + std::to_string(index) +
            " field '" + field + "' has the wrong type");
    }
    return true;
}
}

bool parsePolicyDescriptors(
    const nlohmann::json& response,
    const std::string& expectedModule,
    std::vector<PolicyDescriptor>& policies,
    std::string& error)
{
    policies.clear();
    error.clear();
    try {
        if (!response.is_object()) {
            return fail(policies, error, "daemon response must be an object");
        }
        const auto ok = response.find("ok");
        if (ok == response.end() || !ok->is_boolean()) {
            return fail(policies, error, "response field 'ok' must be a boolean");
        }
        const auto message = response.find("message");
        if (message == response.end() || !message->is_string()) {
            return fail(policies, error, "response field 'message' must be a string");
        }
        if (!ok->get<bool>()) {
            error = message->get<std::string>();
            return false;
        }
        const auto policyItems = response.find("policies");
        if (policyItems == response.end() || !policyItems->is_array()) {
            return fail(policies, error, "daemon response does not contain a policies array");
        }

        std::size_t index = 0;
        for (const auto& item : *policyItems) {
            if (!item.is_object()) {
                return fail(policies, error, "descriptor " + std::to_string(index) +
                    " must be an object");
            }
            const std::pair<const char*, nlohmann::json::value_t> required[] = {
                {"module", nlohmann::json::value_t::string},
                {"submodule", nlohmann::json::value_t::string},
                {"policy", nlohmann::json::value_t::string},
                {"editor", nlohmann::json::value_t::string},
                {"enabled", nlohmann::json::value_t::boolean},
                {"set", nlohmann::json::value_t::boolean},
                {"value_valid", nlohmann::json::value_t::boolean},
                {"value", nlohmann::json::value_t::string},
                {"default_value", nlohmann::json::value_t::string},
                {"restriction", nlohmann::json::value_t::string},
                {"possible_values", nlohmann::json::value_t::array}
            };
            for (const auto& [field, type] : required) {
                if (!requireField(item, field, type, index, policies, error)) {
                    return false;
                }
            }
            for (const char* field : {"min", "max"}) {
                const auto value = item.find(field);
                if (value != item.end() && !value->is_number_integer()) {
                    return fail(policies, error, "descriptor " + std::to_string(index) +
                        " field '" + field + "' must be an integer");
                }
                if (value != item.end()) {
                    const std::int64_t number = value->get<std::int64_t>();
                    if (number < std::numeric_limits<int>::min() ||
                        number > std::numeric_limits<int>::max()) {
                        return fail(policies, error, "descriptor " + std::to_string(index) +
                            " field '" + field + "' is outside the supported integer range");
                    }
                }
            }
            const auto delimiter = item.find("text_delimiter");
            if (delimiter != item.end() && !delimiter->is_string()) {
                return fail(policies, error, "descriptor " + std::to_string(index) +
                    " field 'text_delimiter' must be a string");
            }

            PolicyDescriptor policy;
            policy.moduleName = item.at("module").get<std::string>();
            policy.submoduleName = item.at("submodule").get<std::string>();
            policy.policyName = item.at("policy").get<std::string>();
            policy.editor = item.at("editor").get<std::string>();
            policy.enabled = item.at("enabled").get<bool>();
            policy.isSet = item.at("set").get<bool>();
            policy.valueValid = item.at("value_valid").get<bool>();
            policy.value = item.at("value").get<std::string>();
            policy.defaultValue = item.at("default_value").get<std::string>();
            policy.restriction = item.at("restriction").get<std::string>();
            if (policy.policyName.empty()) {
                return fail(policies, error, "descriptor " + std::to_string(index) +
                    " has an empty policy name");
            }
            if (policy.moduleName != expectedModule) {
                return fail(policies, error, "descriptor " + std::to_string(index) +
                    " module does not match requested module '" + expectedModule + "'");
            }

            for (const auto& value : item.at("possible_values")) {
                if (!value.is_string()) {
                    return fail(policies, error, "descriptor " + std::to_string(index) +
                        " contains a non-string possible_values item");
                }
                policy.possibleValues.push_back(value.get<std::string>());
            }
            if (item.contains("min")) {
                policy.min = item.at("min").get<int>();
            }
            if (item.contains("max")) {
                policy.max = item.at("max").get<int>();
            }
            if (delimiter != item.end()) {
                policy.textDelimiter = delimiter->get<std::string>();
            }
            policies.push_back(std::move(policy));
            ++index;
        }
        return true;
    } catch (const nlohmann::json::exception& exception) {
        return fail(policies, error, "malformed descriptor: " + std::string(exception.what()));
    } catch (const std::exception& exception) {
        return fail(policies, error, "malformed descriptor: " + std::string(exception.what()));
    }
}
