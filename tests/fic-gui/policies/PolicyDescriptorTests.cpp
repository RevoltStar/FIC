#include "features/policies/models/PolicyDescriptor.h"

#include <nlohmann/json.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

namespace {
nlohmann::json validDescriptor()
{
    return {
        {"module", "DAC"},
        {"submodule", "Sudo"},
        {"policy", "sudo_timeout"},
        {"editor", "spinbox"},
        {"enabled", true},
        {"set", true},
        {"value_valid", true},
        {"value", "10"},
        {"default_value", "5"},
        {"restriction", "integer from 0 to 60"},
        {"possible_values", nlohmann::json::array()},
        {"min", 0},
        {"max", 60},
        {"text_delimiter", "\n"}
    };
}

bool parseOne(const nlohmann::json& descriptor,
              std::vector<PolicyDescriptor>& policies,
              std::string& error)
{
    return parsePolicyDescriptors(
        {{"ok", true}, {"message", "policies listed"},
         {"policies", nlohmann::json::array({descriptor})}},
        "DAC", policies, error);
}
}

int main()
{
    std::vector<PolicyDescriptor> policies;
    std::string error;

    assert(parseOne(validDescriptor(), policies, error));
    assert(policies.size() == 1);
    assert(policies.front().moduleName == "DAC");
    assert(policies.front().policyName == "sudo_timeout");
    assert(policies.front().min == 0);
    assert(policies.front().max == 60);

    auto invalid = validDescriptor();
    invalid["module"] = 3;
    assert(!parseOne(invalid, policies, error));
    assert(error.find("field 'module'") != std::string::npos);

    invalid = validDescriptor();
    invalid["enabled"] = "yes";
    assert(!parseOne(invalid, policies, error));
    assert(error.find("field 'enabled'") != std::string::npos);

    invalid = validDescriptor();
    invalid["min"] = 1.5;
    assert(!parseOne(invalid, policies, error));
    assert(error.find("field 'min'") != std::string::npos);

    invalid = validDescriptor();
    invalid["max"] = "60";
    assert(!parseOne(invalid, policies, error));
    assert(error.find("field 'max'") != std::string::npos);

    invalid = validDescriptor();
    invalid["possible_values"] = nlohmann::json::array({"one", 2});
    assert(!parseOne(invalid, policies, error));
    assert(error.find("non-string possible_values") != std::string::npos);

    invalid = validDescriptor();
    invalid.erase("restriction");
    assert(!parseOne(invalid, policies, error));
    assert(error.find("missing required field 'restriction'") != std::string::npos);

    invalid = validDescriptor();
    invalid["module"] = "NET";
    assert(!parseOne(invalid, policies, error));
    assert(error.find("does not match requested module") != std::string::npos);

    invalid = validDescriptor();
    invalid["min"] = nlohmann::json::parse("9223372036854775807");
    assert(!parseOne(invalid, policies, error));
    assert(error.find("protocol error") != std::string::npos);
    assert(policies.empty());

    return 0;
}
