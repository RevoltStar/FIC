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
        {"validator", "integer_range"},
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
    assert(policies.front().validator == "integer_range");

    assert(validatePolicyDescriptorValue(policies.front(), "10", error));
    assert(!validatePolicyDescriptorValue(policies.front(), "invalid", error));
    assert(error.find("is not an integer") != std::string::npos);
    assert(!validatePolicyDescriptorValue(policies.front(), "61", error));
    assert(error.find("outside allowed range") != std::string::npos);

    auto textDescriptor = validDescriptor();
    textDescriptor["policy"] = "user_default_shell";
    textDescriptor["editor"] = "lineedit";
    textDescriptor["validator"] = "none";
    textDescriptor.erase("min");
    textDescriptor.erase("max");
    assert(parseOne(textDescriptor, policies, error));
    assert(validatePolicyDescriptorValue(policies.front(), "/bin/bash", error));
    assert(validatePolicyDescriptorValue(policies.front(), "users", error));

    auto unsignedDescriptor = textDescriptor;
    unsignedDescriptor["policy"] = "uid_min";
    unsignedDescriptor["validator"] = "unsigned_integer";
    assert(parseOne(unsignedDescriptor, policies, error));
    assert(validatePolicyDescriptorValue(policies.front(), "1000", error));
    assert(!validatePolicyDescriptorValue(policies.front(), "/home", error));
    assert(error.find("unsigned decimal integer") != std::string::npos);

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
    invalid.erase("validator");
    assert(!parseOne(invalid, policies, error));
    assert(error.find("missing required field 'validator'") != std::string::npos);

    invalid = validDescriptor();
    invalid["validator"] = "path_from_restriction_text";
    assert(!parseOne(invalid, policies, error));
    assert(error.find("unknown validator") != std::string::npos);

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
