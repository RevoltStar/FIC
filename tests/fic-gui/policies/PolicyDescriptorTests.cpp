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
        {"text_delimiter", "\n"},
        {"violation_severity", "HARD"},
        {"default_violation_severity", "STANDARD"},
        {"violation_severity_values",
         nlohmann::json::array({"NONE", "SOFT", "STANDARD", "HARD",
                                "ISOLATE"})}
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

    auto unsetInteger = validDescriptor();
    unsetInteger["default_value"] = nullptr;
    unsetInteger["set"] = false; unsetInteger["value_valid"] = false;
    unsetInteger["value"] = ""; unsetInteger["enabled"] = false;
    assert(parseOne(unsetInteger, policies, error));
    assert(!policies.front().hasDefault && policies.front().defaultValue.empty() && !policies.front().isSet);
    assert(!validatePolicyDescriptorValue(policies.front(), "", error));
    assert(validatePolicyDescriptorValue(policies.front(), "0", error));
    unsetInteger["default_value"] = 0;
    assert(!parseOne(unsetInteger, policies, error));

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

    // Test violation_severity fields parsing.
    auto sevDescriptor = validDescriptor();
    sevDescriptor["violation_severity"] = "HARD";
    sevDescriptor["default_violation_severity"] = "STANDARD";
    sevDescriptor["violation_severity_values"] =
        nlohmann::json::array({"NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"});
    assert(parseOne(sevDescriptor, policies, error));
    assert(policies.front().violationSeverity == "HARD");
    assert(policies.front().defaultViolationSeverity == "STANDARD");
    assert(policies.front().violationSeverityValues.size() == 5);
    assert(policies.front().violationSeverityValues[0] == "NONE");
    assert(policies.front().violationSeverityValues[4] == "ISOLATE");

    // Test violation_severity_values with non-string items is rejected.
    auto badSev = validDescriptor();
    badSev["violation_severity_values"] =
        nlohmann::json::array({"NONE", 42});
    assert(!parseOne(badSev, policies, error));
    assert(error.find("non-string") != std::string::npos);

    // Test missing violation_severity is rejected.
    auto missingSev = validDescriptor();
    missingSev.erase("violation_severity");
    assert(!parseOne(missingSev, policies, error));
    assert(error.find("missing required field 'violation_severity'") != std::string::npos);

    // Test missing default_violation_severity is rejected.
    auto missingDefaultSev = validDescriptor();
    missingDefaultSev.erase("default_violation_severity");
    assert(!parseOne(missingDefaultSev, policies, error));
    assert(error.find("missing required field 'default_violation_severity'") != std::string::npos);

    // Test missing violation_severity_values is rejected.
    auto missingSevValues = validDescriptor();
    missingSevValues.erase("violation_severity_values");
    assert(!parseOne(missingSevValues, policies, error));
    assert(error.find("missing required field 'violation_severity_values'") != std::string::npos);

    // Test wrong type for violation_severity is rejected.
    auto wrongTypeSev = validDescriptor();
    wrongTypeSev["violation_severity"] = 42;
    assert(!parseOne(wrongTypeSev, policies, error));
    assert(error.find("wrong type") != std::string::npos);

    // Test wrong type for default_violation_severity is rejected.
    auto wrongTypeDefault = validDescriptor();
    wrongTypeDefault["default_violation_severity"] = 42;
    assert(!parseOne(wrongTypeDefault, policies, error));
    assert(error.find("wrong type") != std::string::npos);

    // Test wrong type for violation_severity_values is rejected.
    auto wrongTypeValues = validDescriptor();
    wrongTypeValues["violation_severity_values"] = "not an array";
    assert(!parseOne(wrongTypeValues, policies, error));
    assert(error.find("wrong type") != std::string::npos);

    // Test unknown violation_severity token is rejected.
    auto unknownSev = validDescriptor();
    unknownSev["violation_severity"] = "BOGUS";
    assert(!parseOne(unknownSev, policies, error));
    assert(error.find("unknown violation_severity") != std::string::npos);

    // Test unknown default_violation_severity token is rejected.
    // Test empty violation_severity_values list is rejected.
    auto emptyValues = validDescriptor();
    emptyValues["violation_severity_values"] = nlohmann::json::array();
    assert(!parseOne(emptyValues, policies, error));
    assert(error.find("empty violation_severity_values list") != std::string::npos);

    // Test duplicate entry in violation_severity_values is rejected.
    auto dupValues = validDescriptor();
    dupValues["violation_severity_values"] =
        nlohmann::json::array({"NONE", "SOFT", "SOFT", "STANDARD", "HARD", "ISOLATE"});
    assert(!parseOne(dupValues, policies, error));
    assert(error.find("has duplicate violation_severity_values entry") != std::string::npos);

    // Test correct descriptor with NONE is accepted.
    auto noneDescriptor = validDescriptor();
    noneDescriptor["violation_severity"] = "NONE";
    noneDescriptor["default_violation_severity"] = "NONE";
    noneDescriptor["violation_severity_values"] =
        nlohmann::json::array({"NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"});
    assert(parseOne(noneDescriptor, policies, error));
    assert(policies.front().violationSeverity == "NONE");
    assert(policies.front().defaultViolationSeverity == "NONE");

    // Test correct descriptor with ISOLATE is accepted.
    auto isolateDescriptor = validDescriptor();
    isolateDescriptor["violation_severity"] = "ISOLATE";
    isolateDescriptor["default_violation_severity"] = "ISOLATE";
    isolateDescriptor["violation_severity_values"] =
        nlohmann::json::array({"NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"});
    assert(parseOne(isolateDescriptor, policies, error));
    assert(policies.front().violationSeverity == "ISOLATE");
    assert(policies.front().defaultViolationSeverity == "ISOLATE");

    // Regression: two descriptors, second has unknown severity.
    // Parser must reject the whole list and leave policies empty.
    policies.clear();
    error.clear();
    auto badSevDescriptor = validDescriptor();
    badSevDescriptor["violation_severity"] = "BOGUS";
    nlohmann::json twoDescriptorList = {
        {"ok", true},
        {"message", "policies listed"},
        {"policies", nlohmann::json::array({validDescriptor(), badSevDescriptor})}};
    assert(!parsePolicyDescriptors(twoDescriptorList, "DAC", policies, error));
    assert(policies.empty());
    assert(error.find("unknown violation_severity") != std::string::npos);

    return 0;
}
