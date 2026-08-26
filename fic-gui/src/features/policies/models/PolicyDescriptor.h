#ifndef POLICY_DESCRIPTOR_H
#define POLICY_DESCRIPTOR_H

#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

struct PolicyDescriptor {
    std::string moduleName;
    std::string submoduleName;
    std::string policyName;
    std::string editor;
    std::string validator;
    std::string value;
    std::string defaultValue;
    std::string textDelimiter;
    std::string restriction;
    std::vector<std::string> possibleValues;
    bool enabled = false;
    bool isSet = false;
    bool valueValid = true;
    int min = 0;
    int max = 0;
};

bool parsePolicyDescriptors(
    const nlohmann::json& response,
    const std::string& expectedModule,
    std::vector<PolicyDescriptor>& policies,
    std::string& error);

bool validatePolicyDescriptorValue(
    const PolicyDescriptor& policy,
    const std::string& value,
    std::string& error);

#endif // POLICY_DESCRIPTOR_H
