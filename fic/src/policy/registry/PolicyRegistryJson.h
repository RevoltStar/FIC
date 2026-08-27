#ifndef POLICY_REGISTRY_JSON_H
#define POLICY_REGISTRY_JSON_H

#include <nlohmann/json_fwd.hpp>

#include "policy/registry/PolicyRegistry.h"

nlohmann::json moduleDescriptorsJson(const PolicyRegistry& registry);
nlohmann::json policyToJson(const std::string& module,
                            const std::string& submodule,
                            const std::string& policy,
                            Policy& policyClass);
nlohmann::json policyListJson(const PolicyRegistry& registry,
                              const std::string& module);

#endif // POLICY_REGISTRY_JSON_H
