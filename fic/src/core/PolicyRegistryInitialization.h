#ifndef POLICY_REGISTRY_INITIALIZATION_H
#define POLICY_REGISTRY_INITIALIZATION_H

#include <memory>
#include <string>
#include <vector>

#include "core/PolicyRegistry.h"

bool buildPolicyRegistry(
    std::vector<std::unique_ptr<Policy>> policies,
    PolicyRegistry& registry,
    std::string& error);

#endif // POLICY_REGISTRY_INITIALIZATION_H
