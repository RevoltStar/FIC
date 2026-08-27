#ifndef POLICY_REGISTRY_MUTATION_H
#define POLICY_REGISTRY_MUTATION_H

#include "policy/registry/PolicyRegistry.h"

#include <string>

bool setPolicyValue(PolicyRegistry& registry,
                    const std::string& module,
                    const std::string& policy,
                    const std::string& logicalValue,
                    std::string& error);

#endif // POLICY_REGISTRY_MUTATION_H
