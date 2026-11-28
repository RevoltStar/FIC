#ifndef POLICY_REGISTRY_MUTATION_H
#define POLICY_REGISTRY_MUTATION_H

#include "policy/registry/PolicyRegistry.h"

#include <string>

// Production configuration-only ENABLE path; does not apply the policy.
bool enable(PolicyRegistry& registry, std::string module,
            std::string policy, std::string* error);

bool setPolicyValue(PolicyRegistry& registry,
                    const std::string& module,
                    const std::string& policy,
                    const std::string& logicalValue,
                    std::string& error);

bool setPolicyViolationSeverity(PolicyRegistry& registry,
                                const std::string& module,
                                const std::string& policy,
                                const std::string& severityToken,
                                std::string& error);

#endif // POLICY_REGISTRY_MUTATION_H
