#ifndef FIC_POLICY_DEPENDENCY_GRAPH_H
#define FIC_POLICY_DEPENDENCY_GRAPH_H

#include "core/PolicyRegistry.h"

#include <string>

bool validatePolicyDependencyGraph(
    PolicyRegistry& registry,
    std::string& error);

#endif // FIC_POLICY_DEPENDENCY_GRAPH_H
