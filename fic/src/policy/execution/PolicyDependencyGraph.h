#ifndef FIC_POLICY_DEPENDENCY_GRAPH_H
#define FIC_POLICY_DEPENDENCY_GRAPH_H

#include "policy/registry/PolicyRegistry.h"

#include <string>
#include <vector>

bool validatePolicyDependencyGraph(
    PolicyRegistry& registry,
    std::string& error);

// Enabled policies that declare `dependency` as a REQUIRED dependency.
//
// The planner enforces the forward direction: a dependent policy is not
// reported Applied while its required dependency is not Applied. This is the
// REVERSE direction, needed before a disable: disabling a required dependency
// of an active dependent would let the dependent keep claiming an invariant
// its dependency no longer guarantees (for example disabling the scoped-Defaults
// blocker while sudo_securepath stays enabled).
//
// Recommended dependencies do NOT block: they are advisory by definition.
// Returns the dependents in a deterministic (sorted) order.
std::vector<PolicyRef> enabledRequiredDependents(
    PolicyRegistry& registry,
    const PolicyRef& dependency);

#endif // FIC_POLICY_DEPENDENCY_GRAPH_H
