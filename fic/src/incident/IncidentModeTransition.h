#pragma once

#include <string>
#include <utility>

namespace fic::incident {

inline bool managedModeMutationMayActivate(
    const std::string& command, const std::string& module,
    const std::string& policy, const std::string& requestedValue,
    bool currentlyEnabled, const std::string& currentValue) {
    if (module != "GLOBAL" || policy != "incident_response_mode") return false;
    if (command == "set_policy_value")
        return currentlyEnabled && requestedValue == "ACTIVE";
    if (command == "enable_policy") return currentValue == "ACTIVE";
    return false;
}

// The mutation callback is unreachable until the SSH preflight succeeds.
// The caller owns compensation when the mutation itself fails.
template <typename Result, typename Block, typename Mutation, typename Failure>
Result runGuardedModeMutation(bool enteringActive, Block&& block,
                              Mutation&& mutate, Failure&& onBlockFailure) {
    std::string error;
    if (enteringActive && !std::forward<Block>(block)(error))
        return std::forward<Failure>(onBlockFailure)(error);
    return std::forward<Mutation>(mutate)();
}

} // namespace fic::incident
