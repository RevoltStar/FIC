#ifndef FIC_DAEMON_POLICY_MUTATION_RESULT_H
#define FIC_DAEMON_POLICY_MUTATION_RESULT_H

#include <string>
#include <utility>
#include <optional>

#include <fic/ipc/FicIpcClient.h>

namespace fic::daemon {

struct PolicyMutationResult {
    bool ok = false;
    std::string detail;
    std::optional<bool> saved, applied;

    static PolicyMutationResult success() { return {true, {}}; }
    static PolicyMutationResult failure(std::string detail) {
        return {false, std::move(detail)};
    }
};

inline nlohmann::json policyMutationResponse(
    const PolicyMutationResult& result,
    const std::string& successMessage,
    const std::string& failureMessage) {
    auto response=result.ok?fic::ipc::make_ok_response(successMessage):fic::ipc::make_error_response(
        result.detail.empty()
            ? failureMessage
            : failureMessage + ": " + result.detail);
    if(result.saved)response["saved"]=*result.saved;
    if(result.applied)response["applied"]=*result.applied;
    return response;
}

} // namespace fic::daemon

#endif // FIC_DAEMON_POLICY_MUTATION_RESULT_H
