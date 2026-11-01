#include "daemon/PolicyMutationResult.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

int main() {
    const auto success = fic::daemon::policyMutationResponse(
        fic::daemon::PolicyMutationResult::success(),
        "policy disabled",
        "failed to disable example");
    assert(success.at("ok").get<bool>());
    assert(success.at("message") == "policy disabled");
    assert(success.at("api_version") == fic::ipc::API_VERSION);

    const auto failure = fic::daemon::policyMutationResponse(
        fic::daemon::PolicyMutationResult::failure(
            "unexpected group for configuration directory: /etc/sssd/conf.d"),
        "policy disabled",
        "failed to disable sssd_offline_credentials_expiration");
    assert(!failure.at("ok").get<bool>());
    assert(failure.at("api_version") == fic::ipc::API_VERSION);
    assert(failure.at("message").get<std::string>().find(
               "sssd_offline_credentials_expiration") != std::string::npos);
    assert(failure.at("message").get<std::string>().find(
               "unexpected group for configuration directory") !=
           std::string::npos);
    assert(!failure.contains("saved")&&!failure.contains("applied"));
    auto partial=fic::daemon::PolicyMutationResult::failure("SSSD acknowledgement pending");
    partial.saved=true;partial.applied=false;
    const auto pending=fic::daemon::policyMutationResponse(partial,"disabled","disable failed");
    assert(!pending.at("ok").get<bool>()&&pending.at("saved").get<bool>()&&!pending.at("applied").get<bool>());
    partial.saved.reset();
    const auto uncertain=fic::daemon::policyMutationResponse(partial,"disabled","save durability unknown");
    assert(!uncertain.contains("saved")&&!uncertain.at("applied").get<bool>());
    return 0;
}
