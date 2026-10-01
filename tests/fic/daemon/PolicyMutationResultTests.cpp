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
    return 0;
}
