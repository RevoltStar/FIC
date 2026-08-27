#include "PolicySetCommand.h"

#include <nlohmann/json.hpp>

namespace fic::cli {

bool makePolicySetRequest(int argc,
                          char* argv[],
                          nlohmann::json& request,
                          std::string& error)
{
    if (argc <= 5) {
        error = "policy set value argument is required";
        return false;
    }

    const std::string module = argv[3];
    const std::string policy = argv[4];
    if (module.empty() || policy.empty()) {
        error = "policy set module and policy are required";
        return false;
    }

    request = {
        {"command", "set_policy_value"},
        {"module", module},
        {"policy", policy},
        {"value", std::string(argv[5])}
    };
    error.clear();
    return true;
}

} // namespace fic::cli
