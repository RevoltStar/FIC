#include "PolicySetCommand.h"

#include <nlohmann/json.hpp>

#include <string>

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

bool makePolicySeveritySetRequest(int argc,
                                  char* argv[],
                                  nlohmann::json& request,
                                  std::string& error)
{
    if (argc <= 6) {
        error = "policy severity set requires module, policy, and severity";
        return false;
    }

    const std::string module = argv[4];
    const std::string policy = argv[5];
    const std::string severity = argv[6];
    if (module.empty() || policy.empty() || severity.empty()) {
        error = "policy severity set module, policy, and severity are required";
        return false;
    }

    std::string token;
    if (severity == "NONE" || severity == "none") {
        token = "NONE";
    } else if (severity == "SOFT" || severity == "soft") {
        token = "SOFT";
    } else if (severity == "STANDARD" || severity == "standard") {
        token = "STANDARD";
    } else if (severity == "HARD" || severity == "hard") {
        token = "HARD";
    } else if (severity == "ISOLATE" || severity == "isolate") {
        token = "ISOLATE";
    } else {
        error = "unknown violation severity: " + severity;
        return false;
    }

    request = {
        {"command", "set_policy_violation_severity"},
        {"module", module},
        {"policy", policy},
        {"violation_severity", token}
    };
    error.clear();
    return true;
}

} // namespace fic::cli
