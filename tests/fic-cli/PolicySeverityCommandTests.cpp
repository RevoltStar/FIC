#include "PolicySetCommand.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<char*> arguments(std::vector<std::string>& values) {
    std::vector<char*> result;
    result.reserve(values.size());
    for (std::string& value : values) {
        result.push_back(value.data());
    }
    return result;
}

} // namespace

int main() {
    // Test valid severity tokens produce correct IPC requests.
    for (const auto& [input, expected] : {
             std::make_pair(std::string("NONE"), std::string("NONE")),
             std::make_pair(std::string("none"), std::string("NONE")),
             std::make_pair(std::string("SOFT"), std::string("SOFT")),
             std::make_pair(std::string("soft"), std::string("SOFT")),
             std::make_pair(std::string("STANDARD"), std::string("STANDARD")),
             std::make_pair(std::string("standard"), std::string("STANDARD")),
             std::make_pair(std::string("HARD"), std::string("HARD")),
             std::make_pair(std::string("hard"), std::string("HARD")),
             std::make_pair(std::string("ISOLATE"), std::string("ISOLATE")),
             std::make_pair(std::string("isolate"), std::string("ISOLATE"))}) {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
            input};
        std::vector<char*> argv = arguments(values);
        nlohmann::json request;
        std::string error;
        require(fic::cli::makePolicySeveritySetRequest(
                    static_cast<int>(argv.size()), argv.data(), request, error),
                "makePolicySeveritySetRequest(" + input + ") failed: " + error);
        require(request["command"] == "set_policy_violation_severity",
                "wrong command");
        require(request["module"] == "DAC", "wrong module");
        require(request["policy"] == "sudo_timeout", "wrong policy");
        require(request["violation_severity"] == expected,
                "wrong severity token for " + input);
        require(error.empty(), "error should be empty on success");
    }

    // Test unknown severity token is rejected.
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
            "BOGUS"};
        std::vector<char*> argv = arguments(values);
        nlohmann::json request;
        std::string error;
        require(!fic::cli::makePolicySeveritySetRequest(
                    static_cast<int>(argv.size()), argv.data(), request, error),
                "unknown severity should be rejected");
        require(!error.empty(), "error should be set for unknown severity");
    }

    // Test missing arguments.
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC"};
        std::vector<char*> argv = arguments(values);
        nlohmann::json request;
        std::string error;
        require(!fic::cli::makePolicySeveritySetRequest(
                    static_cast<int>(argv.size()), argv.data(), request, error),
                "missing severity should be rejected");
        require(!error.empty(), "error should be set for missing severity");
    }

    // Test missing module.
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "", "sudo_timeout", "HARD"};
        std::vector<char*> argv = arguments(values);
        nlohmann::json request;
        std::string error;
        require(!fic::cli::makePolicySeveritySetRequest(
                    static_cast<int>(argv.size()), argv.data(), request, error),
                "empty module should be rejected");
    }

    std::cout << "All PolicySeverityCommandTests passed" << std::endl;
    return 0;
}