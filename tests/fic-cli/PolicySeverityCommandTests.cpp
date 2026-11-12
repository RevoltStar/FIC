#include "PolicySetCommand.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<char*> makeArgv(const std::vector<std::string>& values)
{
    std::vector<char*> result;
    result.reserve(values.size());
    for (const std::string& value : values) {
        result.push_back(const_cast<char*>(value.data()));
    }
    return result;
}

void testSeveritySetSuccess(const std::vector<std::string>& values,
                            const std::string& expectedSeverity)
{
    std::vector<char*> argv = makeArgv(values);
    nlohmann::json request;
    std::string error;
    require(
        fic::cli::makePolicySeveritySetRequest(
            static_cast<int>(argv.size()), argv.data(), request, error),
        "makePolicySeveritySetRequest failed: " + error);
    require(request.value("command", "") == "set_policy_violation_severity",
            "wrong command");
    require(request.value("module", "") == values[4], "wrong module");
    require(request.value("policy", "") == values[5], "wrong policy");
    require(request.value("violation_severity", "") == expectedSeverity,
            "wrong severity");
}

} // namespace

int main()
{
    // All five severity values, uppercase.
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout", "NONE"},
        "NONE");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout", "SOFT"},
        "SOFT");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
         "STANDARD"},
        "STANDARD");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout", "HARD"},
        "HARD");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
         "ISOLATE"},
        "ISOLATE");

    // Case variations (lowercase is accepted by the CLI).
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout", "none"},
        "NONE");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout", "soft"},
        "SOFT");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
         "standard"},
        "STANDARD");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout", "hard"},
        "HARD");
    testSeveritySetSuccess(
        {"fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
         "isolate"},
        "ISOLATE");

    // Unknown severity token is rejected.
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
            "BOGUS"};
        std::vector<char*> argv = makeArgv(values);
        nlohmann::json request;
        std::string error;
        require(
            !fic::cli::makePolicySeveritySetRequest(
                static_cast<int>(argv.size()), argv.data(), request, error),
            "should reject unknown severity");
        require(error.find("unknown") != std::string::npos,
                "error should mention unknown severity");
    }

    // Missing severity argument (argc == 6).
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout"};
        std::vector<char*> argv = makeArgv(values);
        nlohmann::json request;
        std::string error;
        require(
            !fic::cli::makePolicySeveritySetRequest(
                static_cast<int>(argv.size()), argv.data(), request, error),
            "should reject missing severity argument");
    }

    // Empty module.
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "", "sudo_timeout", "HARD"};
        std::vector<char*> argv = makeArgv(values);
        nlohmann::json request;
        std::string error;
        require(
            !fic::cli::makePolicySeveritySetRequest(
                static_cast<int>(argv.size()), argv.data(), request, error),
            "should reject empty module");
    }

    // Empty policy.
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC", "", "HARD"};
        std::vector<char*> argv = makeArgv(values);
        nlohmann::json request;
        std::string error;
        require(
            !fic::cli::makePolicySeveritySetRequest(
                static_cast<int>(argv.size()), argv.data(), request, error),
            "should reject empty policy");
    }

    // Empty severity.
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout", ""};
        std::vector<char*> argv = makeArgv(values);
        nlohmann::json request;
        std::string error;
        require(
            !fic::cli::makePolicySeveritySetRequest(
                static_cast<int>(argv.size()), argv.data(), request, error),
            "should reject empty severity");
    }

    std::cout << "All cli_policy_severity_tests passed" << std::endl;
    return 0;
}
