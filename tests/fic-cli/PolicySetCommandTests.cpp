#include "PolicySetCommand.h"

#include <nlohmann/json.hpp>

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

std::vector<char*> arguments(std::vector<std::string>& values)
{
    std::vector<char*> result;
    result.reserve(values.size());
    for (std::string& value : values) {
        result.push_back(value.data());
    }
    return result;
}

void requireEmptyValueRequest(const std::string& module,
                              const std::string& policy)
{
    std::vector<std::string> values{
        "fic-cli", "policy", "set", module, policy, ""};
    std::vector<char*> argv = arguments(values);
    nlohmann::json request;
    std::string error;
    require(
        fic::cli::makePolicySetRequest(
            static_cast<int>(argv.size()), argv.data(), request, error),
        error);
    require(request == nlohmann::json{
                           {"command", "set_policy_value"},
                           {"module", module},
                           {"policy", policy},
                           {"value", ""}},
            "CLI did not preserve the explicit empty policy value");
}

} // namespace

int main()
{
    requireEmptyValueRequest("DAC", "custom_mode_and_owner");
    requireEmptyValueRequest("OSS", "grub_cmdline_linux");
    requireEmptyValueRequest(
        "IDENTITY_ACCESS", "user_default_supplementary_groups");

    std::vector<std::string> values{
        "fic-cli", "policy", "set", "DAC", "custom_mode_and_owner"};
    std::vector<char*> argv = arguments(values);
    nlohmann::json request;
    std::string error;
    require(
        !fic::cli::makePolicySetRequest(
            static_cast<int>(argv.size()), argv.data(), request, error) &&
            error.find("required") != std::string::npos,
        "CLI accepted a missing policy value argument");
    return 0;
}
