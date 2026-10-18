#pragma once
#include "service/VerifiedConfigMountSupport.h"
#include <chrono>
namespace fic::service::detail {
// Typed, canonical launch-only values; no mutable Exec* runtime status fields.
using LaunchContract = std::map<std::string, std::string>;
LaunchContract readLaunchContract(const std::string& unit,
                                 std::chrono::steady_clock::time_point deadline);
// No context means no permission to consume external environment files.
// Coverage is structural; activator must verify every target before mounting.
std::set<std::string> validateEnvironmentFiles(
    const LaunchContract& contract, const std::vector<ControlledPath>* targets = nullptr);
void validateLaunchContract(const LaunchContract& contract,
                            const std::vector<ControlledPath>* targets = nullptr);
} // namespace fic::service::detail
