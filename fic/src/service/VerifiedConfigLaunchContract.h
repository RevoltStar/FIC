#pragma once
#include "service/VerifiedConfigMountSupport.h"
#include <chrono>
namespace fic::service::detail {
// Typed, canonical launch-only values; no mutable Exec* runtime status fields.
using LaunchContract = std::map<std::string, std::string>;
LaunchContract readLaunchContract(const std::string& unit,
                                 std::chrono::steady_clock::time_point deadline);
void validateLaunchContract(const LaunchContract& contract);
} // namespace fic::service::detail
