#pragma once
#include "service/VerifiedConfigMountSupport.h"
#include <chrono>
#ifdef FIC_ACTIVATOR_TESTING
#include <functional>
#endif
namespace fic::service::detail {
enum class ActivationProfile { ActiveNotifyService, UbuntuSshSocket };
// Typed, canonical launch-only values; no mutable Exec* runtime status fields.
using LaunchContract = std::map<std::string, std::string>;
LaunchContract readLaunchContract(const std::string& unit,
                                 std::chrono::steady_clock::time_point deadline);
LaunchContract readSshSocketContract(std::chrono::steady_clock::time_point deadline);
// Internal descriptor-rooted unit-source reader; production always supplies pinned /.
// Alternate roots exercise the same trust checks in isolated native fixtures.
std::string fingerprintUnitSource(int root, const std::string& name, std::uint64_t& budget
#ifdef FIC_ACTIVATOR_TESTING
                                 , const std::function<void()>& captured = {}
#endif
                                 );
// No context means no permission to consume external environment files.
// Coverage is structural; activator must verify every target before mounting.
std::set<std::string> validateEnvironmentFiles(
    const LaunchContract& contract, const std::vector<ControlledPath>* targets = nullptr);
void validateLaunchContract(const LaunchContract& contract,
                            const std::vector<ControlledPath>* targets = nullptr,
                            ActivationProfile profile = ActivationProfile::ActiveNotifyService);
} // namespace fic::service::detail
