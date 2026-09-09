#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"

#include <set>
#include <tuple>
#include <utility>

bool GlobalDesktopConfigKey::operator<(
    const GlobalDesktopConfigKey& other) const
{
    return std::tie(owner, setting) < std::tie(other.owner, other.setting);
}

bool GlobalDesktopConfigKey::operator==(
    const GlobalDesktopConfigKey& other) const
{
    return owner == other.owner && setting == other.setting;
}

DesktopGlobalConfigReconciler::DesktopGlobalConfigReconciler(
    std::vector<std::shared_ptr<DesktopSystemBackend>> backends)
    : backends_(std::move(backends))
{
}

bool DesktopGlobalConfigReconciler::reconcile(
    PolicyRegistry& registry,
    std::string& error)
{
    error.clear();
    std::map<std::string, DesktopGlobalConfigState> desiredByBackend;
    std::set<std::string> registeredBackends;
    for (const auto& backend : backends_) {
        if (backend == nullptr || backend->backendName().empty() ||
            !registeredBackends.insert(backend->backendName()).second) {
            error = "invalid or duplicate desktop system backend";
            return false;
        }
        desiredByBackend[backend->backendName()] = {};
    }

    for (Policy* policy : registry.capabilityPolicies(
             PolicyCapability::GlobalDesktopConfiguration)) {
        if (!policy->isEnabled()) continue;
        auto* contributor =
            dynamic_cast<GlobalDesktopPolicyContributor*>(policy);
        if (contributor == nullptr) {
            error = "global desktop policy capability has no contributor: " +
                policy->moduleName + "/" + policy->submoduleName + "/" +
                policy->policyName;
            return false;
        }
        std::vector<GlobalDesktopPolicyContribution> contributions;
        if (!contributor->globalDesktopPolicyContributions(
                contributions, error)) {
            return false;
        }
        for (const auto& contribution : contributions) {
            const auto desired = desiredByBackend.find(contribution.backend);
            if (desired == desiredByBackend.end()) {
                error = "unknown desktop system backend: " +
                    contribution.backend;
                return false;
            }
            if (contribution.key.owner != PolicyRef{
                    policy->moduleName, policy->submoduleName,
                    policy->policyName} || contribution.key.setting.empty()) {
                error = "invalid global desktop policy contribution owner or key";
                return false;
            }
            if (!desired->second.emplace(
                    contribution.key, contribution.value).second) {
                error = "duplicate global desktop policy contribution";
                return false;
            }
        }
    }

    for (const auto& backend : backends_) {
        const DesktopGlobalConfigState& desired =
            desiredByBackend.at(backend->backendName());
        DesktopGlobalConfigState current;
        if (!backend->readManagedState(current, error)) return false;
        if (current != desired &&
            !backend->replaceManagedState(desired, error)) {
            return false;
        }
        DesktopGlobalConfigState verified;
        if (!backend->readManagedState(verified, error)) return false;
        if (verified != desired) {
            error = "desktop system backend verification failed: " +
                backend->backendName();
            return false;
        }
    }
    return true;
}
