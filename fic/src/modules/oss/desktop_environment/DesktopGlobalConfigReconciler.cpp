#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"

#include <set>
#include <utility>

bool GlobalDesktopConfigKey::operator<(
    const GlobalDesktopConfigKey& other) const
{
    return setting < other.setting;
}

bool GlobalDesktopConfigKey::operator==(
    const GlobalDesktopConfigKey& other) const
{
    return setting == other.setting;
}

bool GlobalDesktopConfigValue::operator==(
    const GlobalDesktopConfigValue& other) const
{
    return value == other.value && owners == other.owners;
}

namespace {
bool reconcileBackend(DesktopSystemBackend& backend,
                      const DesktopGlobalConfigState& desired,
                      std::string& error)
{
    DesktopGlobalConfigState current;
    std::string detail;
    if (!backend.readManagedState(current, detail)) {
        error = "readManagedState failed: " + detail;
        return false;
    }
    detail.clear();
    if (current != desired && !backend.replaceManagedState(desired, detail)) {
        error = "replaceManagedState failed: " + detail;
        return false;
    }
    DesktopGlobalConfigState verified;
    detail.clear();
    if (!backend.readManagedState(verified, detail)) {
        error = "verification readManagedState failed: " + detail;
        return false;
    }
    if (verified != desired) {
        error = "verification failed: managed state differs from desired";
        return false;
    }
    return true;
}
} // namespace

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

    // Stage A: validate the complete desired state before touching any backend.
    const auto& capable = registry.capabilityPolicies(
        PolicyCapability::GlobalDesktopConfiguration);
    const std::set<Policy*> capablePolicies(capable.begin(), capable.end());
    for (const auto& ref : registry.policyRefs()) {
        Policy* policy = registry.findPolicy(ref);
        auto* contributor = dynamic_cast<GlobalDesktopPolicyContributor*>(policy);
        const bool hasCapability = capablePolicies.count(policy) != 0;
        if (!hasCapability && contributor == nullptr) continue;
        if (!policy->isEnabled()) continue;
        if (hasCapability != (contributor != nullptr)) {
            error = "global desktop policy capability/contributor mismatch: " +
                policy->moduleName + "/" + policy->submoduleName + "/" +
                policy->policyName;
            return false;
        }
        std::vector<GlobalDesktopPolicyContribution> contributions;
        std::string contributionError;
        if (!contributor->globalDesktopPolicyContributions(
                contributions, contributionError)) {
            error = "global desktop policy contribution failed: " +
                policy->moduleName + "/" + policy->submoduleName + "/" +
                policy->policyName;
            if (!contributionError.empty()) error += ": " + contributionError;
            return false;
        }
        for (const auto& contribution : contributions) {
            const auto desired = desiredByBackend.find(contribution.backend);
            if (desired == desiredByBackend.end()) {
                error = "unknown desktop system backend: " +
                    contribution.backend;
                return false;
            }
            if (contribution.owner != PolicyRef{
                    policy->moduleName, policy->submoduleName,
                    policy->policyName} || contribution.key.setting.empty()) {
                error = "invalid global desktop policy contribution owner or key";
                return false;
            }
            const auto [entry, inserted] = desired->second.emplace(
                contribution.key,
                GlobalDesktopConfigValue{contribution.value, {contribution.owner}});
            if (!inserted && entry->second.value != contribution.value) {
                error = "conflicting global desktop setting: " +
                    contribution.backend + "/" + contribution.key.setting;
                return false;
            }
            entry->second.owners.insert(contribution.owner);
        }
    }

    // Stage B: independent backends must all get their cleanup/enforcement pass.
    bool overallSuccess = true;
    for (const auto& backend : backends_) {
        const std::string name = backend->backendName();
        std::string backendError;
        if (!reconcileBackend(*backend, desiredByBackend.at(name), backendError)) {
            if (!error.empty()) error += '\n';
            error += name + ": " + backendError;
            overallSuccess = false;
        }
    }
    return overallSuccess;
}
