#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

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

bool DesktopGlobalReconcileReport::successful() const
{
    if (!requirementsValid) return false;
    for (const auto& [name, result] : backends) {
        (void)name;
        if (result.attempted && !result.verified) return false;
    }
    return true;
}

bool DesktopGlobalReconcileReport::successfulForPolicy(
    const PolicyRef& policy) const
{
    if (!requirementsValid) return false;
    const auto found = policies.find(policy);
    if (found == policies.end()) return true;
    for (const auto& [desktop, result] : found->second) {
        (void)desktop;
        if (!result.verified) return false;
    }
    return true;
}

bool DesktopGlobalReconcileReport::successfulForModule(
    const std::string& module) const
{
    if (!requirementsValid) return false;
    for (const auto& [policy, results] : policies) {
        if (policy.moduleName != module) continue;
        for (const auto& [desktop, result] : results) {
            (void)desktop;
            if (!result.verified) return false;
        }
    }
    return true;
}

PolicyGlobalEnforcementResult DesktopGlobalReconcileReport::resultFor(
    const PolicyRef& policy,
    DesktopEnvironmentKind desktop) const
{
    if (!requirementsValid) {
        return {false, false, {}, stageADiagnostic};
    }
    const auto policyIt = policies.find(policy);
    if (policyIt == policies.end()) return {};
    const auto desktopIt = policyIt->second.find(desktop);
    return desktopIt == policyIt->second.end()
        ? PolicyGlobalEnforcementResult{}
        : desktopIt->second;
}

PolicyGlobalEnforcementResults DesktopGlobalReconcileReport::resultsFor(
    const PolicyRef& policy) const
{
    const auto found = policies.find(policy);
    return found == policies.end()
        ? PolicyGlobalEnforcementResults{}
        : found->second;
}

std::string DesktopGlobalReconcileReport::diagnostic() const
{
    if (!requirementsValid) return stageADiagnostic;
    std::string result;
    for (const auto& [name, backend] : backends) {
        if (!backend.attempted || backend.verified) continue;
        if (!result.empty()) result += '\n';
        result += name + ": " + backend.diagnostic;
    }
    return result;
}

namespace {
bool reconcileBackend(DesktopSystemBackend& backend,
                      const DesktopManagedSettings& required,
                      std::string& error)
{
    std::string detail;
    if (!backend.ensureManagedSettings(required, detail)) {
        error = "ensureManagedSettings failed: " + detail;
        return false;
    }
    detail.clear();
    if (!backend.verifyManagedSettings(required, detail)) {
        error = "verifyManagedSettings failed: " + detail;
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

DesktopGlobalReconcileReport DesktopGlobalConfigReconciler::reconcile(
    PolicyRegistry& registry)
{
    DesktopGlobalReconcileReport report;
    auto failStageA = [&](std::string diagnostic) {
        report.requirementsValid = false;
        report.stageADiagnostic = std::move(diagnostic);
        return report;
    };
    std::map<std::string, DesktopGlobalConfigRequirements> desiredByBackend;
    std::map<std::string, DesktopSystemBackend*> backendByName;
    std::map<DesktopEnvironmentKind, DesktopSystemBackend*> backendByDesktop;
    for (const auto& backend : backends_) {
        if (backend == nullptr || backend->backendName().empty() ||
            backend->desktop() == DesktopEnvironmentKind::Unknown ||
            !backendByName.emplace(backend->backendName(), backend.get()).second) {
            return failStageA("invalid or duplicate desktop system backend");
        }
        if (!backendByDesktop.emplace(backend->desktop(), backend.get()).second) {
            return failStageA(
                "duplicate desktop system backend for " +
                std::string(DesktopEnvironmentBackend::kindName(
                    backend->desktop())));
        }
        const std::string name = backend->backendName();
        desiredByBackend[name] = {};
        report.backends[name] = {};
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
            return failStageA(
                "global desktop policy capability/contributor mismatch: " +
                policy->moduleName + "/" + policy->submoduleName + "/" +
                policy->policyName);
        }
        std::vector<GlobalDesktopPolicyContribution> contributions;
        std::string contributionError;
        if (!contributor->globalDesktopPolicyContributions(
                contributions, contributionError)) {
            std::string diagnostic = "global desktop policy contribution failed: " +
                policy->moduleName + "/" + policy->submoduleName + "/" +
                policy->policyName;
            if (!contributionError.empty()) diagnostic += ": " + contributionError;
            return failStageA(std::move(diagnostic));
        }
        for (const auto& contribution : contributions) {
            const auto desired = desiredByBackend.find(contribution.backend);
            if (desired == desiredByBackend.end()) {
                return failStageA("unknown desktop system backend: " +
                    contribution.backend);
            }
            if (contribution.owner != PolicyRef{
                    policy->moduleName, policy->submoduleName,
                    policy->policyName} || contribution.key.setting.empty() ||
                contribution.desktop == DesktopEnvironmentKind::Unknown) {
                return failStageA(
                    "invalid global desktop policy contribution owner, desktop, or key");
            }
            DesktopSystemBackend* backend =
                backendByName.at(contribution.backend);
            if (backend->desktop() != contribution.desktop) {
                return failStageA(
                    "global desktop contribution/backend desktop mismatch: " +
                    contribution.backend + " does not serve " +
                    std::string(DesktopEnvironmentBackend::kindName(
                        contribution.desktop)));
            }
            auto* sessionAware = dynamic_cast<SessionAwarePolicy*>(policy);
            std::string applicabilityError;
            if (sessionAware == nullptr ||
                sessionAware->sessionApplicability(
                    contribution.desktop, applicabilityError) !=
                    SessionApplicability::Applicable ||
                sessionAware->enforcementMode(contribution.desktop) !=
                    EnforcementMode::MandatoryGlobal) {
                return failStageA(
                    "global desktop contribution has no MandatoryGlobal policy coverage: " +
                    policy->moduleName + "/" + policy->submoduleName + "/" +
                    policy->policyName);
            }
            const auto [entry, inserted] = desired->second.emplace(
                contribution.key,
                GlobalDesktopConfigValue{contribution.value, {contribution.owner}});
            if (!inserted && entry->second.value != contribution.value) {
                return failStageA("conflicting global desktop setting: " +
                    contribution.backend + "/" + contribution.key.setting);
            }
            entry->second.owners.insert(contribution.owner);
            auto& policyResult =
                report.policies[contribution.owner][contribution.desktop];
            policyResult.hasRequirement = true;
            policyResult.backends.insert(contribution.backend);
        }
    }

    constexpr DesktopEnvironmentKind desktops[] = {
        DesktopEnvironmentKind::Gnome,
        DesktopEnvironmentKind::Kde,
        DesktopEnvironmentKind::Xfce,
        DesktopEnvironmentKind::Fly,
        DesktopEnvironmentKind::Lxqt
    };
    for (Policy* policy : registry.capabilityPolicies(
             PolicyCapability::SessionAware)) {
        if (!policy->isEnabled()) continue;
        auto* sessionAware = dynamic_cast<SessionAwarePolicy*>(policy);
        if (sessionAware == nullptr) continue;
        const PolicyRef owner{
            policy->moduleName, policy->submoduleName, policy->policyName};
        for (const DesktopEnvironmentKind desktop : desktops) {
            std::string applicabilityError;
            if (sessionAware->sessionApplicability(desktop, applicabilityError) !=
                    SessionApplicability::Applicable ||
                sessionAware->enforcementMode(desktop) !=
                    EnforcementMode::MandatoryGlobal) {
                continue;
            }
            if (!report.resultFor(owner, desktop).hasRequirement) {
                return failStageA(
                    "MandatoryGlobal policy has no global requirement coverage: " +
                    owner.moduleName + "/" + owner.submoduleName + "/" +
                    owner.policyName);
            }
        }
    }

    // Stage B: independently ensure every backend with active requirements.
    for (const auto& backend : backends_) {
        const std::string name = backend->backendName();
        const auto& desired = desiredByBackend.at(name);
        if (desired.empty()) continue;
        auto& backendResult = report.backends.at(name);
        backendResult.attempted = true;
        DesktopManagedSettings required;
        for (const auto& [key, value] : desired) {
            required.emplace(key, value.value);
        }
        backendResult.verified =
            reconcileBackend(*backend, required, backendResult.diagnostic);
    }
    for (auto& [owner, desktopsForPolicy] : report.policies) {
        (void)owner;
        for (auto& [desktop, policyResult] : desktopsForPolicy) {
            (void)desktop;
            policyResult.verified = true;
            for (const std::string& backend : policyResult.backends) {
                const auto& backendResult = report.backends.at(backend);
                if (!backendResult.verified) {
                    policyResult.verified = false;
                    if (!policyResult.diagnostic.empty()) {
                        policyResult.diagnostic += '\n';
                    }
                    policyResult.diagnostic +=
                        backend + ": " + backendResult.diagnostic;
                }
            }
        }
    }
    return report;
}
