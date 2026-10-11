#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include <fic/policy/PolicyDependencyConditionEvaluator.h>
#include "rollback/DaemonMutationJournal.h"
#include "rollback/ScopeTransition.h"
#include <algorithm>

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

DesktopGlobalConfigReconciler::DesktopGlobalConfigReconciler(
    std::vector<std::shared_ptr<DesktopSystemBackend>> backends,
    fic::rollback::MutationJournal* journal)
    : backends_(std::move(backends)), journal_(journal)
{
}

DesktopGlobalReconcileReport DesktopGlobalConfigReconciler::reconcile(
    PolicyRegistry& registry)
{
    DesktopGlobalReconcileReport report;
    fic::rollback::MutationJournal* journal = nullptr;
    std::vector<std::string> target;
    bool executingTransition = false;
    auto failStageA = [&](std::string diagnostic) {
        if (journal && journal->usable() && !executingTransition) {
            std::string checkpointError;
            const auto fail = [&](std::string& error) { error = diagnostic; return false; };
            const auto unused = [](std::string&) { return true; };
            (void)fic::rollback::ScopeTransition(*journal).reconcile(target, fail, unused, unused, unused, checkpointError);
            if (checkpointError != diagnostic && !checkpointError.empty()) diagnostic += "; " + checkpointError;
        }
        report.requirementsValid = false;
        report.stageADiagnostic = std::move(diagnostic);
        return report;
    };
    const PolicyRef scopeRef{"OSS", "DesktopEnvironment", "controlled_desktop_environments"};
    Policy* scopePolicy = registry.findPolicy(scopeRef);
    auto* scope = dynamic_cast<ControlledDesktopEnvironmentScope*>(scopePolicy);
    DesktopEnvironmentSet configured;
    std::string scopeError;
    if (!scopePolicy || !scopePolicy->isEnabled()) {
        // A disabled scope never authorizes enforcement or release. With no
        // enabled consumer it is an inert configuration, not a transition.
        for (const auto& ref : registry.policyRefs()) {
            Policy* policy = registry.findPolicy(ref);
            if (!policy->isEnabled()) continue;
            for (const auto& dependency : policy->dependencies())
                if (dependency.policy == scopeRef && dependency.strength == PolicyDependencyStrength::Required)
                    return failStageA("Required dependency is disabled: " + formatPolicyRef(scopeRef));
        }
        return report;
    }
    if (!scope || !scope->controlledDesktopEnvironments(configured, scopeError))
        return failStageA("Invalid configured DE scope: " + scopeError);
    journal = journal_ ? journal_ : fic::rollback::DaemonMutationJournal::instance().tryGet(scopeError);
    if (!journal) return failStageA("DE scope journal unavailable: " + scopeError);
    for (const auto desktop : configured) target.emplace_back(DesktopEnvironmentBackend::kindName(desktop));
    std::sort(target.begin(), target.end());
    std::map<std::string, AtomicTargetState> configurationVersions;
    const auto rememberIntent = [&](Policy& policy) {
        std::string path;
        AtomicTargetState version;
        if (!policy.captureConfigurationVersion(path, version, scopeError)) return false;
        const auto [entry, inserted] = configurationVersions.emplace(path, version);
        return inserted || AtomicFileWriter::targetStateMatches(path, entry->second, &scopeError);
    };
    if (!rememberIntent(*scopePolicy)) return failStageA(scopeError);
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
        if (!rememberIntent(*policy)) return failStageA(scopeError);
        // This entrypoint runs before the planner: it must prove Required
        // dependencies before invoking a contributor or touching a backend.
        for (const auto& dependency : policy->dependencies()) {
            if (dependency.strength != PolicyDependencyStrength::Required)
                continue;
            if (!dependencyConditionMatches(*policy, dependency.condition))
                continue;
            Policy* prerequisite = registry.findPolicy(dependency.policy);
            std::string prerequisiteError;
            if (prerequisite == nullptr || !prerequisite->isEnabled() ||
                (dependency.policy != scopeRef) ||
                dynamic_cast<ControlledDesktopEnvironmentScope*>(prerequisite) == nullptr) {
                return failStageA("Required dependency was not applied: " +
                    formatPolicyRef(dependency.policy) +
                    (prerequisiteError.empty() ? "" : "; " + prerequisiteError));
            }
        }
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
            const auto applicable = sessionAware->sessionApplicability(desktop, applicabilityError);
            if (!applicabilityError.empty()) return failStageA(applicabilityError);
            if (!configured.count(desktop) || applicable == SessionApplicability::NotApplicable) {
                continue;
            }
            // Session-only setters currently have no native conditional
            // mutation contract. Refuse BEFORE releasing any global state.
            // They cannot grant a successful scope checkpoint, even when an
            // agent is temporarily absent or a setting happens to match.
            if (applicable == SessionApplicability::Unsupported ||
                sessionAware->enforcementMode(desktop) != EnforcementMode::MandatoryGlobal) {
                return failStageA("DE transition cannot prove ownership-safe session enforcement: " +
                    formatPolicyRef(owner) + "/" + DesktopEnvironmentBackend::kindName(desktop));
            }
            if (!report.resultFor(owner, desktop).hasRequirement) {
                return failStageA(
                    "MandatoryGlobal policy has no global requirement coverage: " +
                    owner.moduleName + "/" + owner.submoduleName + "/" +
                    owner.policyName);
            }
        }
    }

    // Only this coordinator authorizes a pending target; ordinary policy and
    // session entrypoints still require a committed checkpoint. Complete all
    // preflights before any protected resource changes, preserving owners.
    const auto preflight = [&](std::string& error) {
        for (const auto& backend : backends_) {
            auto& result = report.backends.at(backend->backendName());
            if (!desiredByBackend.at(backend->backendName()).empty() &&
                !backend->verifiedEnforcementAvailable(result.diagnostic)) {
                error = backend->backendName() + ": " + result.diagnostic; return false;
            }
            if (!backend->preflightJournaled(desiredByBackend.at(backend->backendName()), *journal, result.diagnostic)) {
                error = backend->backendName() + ": " + result.diagnostic; return false;
            }
        }
        return true;
    };
    const auto reconcile = [&](bool nonempty, std::string& error) {
        for (const auto& backend : backends_) {
            const auto& desired = desiredByBackend.at(backend->backendName());
            if (desired.empty() == nonempty) continue;
            auto& result = report.backends.at(backend->backendName());
            result.attempted = true;
            if (!backend->reconcileJournaled(desired, *journal, result.diagnostic)) {
                error = backend->backendName() + ": " + result.diagnostic; return false;
            }
        }
        return true;
    };
    const auto verify = [&](std::string& error) {
        for (const auto& [path, version] : configurationVersions)
            if (!AtomicFileWriter::targetStateMatches(path, version, &error)) {
                error = "configured DE intent changed during transition: " + error; return false;
            }
        DesktopEnvironmentSet current;
        if (!scopePolicy->isEnabled() || !scope->controlledDesktopEnvironments(current, error) || current != configured) {
            error = "configured DE scope changed during transition"; return false;
        }
        for (const auto& backend : backends_) {
            auto& result = report.backends.at(backend->backendName());
            const auto& desired = desiredByBackend.at(backend->backendName());
            DesktopManagedSettings values;
            for (const auto& [key, value] : desired) values.emplace(key, value.value);
            if (!backend->preflightJournaled(desired, *journal, result.diagnostic) ||
                !backend->verifyManagedSettings(values, result.diagnostic)) {
                error = backend->backendName() + ": " + result.diagnostic; return false;
            }
            result.verified = true;
        }
        return true;
    };
    executingTransition = true;
    if (!fic::rollback::ScopeTransition(*journal).reconcile(target, preflight,
        [&](std::string& error) { return reconcile(true, error); },
        [&](std::string& error) { return reconcile(false, error); }, verify, scopeError))
        return failStageA("DE scope transition failed: " + scopeError);
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

bool DesktopGlobalConfigReconciler::releasePolicy(const PolicyRef& owner,
    fic::rollback::MutationJournal& journal, std::string& error, bool preview) {
    for (const auto& backend : backends_)
        if (!backend || !backend->releaseOwnerJournaled(owner, journal, error, true)) return false;
    if (preview) return true;
    if (!fic::rollback::ScopeTransition(journal).invalidate("DE policy owner release requires scope re-verification", error)) return false;
    for (const auto& backend : backends_)
        if (!backend->releaseOwnerJournaled(owner, journal, error)) return false;
    return true;
}

bool DesktopGlobalConfigReconciler::releaseAll(fic::rollback::MutationJournal& journal,
    std::string& error, bool preview) {
    for (const auto& backend : backends_)
        if (!backend || !backend->preflightJournaled({}, journal, error)) return false;
    if (preview) return true;
    if (!fic::rollback::ScopeTransition(journal).invalidate("DE package ownership release", error)) return false;
    for (const auto& backend : backends_)
        if (!backend->reconcileJournaled({}, journal, error)) return false;
    for (const auto& backend : backends_)
        if (!backend->preflightJournaled({}, journal, error)) return false;
    return true;
}
