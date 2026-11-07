// Included by the native registry driver: fixtures never apply host policies.
#include "policy/execution/PolicyExecutionPlanner.h"
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/config/ModuleConfigFileHandler.h>

PolicyRef pamRef(const std::string& name) { return {"IDENTITY_ACCESS", "PAM", name}; }
void configure(const PlatformProfile&, const std::string& enabledOption,
               bool activationEnabled) {
    ModuleConfigFileHandler conf("IDENTITY_ACCESS");
    for (const auto& option : options)
        need(conf.setPolicyStatus(option.name, option.name == enabledOption ? "ENABLE" : "DISABLE"), "option status");
    for (auto capability : {PamCapability::PasswordQuality, PamCapability::PasswordHistory,
                            PamCapability::AuthenticationLockout}) {
        const auto* name = pamCapabilityActivationPolicyName(capability);
        need(conf.setPolicyStatus(name, activationEnabled ? "ENABLE" : "DISABLE"), "activation status");
    }
    need(conf.setPolicyStatus("disable_nopasswdlogin", "ENABLE"), "recommended status");
    need(conf.saveConfig(), "save fixture configuration");
}
PolicyRegistry registryFor(const PlatformProfile& profile, const PlatformExecutableResolver& executables) {
    PolicyRegistry registry; std::string error;
    need(initPolicyRegistry(profile, executables, registry, error), error);
    need(validatePolicyDependencyGraph(registry, error), error);
    return registry;
}
void checkDependencies(const PlatformProfile& profile) {
    PlatformExecutableResolver executables(profile.executables);
    auto registry = registryFor(profile, executables);
    for (const auto& option : options) {
        const auto* policy = registry.findPolicy(pamRef(option.name));
        const bool supported = p::pamPolicySupport(profile.pam, option.feature) != PamPolicySupport::Unsupported;
        need(bool(policy) == supported, std::string("registration: ") + option.name);
        if (!policy) continue;
        const auto capability = p::pamPolicyCapability(option.feature);
        const auto activation = pamRef(pamCapabilityActivationPolicyName(capability));
        need(registry.findPolicy(activation) != nullptr, "missing activation");
        unsigned required = 0, recommended = 0;
        for (const auto& dep : policy->dependencies()) {
            if (dep.strength == PolicyDependencyStrength::Required) {
                ++required;
                need(dep.policy == activation && dep.condition.type == PolicyDependencyConditionType::Always,
                     "noncanonical/conditional Required dependency");
            } else {
                ++recommended;
                need(capability == PamCapability::AuthenticationLockout &&
                     dep.policy == pamRef("disable_nopasswdlogin"), "changed Recommended dependency");
            }
        }
        need(required == 1 && recommended == (capability == PamCapability::AuthenticationLockout && profile.pam.passwordlessLoginControl.has_value() ? 1u : 0u),
             std::string("dependency count: ") + option.name);
        need(registry.findPolicy(activation)->dependencies().empty(), "artificial activation edge");
    }
    for (const auto* name : {"disable_nopasswdlogin", "disable_root_sddm_login"})
        if (const auto* policy = registry.findPolicy(pamRef(name)))
            need(policy->dependencies().empty(), "changed nonparametric dependencies");
}
json contracts(PlatformProfile profile, const fs::path& root) {
    checkDependencies(profile);
    PlatformExecutableResolver executables(profile.executables);
    json result = {{"registration_graph", true}, {"execution", json::array()}};
    for (const auto& option : options) {
        if (p::pamPolicySupport(profile.pam, option.feature) == PamPolicySupport::Unsupported) continue;
        const auto target = pamRef(option.name);
        const auto activation = pamRef(pamCapabilityActivationPolicyName(p::pamPolicyCapability(option.feature)));
        for (int mode = 0; mode != 3; ++mode) {
            configure(profile, option.name, mode != 0);
            auto registry = registryFor(profile, executables);
            unsigned ownCalls = 0, activationCalls = 0;
            PolicyExecutionPlanner planner(registry, [&](const PolicyRef& ref, Policy&) -> std::optional<PolicyApplyResult> {
                if (ref == target) ++ownCalls;
                if (ref == activation) ++activationCalls;
                // Always fail the Recommended dependency: it must not suppress the option.
                const bool success = ref == target || (ref == activation && mode == 2);
                PolicyApplyResult value{ref.moduleName, ref.submoduleName, ref.policyName,
                    success ? PolicyApplyStatus::Applied : PolicyApplyStatus::Failed, "fixture own executor", {}};
                value.ownApplyAttempted = true;
                return value;
            });
            const auto summary = planner.execute({{target}, {}});
            const PolicyApplyResult* targetResult = nullptr;
            for (const auto& value : summary.getResults()) if (value.policyName == target.policyName) targetResult = &value;
            need(targetResult != nullptr, "missing planner result");
            need(ownCalls == (mode == 2 ? 1u : 0u) && activationCalls == (mode == 0 ? 0u : 1u), "executor suppression failed");
            need(targetResult->ownApplyAttempted == (mode == 2), "incorrect ownApplyAttempted");
            need(mode == 2 ? targetResult->isApplied() :
                 (targetResult->isFailure() && targetResult->failureOrigin == PolicyFailureOrigin::RequiredDependencyBlocked),
                 "incorrect Required failure result");
            result["execution"].push_back({{"option", option.name}, {"mode", mode}, {"pass", true}});
        }
        configure(profile, option.name, true);
        auto registry = registryFor(profile, executables);
        need(enabledRequiredDependents(registry, activation).size() == 1, "reverse dependencies");
        const auto before = read(root / "config/IDENTITY_ACCESS.conf");
        // If the guard regresses, the test must still never release a native
        // host stack. Rollback receives a verify-only profile and empty journal;
        // the actual registry/dependent policies above remain unmodified.
        auto guardProfile = profile;
        for (auto& config : guardProfile.pam.capabilities)
            config.topology = PamTopologyStrategyKind::StaticVerifyOnly;
        need(!disable(registry, guardProfile, executables, "IDENTITY_ACCESS", activation.policyName).ok,
             "enabled Required dependent did not block production disable");
        need(read(root / "config/IDENTITY_ACCESS.conf") == before, "blocked disable changed config");
    }
    result["reverse_disable_guard"] = true;
    // Exercise future read-only profile routes with the real registry factory.
    auto readOnly = profile;
    readOnly.pam.passwordTopologyRuntimeMutable = false;
    checkDependencies(readOnly);
    result["readonly_graph"] = true;
    PolicyRegistry missing; std::string error;
    need(missing.addModule("IDENTITY_ACCESS", ModuleView::Standard, 0, error), error);
    need(missing.addPolicy(std::make_unique<PamPasswordQualityEnforceForRootPolicy>(profile.pam), error), error);
    need(!validatePolicyDependencyGraph(missing, error), "missing activation accepted");
    result["missing_activation_rejected"] = true;

    // A real factory/verifier StaticVerifyOnly path, with deliberately weak
    // values: Structural is not a claim of enforcing password strength.
    const auto fixture = root / "static";
    write(fixture / "security/pam_passwdqc.so", "fixture\n");
    write(fixture / "passwdqc.conf", "min=disabled,24,11,8,7\n");
    write(fixture / "pam.d/passwd", "password required pam_passwdqc.so config=" + (fixture / "passwdqc.conf").string() + "\n");
    auto staticProfile = profile;
    staticProfile.pam = {};
    staticProfile.pam.configDirectories = {fixture / "pam.d"};
    staticProfile.pam.moduleDirectories = {fixture / "security"};
    staticProfile.pam.scopes = {{PamScope::EffectivePasswordStack, {"passwd"}}};
    staticProfile.pam.capabilities = {{PamCapability::PasswordQuality, PamProviderKind::PamPasswdqc,
        PamScope::EffectivePasswordStack, fixture / "passwdqc.conf", PamTopologyStrategyKind::StaticVerifyOnly}};
    configure(staticProfile, "password_quality_enforce_for_root", true);
    PlatformExecutableResolver staticExecutables(staticProfile.executables);
    auto staticRegistry = registryFor(staticProfile, staticExecutables);
    const auto pamBefore = read(fixture / "pam.d/passwd"), confBefore = read(fixture / "passwdqc.conf");
    unsigned optionCalls = 0;
    PolicyExecutionPlanner structural(staticRegistry, [&](const PolicyRef& ref, Policy&) -> std::optional<PolicyApplyResult> {
        if (ref == pamRef("enable_password_quality")) return std::nullopt; // real apply, real verifier
        need(ref == pamRef("password_quality_enforce_for_root"), "unexpected executor");
        ++optionCalls;
        PolicyApplyResult value{ref.moduleName, ref.submoduleName, ref.policyName, PolicyApplyStatus::Applied, "option fixture", {}};
        value.ownApplyAttempted = true; return value;
    });
    need(structural.execute({{pamRef("password_quality_enforce_for_root")}, {}}).requestedRootsApplied() && optionCalls == 1,
         "foreign Structural activation did not satisfy Required");
    need(read(fixture / "pam.d/passwd") == pamBefore && read(fixture / "passwdqc.conf") == confBefore,
         "Structural activation mutated foreign files");
    {
        auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        need(journal && journal->records().empty(),
             "StaticVerifyOnly apply created topology ownership");
    }
    write(fixture / "security/pam_permit.so", "fixture\n");
    write(fixture / "pam.d/passwd", "password required pam_permit.so\n");
    optionCalls = 0;
    need(!structural.execute({{pamRef("password_quality_enforce_for_root")}, {}}).requestedRootsApplied() && optionCalls == 0,
         "ineffective static topology allowed option");
    const auto invalidPam = read(fixture / "pam.d/passwd");
    need(disable(staticRegistry, staticProfile, staticExecutables, "IDENTITY_ACCESS", "password_quality_enforce_for_root").ok,
         "disable dependent with absent provider ownership/broken activation failed");
    staticRegistry = registryFor(staticProfile, staticExecutables);
    need(enabledRequiredDependents(staticRegistry, pamRef("enable_password_quality")).empty(), "disabled dependent still blocks");
    need(disable(staticRegistry, staticProfile, staticExecutables, "IDENTITY_ACCESS", "enable_password_quality").ok,
         "static disable after last dependent failed");
    ModuleConfigFileHandler disabledConfig("IDENTITY_ACCESS");
    need(disabledConfig.getPolicyStatus("password_quality_enforce_for_root") == "DISABLE" &&
         disabledConfig.getPolicyStatus("enable_password_quality") == "DISABLE", "disable did not persist status");
    need(read(fixture / "pam.d/passwd") == invalidPam && read(fixture / "passwdqc.conf") == confBefore,
         "static disable mutated PAM/provider");
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    need(journal && journal->records().empty(), "static activation acquired ownership");
    result["static_structural_required_no_mutation_no_ownership"] = true;
    result["disable_after_last_dependent"] = true;
    return result;
}
