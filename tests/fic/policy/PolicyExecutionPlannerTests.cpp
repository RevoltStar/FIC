#include <fic/core/runtime/FicRuntimePaths.h>

#include "policy/execution/PolicyDependencyGraph.h"
#include "policy/execution/PolicyApplication.h"
#include "policy/execution/PolicyExecutionPlanner.h"
#include "modules/global/lock_settings/GLOBAL_incident_response_mode.h"
#include "policy/registry/PolicyRegistryJson.h"
#include "policy/registry/PolicyRegistryInitialization.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

PolicyRef ref(
    const std::string& policy,
    const std::string& module = "AUDIT") {
    return {module, "test", policy};
}

struct PolicyBehavior {
    bool result = true;
    int calls = 0;
};

class TestPolicy : public Policy {
public:
    TestPolicy(
        PolicyRef identity,
        PolicyBehavior& behavior,
        std::vector<std::string>& order,
        std::vector<PolicyDependency> dependencies = {})
        : behavior_(behavior), order_(order) {
        moduleName = std::move(identity.moduleName);
        submoduleName = std::move(identity.submoduleName);
        policyName = std::move(identity.policyName);
        policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
            std::vector<std::string>{"0", "1", "2"});
        for (const PolicyDependency& dependency : dependencies) {
            if (dependency.strength == PolicyDependencyStrength::Required) {
                addRequiredDependency(
                    dependency.policy, dependency.condition);
            } else {
                addRecommendedDependency(
                    dependency.policy, dependency.condition);
            }
        }
        moduleConf = std::make_unique<ModuleConfigFileHandler>(moduleName);
        if (!moduleConf->loadConfig()) {
            throw std::runtime_error("could not load test policy config");
        }
    }

    bool apply() override {
        ++behavior_.calls;
        order_.push_back(policyName);
        return behavior_.result;
    }

    void addDependencyAfterConstructionForTest(const PolicyRef& dependency) {
        addRequiredDependency(dependency);
    }

private:
    PolicyBehavior& behavior_;
    std::vector<std::string>& order_;
};

PolicyDependency required(
    const PolicyRef& dependency,
    PolicyDependencyCondition condition = {}) {
    return {
        dependency,
        PolicyDependencyStrength::Required,
        std::move(condition)
    };
}

PolicyDependency recommended(
    const PolicyRef& dependency,
    PolicyDependencyCondition condition = {}) {
    return {
        dependency,
        PolicyDependencyStrength::Recommended,
        std::move(condition)
    };
}

void writeModuleConfig(
    const std::filesystem::path& root,
    const std::string& module,
    const std::map<std::string, bool>& enabled,
    const std::map<std::string, std::string>& values = {}) {
    std::ofstream output(root / "config" / (module + ".conf"), std::ios::trunc);
    output << "_schema_version=1\n";
    for (const auto& [policy, isEnabled] : enabled) {
        output << policy << ".status="
               << (isEnabled ? "ENABLE" : "DISABLE") << '\n';
        const auto value = values.find(policy);
        if (value != values.end()) {
            output << policy << ".value=" << value->second << '\n';
        }
    }
}

PolicyRegistry buildRegistry(PolicyList policies) {
    PolicyRegistry registry;
    std::string error;
    require(
        buildPolicyRegistry(std::move(policies), registry, error),
        "registry build failed: " + error);
    return registry;
}

const PolicyApplyResult& result(
    const PolicyApplySummary& summary,
    const PolicyRef& policy) {
    const auto found = std::find_if(
        summary.getResults().begin(), summary.getResults().end(),
        [&](const PolicyApplyResult& candidate) {
            return PolicyRef{
                candidate.moduleName,
                candidate.submoduleName,
                candidate.policyName
            } == policy;
        });
    require(found != summary.getResults().end(),
            "missing result for " + formatPolicyRef(policy));
    return *found;
}

bool hasResult(
    const PolicyApplySummary& summary,
    const PolicyRef& policy) {
    return std::any_of(
        summary.getResults().begin(), summary.getResults().end(),
        [&](const PolicyApplyResult& candidate) {
            return PolicyRef{
                candidate.moduleName,
                candidate.submoduleName,
                candidate.policyName
            } == policy;
        });
}

bool hasDiagnostic(
    const PolicyApplyResult& policyResult,
    const std::string& level,
    const std::string& text) {
    return std::any_of(
        policyResult.diagnostics.begin(), policyResult.diagnostics.end(),
        [&](const PolicyDiagnostic& diagnostic) {
            return diagnostic.level == level &&
                diagnostic.message.find(text) != std::string::npos;
        });
}

void testRequiredDependencies(const std::filesystem::path& root) {
    writeModuleConfig(root, "AUDIT", {{"a", true}, {"b", true}});
    PolicyBehavior a;
    PolicyBehavior b;
    std::vector<std::string> order;
    PolicyList policies;
    policies.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order, std::vector<PolicyDependency>{required(ref("b"))}));
    policies.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
    PolicyRegistry registry = buildRegistry(std::move(policies));
    const PolicyApplySummary successful = PolicyExecutionPlanner(registry).execute(
        {{ref("a")}, {}});
    require(order == std::vector<std::string>({"b", "a"}),
            "required dependency order is incorrect");
    require(result(successful, ref("b")).status == PolicyApplyStatus::Applied &&
                result(successful, ref("a")).status == PolicyApplyStatus::Applied,
            "required success statuses are incorrect");

    writeModuleConfig(root, "AUDIT", {{"a", true}, {"b", true}});
    PolicyBehavior failedA;
    PolicyBehavior failedB{false};
    order.clear();
    PolicyList failedPolicies;
    failedPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), failedA, order,
        std::vector<PolicyDependency>{required(ref("b"))}));
    failedPolicies.push_back(
        std::make_unique<TestPolicy>(ref("b"), failedB, order));
    PolicyRegistry failedRegistry = buildRegistry(std::move(failedPolicies));
    const PolicyApplySummary failed = PolicyExecutionPlanner(failedRegistry).execute(
        {{ref("a")}, {}});
    require(failedB.calls == 1 && failedA.calls == 0,
            "required failure did not block dependent apply");
    require(result(failed, ref("b")).status == PolicyApplyStatus::Failed &&
                result(failed, ref("a")).status == PolicyApplyStatus::Failed,
            "required failure statuses are incorrect");
    require(hasDiagnostic(
                result(failed, ref("a")), "ERROR", "dependency status=failed"),
            "required failure diagnostic is missing");

    writeModuleConfig(root, "AUDIT", {{"a", true}, {"b", false}});
    PolicyBehavior disabledA;
    PolicyBehavior disabledB;
    order.clear();
    PolicyList disabledPolicies;
    disabledPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), disabledA, order,
        std::vector<PolicyDependency>{required(ref("b"))}));
    disabledPolicies.push_back(
        std::make_unique<TestPolicy>(ref("b"), disabledB, order));
    PolicyRegistry disabledRegistry = buildRegistry(std::move(disabledPolicies));
    const PolicyApplySummary disabled =
        PolicyExecutionPlanner(disabledRegistry).execute({{ref("a")}, {}});
    require(disabledB.calls == 0 && disabledA.calls == 0,
            "disabled required dependency or dependent was applied");
    require(result(disabled, ref("b")).status == PolicyApplyStatus::Disabled &&
                result(disabled, ref("a")).status == PolicyApplyStatus::Failed,
            "disabled required dependency statuses are incorrect");
}

void testRecommendedDependencies(const std::filesystem::path& root) {
    writeModuleConfig(root, "AUDIT", {{"a", true}, {"b", true}});
    PolicyBehavior successfulA;
    PolicyBehavior successfulB;
    std::vector<std::string> successfulOrder;
    PolicyList successfulPolicies;
    successfulPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), successfulA, successfulOrder,
        std::vector<PolicyDependency>{recommended(ref("b"))}));
    successfulPolicies.push_back(std::make_unique<TestPolicy>(
        ref("b"), successfulB, successfulOrder));
    PolicyRegistry successfulRegistry =
        buildRegistry(std::move(successfulPolicies));
    const PolicyApplySummary successful =
        PolicyExecutionPlanner(successfulRegistry).execute({{ref("a")}, {}});
    require(successfulOrder == std::vector<std::string>({"b", "a"}) &&
                result(successful, ref("b")).status ==
                    PolicyApplyStatus::Applied &&
                result(successful, ref("a")).status ==
                    PolicyApplyStatus::Applied,
            "recommended success order or statuses are incorrect");

    for (const bool dependencyEnabled : {true, false}) {
        writeModuleConfig(
            root, "AUDIT", {{"a", true}, {"b", dependencyEnabled}});
        PolicyBehavior a;
        PolicyBehavior b{false};
        std::vector<std::string> order;
        PolicyList policies;
        policies.push_back(std::make_unique<TestPolicy>(
            ref("a"), a, order,
            std::vector<PolicyDependency>{recommended(ref("b"))}));
        policies.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
        PolicyRegistry registry = buildRegistry(std::move(policies));
        const PolicyApplySummary summary =
            PolicyExecutionPlanner(registry).execute({{ref("a")}, {}});

        require(a.calls == 1, "recommended dependency blocked dependent apply");
        require(result(summary, ref("a")).status == PolicyApplyStatus::Applied,
                "recommended dependent status is incorrect");
        const PolicyApplyStatus expectedDependency = dependencyEnabled
            ? PolicyApplyStatus::Failed
            : PolicyApplyStatus::Disabled;
        require(result(summary, ref("b")).status == expectedDependency,
                "recommended dependency status is incorrect");
        require(hasDiagnostic(
                    result(summary, ref("a")),
                    "WARN",
                    "dependency status=" +
                        policyApplyStatusToString(expectedDependency)),
                "recommended dependency warning is missing");
        require(summary.requestedRootsApplied(),
                "dependency-only recommended failure broke root success");
    }
}

void testConditionalDependencies(const std::filesystem::path& root) {
    for (const std::string& ownerValue : {std::string("2"), std::string("1")}) {
        writeModuleConfig(
            root,
            "AUDIT",
            {{"a", true}, {"b", true}},
            {{"a", ownerValue}});
        PolicyBehavior a;
        PolicyBehavior b;
        std::vector<std::string> order;
        PolicyList policies;
        policies.push_back(std::make_unique<TestPolicy>(
            ref("a"), a, order,
            std::vector<PolicyDependency>{required(
                ref("b"), whenOwnerValueEquals("2"))}));
        policies.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
        PolicyRegistry registry = buildRegistry(std::move(policies));
        const PolicyApplySummary summary =
            PolicyExecutionPlanner(registry).execute({{ref("a")}, {}});

        if (ownerValue == "2") {
            require(order == std::vector<std::string>({"b", "a"}) &&
                        b.calls == 1 && a.calls == 1,
                    "matching required condition did not execute dependency first");
            require(result(summary, ref("b")).status ==
                            PolicyApplyStatus::Applied &&
                        result(summary, ref("a")).status ==
                            PolicyApplyStatus::Applied,
                    "matching required condition statuses are incorrect");
        } else {
            require(order == std::vector<std::string>({"a"}) &&
                        b.calls == 0 && a.calls == 1 &&
                        !hasResult(summary, ref("b")),
                    "mismatching required condition expanded dependency");
            require(result(summary, ref("a")).diagnostics.empty(),
                    "mismatching required condition created diagnostic");
        }
    }

    for (const std::string& ownerValue : {std::string("2"), std::string("1")}) {
        writeModuleConfig(
            root,
            "AUDIT",
            {{"a", true}, {"b", true}},
            {{"a", ownerValue}});
        PolicyBehavior a;
        PolicyBehavior b{false};
        std::vector<std::string> order;
        PolicyList policies;
        policies.push_back(std::make_unique<TestPolicy>(
            ref("a"), a, order,
            std::vector<PolicyDependency>{recommended(
                ref("b"), whenOwnerValueEquals("2"))}));
        policies.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
        PolicyRegistry registry = buildRegistry(std::move(policies));
        const PolicyApplySummary summary =
            PolicyExecutionPlanner(registry).execute({{ref("a")}, {}});

        require(a.calls == 1 &&
                    result(summary, ref("a")).status == PolicyApplyStatus::Applied,
                "conditional recommended dependency blocked owner");
        if (ownerValue == "2") {
            require(b.calls == 1 &&
                        result(summary, ref("b")).status ==
                            PolicyApplyStatus::Failed &&
                        hasDiagnostic(
                            result(summary, ref("a")),
                            "WARN",
                            "dependency status=failed"),
                    "matching recommended condition lost failure warning");
        } else {
            require(b.calls == 0 && !hasResult(summary, ref("b")) &&
                        result(summary, ref("a")).diagnostics.empty(),
                    "mismatching recommended condition created work or warning");
        }
    }

    writeModuleConfig(root, "AUDIT", {{"a", true}, {"b", true}});
    PolicyBehavior missingValueA;
    PolicyBehavior missingValueB;
    std::vector<std::string> missingValueOrder;
    PolicyList missingValuePolicies;
    missingValuePolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), missingValueA, missingValueOrder,
        std::vector<PolicyDependency>{required(
            ref("b"), whenOwnerValueEquals("2"))}));
    missingValuePolicies.push_back(std::make_unique<TestPolicy>(
        ref("b"), missingValueB, missingValueOrder));
    PolicyRegistry missingValueRegistry =
        buildRegistry(std::move(missingValuePolicies));
    const PolicyApplySummary missingValueSummary =
        PolicyExecutionPlanner(missingValueRegistry).execute({{ref("a")}, {}});
    require(missingValueA.calls == 1 && missingValueB.calls == 0 &&
                !hasResult(missingValueSummary, ref("b")) &&
                result(missingValueSummary, ref("a")).status ==
                    PolicyApplyStatus::Applied,
            "null owner value did not behave as a false condition");

    writeModuleConfig(
        root,
        "AUDIT",
        {{"a", false}, {"b", true}},
        {{"a", "2"}});
    PolicyBehavior disabledA;
    PolicyBehavior disabledB;
    std::vector<std::string> disabledOrder;
    PolicyList disabledPolicies;
    disabledPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), disabledA, disabledOrder,
        std::vector<PolicyDependency>{required(
            ref("b"), whenOwnerValueEquals("2"))}));
    disabledPolicies.push_back(std::make_unique<TestPolicy>(
        ref("b"), disabledB, disabledOrder));
    PolicyRegistry disabledRegistry = buildRegistry(std::move(disabledPolicies));
    const PolicyApplySummary disabledSummary =
        PolicyExecutionPlanner(disabledRegistry).execute({{ref("a")}, {}});
    require(disabledA.calls == 0 && disabledB.calls == 0 &&
                disabledSummary.totalCount() == 1 &&
                result(disabledSummary, ref("a")).status ==
                    PolicyApplyStatus::Disabled,
            "disabled owner evaluated its conditional dependency");
}

void testConditionalExcludedModule(const std::filesystem::path& root) {
    for (const PolicyDependencyStrength strength : {
             PolicyDependencyStrength::Required,
             PolicyDependencyStrength::Recommended}) {
        for (const std::string& ownerValue : {
                 std::string("1"), std::string("2")}) {
            writeModuleConfig(
                root, "AUDIT", {{"a", true}}, {{"a", ownerValue}});
            writeModuleConfig(root, "GLOBAL", {{"b", true}});
            PolicyBehavior a;
            PolicyBehavior b;
            std::vector<std::string> order;
            const PolicyDependency dependency{
                ref("b", "GLOBAL"),
                strength,
                whenOwnerValueEquals("2")
            };
            PolicyList policies;
            policies.push_back(std::make_unique<TestPolicy>(
                ref("a"), a, order,
                std::vector<PolicyDependency>{dependency}));
            policies.push_back(std::make_unique<TestPolicy>(
                ref("b", "GLOBAL"), b, order));
            PolicyRegistry registry = buildRegistry(std::move(policies));
            const PolicyApplySummary summary =
                PolicyExecutionPlanner(registry).execute(
                    {{ref("a")}, {"GLOBAL"}});

            require(b.calls == 0 && !hasResult(summary, ref("b", "GLOBAL")),
                    "excluded conditional target was unexpectedly executed");
            if (ownerValue == "1") {
                require(a.calls == 1 &&
                            result(summary, ref("a")).status ==
                                PolicyApplyStatus::Applied &&
                            result(summary, ref("a")).diagnostics.empty(),
                        "inactive excluded edge affected owner");
            } else if (strength == PolicyDependencyStrength::Required) {
                require(a.calls == 0 &&
                            result(summary, ref("a")).status ==
                                PolicyApplyStatus::Failed &&
                            hasDiagnostic(
                                result(summary, ref("a")),
                                "ERROR",
                                "explicitly excluded module GLOBAL"),
                        "active required excluded edge did not block owner");
            } else {
                require(a.calls == 1 &&
                            result(summary, ref("a")).status ==
                                PolicyApplyStatus::Applied &&
                            hasDiagnostic(
                                result(summary, ref("a")),
                                "WARN",
                                "explicitly excluded module GLOBAL"),
                        "active recommended excluded edge lost warning");
            }
        }
    }
}

void testDisabledDependentDoesNotExpand(const std::filesystem::path& root) {
    for (const PolicyDependencyStrength strength : {
             PolicyDependencyStrength::Required,
             PolicyDependencyStrength::Recommended}) {
        writeModuleConfig(root, "AUDIT", {{"a", false}, {"b", true}});
        PolicyBehavior a;
        PolicyBehavior b;
        std::vector<std::string> order;
        PolicyList policies;
        const PolicyDependency dependency{ref("b"), strength};
        policies.push_back(std::make_unique<TestPolicy>(
            ref("a"), a, order, std::vector<PolicyDependency>{dependency}));
        policies.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
        PolicyRegistry registry = buildRegistry(std::move(policies));
        const PolicyApplySummary summary =
            PolicyExecutionPlanner(registry).execute({{ref("a")}, {}});
        require(a.calls == 0 && b.calls == 0 && summary.totalCount() == 1,
                "disabled dependent expanded its dependency graph");
        require(result(summary, ref("a")).status == PolicyApplyStatus::Disabled,
                "disabled dependent status is incorrect");

        const PolicyApplySummary explicitDependencyRoot =
            PolicyExecutionPlanner(registry).execute(
                {{ref("a"), ref("b")}, {}});
        require(b.calls == 1 &&
                    result(explicitDependencyRoot, ref("b")).status ==
                        PolicyApplyStatus::Applied,
                "disabled dependent suppressed a dependency selected as root");
    }
}

void testChains(const std::filesystem::path& root) {
    writeModuleConfig(
        root, "AUDIT", {{"a", true}, {"b", true}, {"c", true}});
    PolicyBehavior a;
    PolicyBehavior b;
    PolicyBehavior c;
    std::vector<std::string> order;
    PolicyList policies;
    policies.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order, std::vector<PolicyDependency>{required(ref("b"))}));
    policies.push_back(std::make_unique<TestPolicy>(
        ref("b"), b, order, std::vector<PolicyDependency>{required(ref("c"))}));
    policies.push_back(std::make_unique<TestPolicy>(ref("c"), c, order));
    PolicyRegistry registry = buildRegistry(std::move(policies));
    PolicyApplySummary summary =
        PolicyExecutionPlanner(registry).execute({{ref("a")}, {}});
    require(order == std::vector<std::string>({"c", "b", "a"}),
            "transitive required order is incorrect");

    writeModuleConfig(
        root, "AUDIT", {{"a", true}, {"b", true}, {"c", true}});
    PolicyBehavior blockedA;
    PolicyBehavior blockedB;
    PolicyBehavior failedC{false};
    order.clear();
    PolicyList blockedPolicies;
    blockedPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), blockedA, order,
        std::vector<PolicyDependency>{required(ref("b"))}));
    blockedPolicies.push_back(std::make_unique<TestPolicy>(
        ref("b"), blockedB, order,
        std::vector<PolicyDependency>{required(ref("c"))}));
    blockedPolicies.push_back(
        std::make_unique<TestPolicy>(ref("c"), failedC, order));
    PolicyRegistry blockedRegistry = buildRegistry(std::move(blockedPolicies));
    summary = PolicyExecutionPlanner(blockedRegistry).execute({{ref("a")}, {}});
    require(failedC.calls == 1 && blockedB.calls == 0 && blockedA.calls == 0,
            "transitive required failure did not block dependents");
    require(result(summary, ref("c")).status == PolicyApplyStatus::Failed &&
                result(summary, ref("b")).status == PolicyApplyStatus::Failed &&
                result(summary, ref("a")).status == PolicyApplyStatus::Failed,
            "transitive required failure statuses are incorrect");

    writeModuleConfig(
        root, "AUDIT", {{"a", true}, {"b", false}, {"c", true}});
    PolicyBehavior prunedA;
    PolicyBehavior prunedB;
    PolicyBehavior prunedC;
    order.clear();
    PolicyList prunedPolicies;
    prunedPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), prunedA, order,
        std::vector<PolicyDependency>{required(ref("b"))}));
    prunedPolicies.push_back(std::make_unique<TestPolicy>(
        ref("b"), prunedB, order,
        std::vector<PolicyDependency>{required(ref("c"))}));
    prunedPolicies.push_back(
        std::make_unique<TestPolicy>(ref("c"), prunedC, order));
    PolicyRegistry prunedRegistry = buildRegistry(std::move(prunedPolicies));
    summary = PolicyExecutionPlanner(prunedRegistry).execute({{ref("a")}, {}});
    require(prunedA.calls == 0 && prunedB.calls == 0 && prunedC.calls == 0 &&
                summary.totalCount() == 2,
            "disabled intermediate dependency did not prune its dependencies");

    writeModuleConfig(
        root, "AUDIT", {{"a", true}, {"b", true}, {"c", true}});
    PolicyBehavior mixedA;
    PolicyBehavior mixedB;
    PolicyBehavior mixedC{false};
    order.clear();
    PolicyList mixedPolicies;
    mixedPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), mixedA, order,
        std::vector<PolicyDependency>{recommended(ref("b"))}));
    mixedPolicies.push_back(std::make_unique<TestPolicy>(
        ref("b"), mixedB, order,
        std::vector<PolicyDependency>{required(ref("c"))}));
    mixedPolicies.push_back(
        std::make_unique<TestPolicy>(ref("c"), mixedC, order));
    PolicyRegistry mixedRegistry = buildRegistry(std::move(mixedPolicies));
    summary = PolicyExecutionPlanner(mixedRegistry).execute({{ref("a")}, {}});
    require(mixedC.calls == 1 && mixedB.calls == 0 && mixedA.calls == 1,
            "mixed dependency chain execution is incorrect");
    require(result(summary, ref("c")).status == PolicyApplyStatus::Failed &&
                result(summary, ref("b")).status == PolicyApplyStatus::Failed &&
                result(summary, ref("a")).status == PolicyApplyStatus::Applied,
            "mixed dependency chain statuses are incorrect");
}

void testSharedDependencyAndBatchRoots(const std::filesystem::path& root) {
    writeModuleConfig(
        root, "AUDIT", {{"a", true}, {"b", true}, {"c", true}});
    PolicyBehavior a;
    PolicyBehavior b;
    PolicyBehavior c;
    std::vector<std::string> order;
    PolicyList policies;
    policies.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order, std::vector<PolicyDependency>{required(ref("c"))}));
    policies.push_back(std::make_unique<TestPolicy>(
        ref("b"), b, order, std::vector<PolicyDependency>{required(ref("c"))}));
    policies.push_back(std::make_unique<TestPolicy>(ref("c"), c, order));
    PolicyRegistry registry = buildRegistry(std::move(policies));
    const PolicyApplySummary summary = PolicyExecutionPlanner(registry).execute(
        {{ref("a"), ref("b")}, {}});
    require(c.calls == 1 && a.calls == 1 && b.calls == 1,
            "shared dependency was not reused");

    writeModuleConfig(root, "AUDIT", {{"a", true}, {"b", true}});
    PolicyBehavior rootA;
    PolicyBehavior rootB{false};
    order.clear();
    PolicyList rootPolicies;
    rootPolicies.push_back(std::make_unique<TestPolicy>(
        ref("a"), rootA, order,
        std::vector<PolicyDependency>{recommended(ref("b"))}));
    rootPolicies.push_back(
        std::make_unique<TestPolicy>(ref("b"), rootB, order));
    PolicyRegistry rootRegistry = buildRegistry(std::move(rootPolicies));
    const PolicyApplySummary single = applyPolicy(rootRegistry, "AUDIT", "a");
    require(isPolicyApplySuccessful(single, "AUDIT", "a"),
            "recommended dependency-only failure broke single request");
    const PolicyApplySummary batch =
        applyModulePolicies(rootRegistry, "AUDIT");
    require(!isPolicyApplySuccessful(batch, "AUDIT", "all"),
            "failed dependency that is also a batch root was ignored");
}

void testDeterministicRootsAndFrozenMetadata(
    const std::filesystem::path& root) {
    writeModuleConfig(root, "AUDIT", {{"a", true}, {"z", true}});
    PolicyBehavior a;
    PolicyBehavior z;
    std::vector<std::string> order;
    PolicyList policies;
    policies.push_back(std::make_unique<TestPolicy>(ref("z"), z, order));
    policies.push_back(std::make_unique<TestPolicy>(ref("a"), a, order));
    PolicyRegistry registry = buildRegistry(std::move(policies));
    const PolicyApplySummary summary = PolicyExecutionPlanner(registry).execute(
        {{ref("z"), ref("a")}, {}});
    require(order == std::vector<std::string>({"a", "z"}) &&
                summary.requestedRootsApplied(),
            "independent roots are not deterministic");

    auto* registered = dynamic_cast<TestPolicy*>(registry.findPolicy(ref("a")));
    require(registered != nullptr, "registered test policy is unavailable");
    bool rejected = false;
    try {
        registered->addDependencyAfterConstructionForTest(ref("z"));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    require(rejected, "registered dependency metadata remained mutable");
}

void testExcludedModule(const std::filesystem::path& root) {
    for (const PolicyDependencyStrength strength : {
             PolicyDependencyStrength::Required,
             PolicyDependencyStrength::Recommended}) {
        writeModuleConfig(root, "AUDIT", {{"a", true}});
        writeModuleConfig(root, "GLOBAL", {{"b", true}});
        PolicyBehavior a;
        PolicyBehavior b;
        std::vector<std::string> order;
        PolicyList policies;
        policies.push_back(std::make_unique<TestPolicy>(
            ref("a"), a, order,
            std::vector<PolicyDependency>{{ref("b", "GLOBAL"), strength}}));
        policies.push_back(std::make_unique<TestPolicy>(
            ref("b", "GLOBAL"), b, order));
        PolicyRegistry registry = buildRegistry(std::move(policies));
        const PolicyApplySummary summary = PolicyExecutionPlanner(registry).execute(
            {{ref("a")}, {"GLOBAL"}});
        require(b.calls == 0, "hard-excluded dependency was applied");
        if (strength == PolicyDependencyStrength::Required) {
            require(a.calls == 0 &&
                        result(summary, ref("a")).status ==
                            PolicyApplyStatus::Failed,
                    "required excluded dependency did not block dependent");
        } else {
            require(a.calls == 1 &&
                        result(summary, ref("a")).status ==
                            PolicyApplyStatus::Applied,
                    "recommended excluded dependency blocked dependent");
        }
        require(hasDiagnostic(
                    result(summary, ref("a")),
                    strength == PolicyDependencyStrength::Required
                        ? "ERROR"
                        : "WARN",
                    "explicitly excluded module GLOBAL"),
                "excluded dependency diagnostic is missing");
    }
}

void expectInvalid(
    PolicyList policies,
    const std::string& expectedError) {
    PolicyRegistry registry;
    std::string error;
    require(!buildPolicyRegistry(std::move(policies), registry, error),
            "invalid dependency graph was accepted");
    require(error.find(expectedError) != std::string::npos,
            "unexpected graph validation error: " + error);
}

void testGraphValidation(const std::filesystem::path& root) {
    writeModuleConfig(
        root, "AUDIT", {{"a", true}, {"b", true}, {"c", true}});
    PolicyBehavior a;
    PolicyBehavior b;
    PolicyBehavior c;
    std::vector<std::string> order;

    PolicyList self;
    self.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order, std::vector<PolicyDependency>{required(ref("a"))}));
    expectInvalid(std::move(self), "depends on itself");

    PolicyList missing;
    missing.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{required(ref("missing"))}));
    expectInvalid(std::move(missing), "references unknown dependency");

    PolicyList duplicate;
    duplicate.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{required(ref("b")), required(ref("b"))}));
    duplicate.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
    expectInvalid(std::move(duplicate), "declares duplicate dependency");

    PolicyList conditionalDuplicate;
    conditionalDuplicate.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{
            required(ref("b"), whenOwnerValueEquals("1")),
            required(ref("b"), whenOwnerValueEquals("2"))}));
    conditionalDuplicate.push_back(
        std::make_unique<TestPolicy>(ref("b"), b, order));
    expectInvalid(
        std::move(conditionalDuplicate), "declares duplicate dependency");

    PolicyList mixedTarget;
    mixedTarget.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{required(ref("b")), recommended(ref("b"))}));
    mixedTarget.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
    expectInvalid(
        std::move(mixedTarget), "both Required and Recommended");

    PolicyList invalidLiteral;
    invalidLiteral.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{required(
            ref("b"), whenOwnerValueEquals("42"))}));
    invalidLiteral.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
    expectInvalid(
        std::move(invalidLiteral),
        "OwnerValueEquals dependency condition contains an invalid owner policy value");

    PolicyList invalidAlwaysPayload;
    invalidAlwaysPayload.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{required(
            ref("b"),
            {PolicyDependencyConditionType::Always, "unexpected"})}));
    invalidAlwaysPayload.push_back(
        std::make_unique<TestPolicy>(ref("b"), b, order));
    expectInvalid(
        std::move(invalidAlwaysPayload),
        "Always dependency condition must not contain a value");

    for (const auto strengths : {
             std::pair{PolicyDependencyStrength::Required,
                       PolicyDependencyStrength::Required},
             std::pair{PolicyDependencyStrength::Recommended,
                       PolicyDependencyStrength::Recommended},
             std::pair{PolicyDependencyStrength::Required,
                       PolicyDependencyStrength::Recommended}}) {
        PolicyList cycle;
        cycle.push_back(std::make_unique<TestPolicy>(
            ref("a"), a, order,
            std::vector<PolicyDependency>{{ref("b"), strengths.first}}));
        cycle.push_back(std::make_unique<TestPolicy>(
            ref("b"), b, order,
            std::vector<PolicyDependency>{{ref("a"), strengths.second}}));
        expectInvalid(std::move(cycle), "dependency cycle detected");
    }

    PolicyList longCycle;
    longCycle.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order, std::vector<PolicyDependency>{required(ref("b"))}));
    longCycle.push_back(std::make_unique<TestPolicy>(
        ref("b"), b, order,
        std::vector<PolicyDependency>{recommended(ref("c"))}));
    longCycle.push_back(std::make_unique<TestPolicy>(
        ref("c"), c, order, std::vector<PolicyDependency>{required(ref("a"))}));
    expectInvalid(std::move(longCycle), "dependency cycle detected");

    PolicyList conditionalCycle;
    conditionalCycle.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{required(
            ref("b"), whenOwnerValueEquals("1"))}));
    conditionalCycle.push_back(std::make_unique<TestPolicy>(
        ref("b"), b, order,
        std::vector<PolicyDependency>{recommended(
            ref("a"), whenOwnerValueEquals("2"))}));
    expectInvalid(std::move(conditionalCycle), "dependency cycle detected");
    require(a.calls == 0 && b.calls == 0 && c.calls == 0,
            "invalid graph executed a policy");
}

} // namespace


// ---------------------------------------------------------------------------
// Reverse-dependency guard: a required dependency of an ENABLED policy must
// not be disabled before its dependents (Part E).
// ---------------------------------------------------------------------------

void testEnabledRequiredDependentsGuard(const std::filesystem::path& root) {
    const PolicyRef blocker = ref("blocker");
    const PolicyRef dependent = ref("dependent");
    const PolicyRef advisory = ref("advisory");
    const PolicyRef unrelated = ref("unrelated");

    // blocker enabled, dependent enabled, advisory disabled.
    writeModuleConfig(root, "AUDIT", {{"blocker", true},
                                      {"dependent", true},
                                      {"advisory", false},
                                      {"unrelated", true}});

    PolicyBehavior blockerBehavior;
    PolicyBehavior dependentBehavior;
    PolicyBehavior advisoryBehavior;
    PolicyBehavior unrelatedBehavior;
    std::vector<std::string> order;

    PolicyList policies;
    policies.push_back(std::make_unique<TestPolicy>(blocker, blockerBehavior, order));
    policies.push_back(std::make_unique<TestPolicy>(
        dependent, dependentBehavior, order,
        std::vector<PolicyDependency>{required(blocker)}));
    policies.push_back(std::make_unique<TestPolicy>(
        advisory, advisoryBehavior, order,
        std::vector<PolicyDependency>{recommended(blocker)}));
    policies.push_back(std::make_unique<TestPolicy>(unrelated, unrelatedBehavior, order));
    PolicyRegistry registry = buildRegistry(std::move(policies));

    const auto dependents = enabledRequiredDependents(registry, blocker);
    require(dependents.size() == 1,
            "only the ENABLED required dependent must block the disable");
    require(dependents.front() == dependent,
            "the reported dependent must be the required one");

    require(enabledRequiredDependents(registry, unrelated).empty(),
            "a policy nobody requires is never blocked");
    require(enabledRequiredDependents(registry, dependent).empty(),
            "a leaf dependency is never blocked");
    // Recommended dependencies never block a disable.
    require(enabledRequiredDependents(registry, advisory).empty(),
            "advisory dependency is never blocked");

    // Forward direction: a dependent is not Applied while its required
    // dependency fails.
    blockerBehavior.result = false;
    PolicyExecutionRequest request;
    request.requestedRoots.push_back(dependent);
    const PolicyApplySummary summary = PolicyExecutionPlanner(registry).execute(request);
    require(result(summary, dependent).status == PolicyApplyStatus::Failed,
            "a dependent must not report Applied when its required blocker fails");
    require(dependentBehavior.calls == 0,
            "a blocked dependent must not be applied at all");

}


// Locks the intended production SUDO dependency graph shape (Part E/G).
// The concrete classes live in the daemon binary, so this pins the EDGES by
// name: every global Defaults policy requires the scoped-Defaults blocker,
// and every policy whose guarantee exempt_group can void requires the
// exempt_group policy. sudo_env_reset is deliberately absent from the
// exempt_group set.
void testSudoDependencyGraphShape(const std::filesystem::path& root) {
    const PolicyRef scoped = {"DAC", "SudoEdit", "sudo_disable_scoped_defaults"};
    const PolicyRef exempt = {"DAC", "SudoEdit", "sudo_exempt_group_disable"};
    const PolicyRef envReset = {"DAC", "SudoEdit", "sudo_env_reset"};
    const PolicyRef passwdTries = {"DAC", "SudoEdit", "sudo_passwd_tries"};
    const PolicyRef securepath = {"DAC", "SudoEdit", "sudo_securepath"};
    const PolicyRef timeout = {"DAC", "SudoEdit", "sudo_timeout"};
    const PolicyRef requireAuth =
        {"DAC", "SudoEdit", "sudo_require_authentication"};

    writeModuleConfig(root, "DAC", {
        {"sudo_disable_scoped_defaults", false},
        {"sudo_exempt_group_disable", false},
        {"sudo_env_reset", false},
        {"sudo_passwd_tries", false},
        {"sudo_securepath", false},
        {"sudo_timeout", false},
        {"sudo_require_authentication", false},
    });

    PolicyBehavior behavior;
    std::vector<std::string> order;
    PolicyList policies;
    policies.push_back(std::make_unique<TestPolicy>(scoped, behavior, order));
    policies.push_back(std::make_unique<TestPolicy>(exempt, behavior, order,
        std::vector<PolicyDependency>{required(scoped)}));
    for (const PolicyRef& globalDefaults :
         {envReset, passwdTries, securepath, timeout}) {
        policies.push_back(std::make_unique<TestPolicy>(
            globalDefaults, behavior, order,
            std::vector<PolicyDependency>{required(scoped)}));
    }
    policies.push_back(std::make_unique<TestPolicy>(
        requireAuth, behavior, order,
        std::vector<PolicyDependency>{required(exempt)}));

    // The graph must be valid (no cycle, no unknown/duplicate dependency).
    PolicyRegistry registry = buildRegistry(std::move(policies));

    const auto hasRequired = [&registry](const PolicyRef& owner,
                                         const PolicyRef& dependency) {
        for (const PolicyDependency& declared :
             registry.findPolicy(owner)->dependencies()) {
            if (declared.policy == dependency &&
                declared.strength == PolicyDependencyStrength::Required) {
                return true;
            }
        }
        return false;
    };

    for (const PolicyRef& globalDefaults :
         {envReset, passwdTries, securepath, timeout}) {
        require(hasRequired(globalDefaults, scoped),
                "every global Defaults policy must require the scoped blocker");
    }
    require(hasRequired(exempt, scoped),
            "exempt_group policy must require the scoped blocker");
    require(hasRequired(requireAuth, exempt),
            "require_authentication must require the exempt_group owner");
    require(!hasRequired(envReset, exempt),
            "env_reset must not depend on exempt_group: upstream sudoers shows "
            "no such relation");

}

// ---------------------------------------------------------------------------
// Violation severity semantics.
//
// The mandatory matrix from the incident specification, verified end to end
// through the real execution planner and the real Policy metadata:
//
//   A Required->B, B fails  => B raises Y, A raises X (A is itself Failed),
//                              result = max(X, Y). This is NOT inheritance:
//                              A fires because A ITSELF ended in Failed.
//   A Recommended->B, A succeeds, B fails
//                           => only B raises, result = Y.
//   A Recommended->B, both fail
//                           => result = max(X, Y).
// ---------------------------------------------------------------------------

// Minimal policy that carries an explicit violation severity, so the matrix
// can be driven from configuration rather than from compiled-in defaults.
class SeverityPolicy final : public TestPolicy {
public:
    using TestPolicy::TestPolicy;

    ::fic::core::ViolationSeverity getDefaultViolationSeverity() const override {
        return ::fic::core::ViolationSeverity::None;
    }
};

// Mirrors the daemon-side decision: for every result of an ENABLED policy
// that ended in Failed, that policy's OWN violation severity is activated.
// The iteration order cannot change the outcome because the merge is a max.
::fic::core::IncidentSeverity severityRaisedBy(
    const PolicyApplySummary& summary,
    const PolicyRegistry& registry) {
    ::fic::core::IncidentSeverity raised = ::fic::core::IncidentSeverity::Unlocked;
    for (const PolicyApplyResult& policyResult : summary.getResults()) {
        const PolicyRef owner{policyResult.moduleName,
                              policyResult.submoduleName,
                              policyResult.policyName};
        const Policy* policy = registry.findPolicy(owner);
        // A result for a policy that is no longer in the registry cannot be
        // attributed a severity, and therefore cannot raise one.
        if (policy == nullptr || !policy->isEnabled()) {
            continue;
        }
        if (!policyResult.activatesIncident()) {
            continue;
        }
        const ::fic::core::ViolationSeverity severity =
            policy->getViolationSeverity();
        if (!::fic::core::violationSeverityReacts(severity)) {
            continue;
        }
        raised = ::fic::core::maxIncidentSeverity(
            raised,
            ::fic::core::violationSeverityToIncidentSeverity(severity));
    }
    return raised;
}

// Writes the module configuration into the runtime tree that main() already
// initialized. FicRuntimePaths is intentionally a once-only singleton, so the
// severity scenarios configure it in place instead of re-initializing.
struct SeverityFixture {
    SeverityFixture() {
        configPath = fic::core::FicRuntimePaths::get().configDir / "AUDIT.conf";
    }
    std::filesystem::path configPath;
};

// Builds A (with a dependency on B) and B, with the requested severities and
// apply outcomes, then returns the summary and the registry.
struct MatrixResult {
    PolicyApplySummary summary;
    PolicyRegistry registry;
};

MatrixResult runMatrix(
    PolicyDependencyStrength strength,
    ::fic::core::ViolationSeverity aSeverity,
    ::fic::core::ViolationSeverity bSeverity,
    bool aFails,
    bool bFails) {
    SeverityFixture fixture;
    {
        std::ofstream config(fixture.configPath, std::ios::trunc);
        config << "_schema_version=1\n"
               << "a.status=ENABLE\na.violation_severity="
               << ::fic::core::violationSeverityToken(aSeverity) << "\n"
               << "b.status=ENABLE\nb.violation_severity="
               << ::fic::core::violationSeverityToken(bSeverity) << "\n";
    }

    PolicyBehavior aBehavior;
    PolicyBehavior bBehavior;
    aBehavior.result = !aFails;
    bBehavior.result = !bFails;
    std::vector<std::string> order;

    const PolicyRef b = ref("b");
    const PolicyRef a = ref("a");
    PolicyList policies;
    policies.push_back(std::make_unique<SeverityPolicy>(b, bBehavior, order));
    policies.push_back(std::make_unique<SeverityPolicy>(
        a, aBehavior, order,
        std::vector<PolicyDependency>{{b, strength, {}}}));
    MatrixResult built;
    built.registry = buildRegistry(std::move(policies));

    PolicyExecutionRequest request;
    request.requestedRoots.push_back(a);
    built.summary = PolicyExecutionPlanner(built.registry).execute(request);
    return built;
}

// A Required->B where B fails. B raises Y; A is ITSELF Failed
// (RequiredDependencyBlocked) and raises X. The result is max(X, Y) and NOT
// an inheritance of Y onto A.
void testRequiredDependencyRaisesBothOwnSeverities() {
    using VS = ::fic::core::ViolationSeverity;
    using IS = ::fic::core::IncidentSeverity;

    const MatrixResult isolateSoft = runMatrix(
        PolicyDependencyStrength::Required, VS::Isolate, VS::Soft,
        /*aFails=*/false, /*bFails=*/true);
    require(result(isolateSoft.summary, ref("a")).status ==
                PolicyApplyStatus::Failed,
            "a Required-blocked dependent must be Failed");
    require(result(isolateSoft.summary, ref("a")).failureOrigin ==
                PolicyFailureOrigin::RequiredDependencyBlocked,
            "the blocked dependent must report RequiredDependencyBlocked");
    require(!result(isolateSoft.summary, ref("a")).ownApplyAttempted,
            "a blocked dependent must not have run its own apply()");
    require(severityRaisedBy(isolateSoft.summary, isolateSoft.registry) ==
                IS::Isolate,
            "A=ISOLATE with B=SOFT failing must raise ISOLATE");

    const MatrixResult softHard = runMatrix(
        PolicyDependencyStrength::Required, VS::Soft, VS::Hard,
        /*aFails=*/false, /*bFails=*/true);
    require(severityRaisedBy(softHard.summary, softHard.registry) == IS::Hard,
            "A=SOFT with B=HARD failing must raise HARD");
}

// A Recommended->B where A SUCCEEDS and B fails. Only B raises: a
// Recommended dependency failure must NOT fail the dependent.
void testRecommendedDependencyDoesNotRaiseTheDependent() {
    using VS = ::fic::core::ViolationSeverity;
    using IS = ::fic::core::IncidentSeverity;

    const MatrixResult run = runMatrix(
        PolicyDependencyStrength::Recommended, VS::Isolate, VS::Hard,
        /*aFails=*/false, /*bFails=*/true);
    require(result(run.summary, ref("a")).status == PolicyApplyStatus::Applied,
            "a Recommended dependency failure must not fail the dependent");
    require(result(run.summary, ref("a")).failureOrigin ==
                PolicyFailureOrigin::None,
            "an applied policy has no failure origin");
    require(severityRaisedBy(run.summary, run.registry) == IS::Hard,
            "only the failing dependency may raise its own severity");
}

// A Recommended->B where BOTH fail: each raises its own severity.
void testRecommendedDependencyRaisesBothWhenBothFail() {
    using VS = ::fic::core::ViolationSeverity;
    using IS = ::fic::core::IncidentSeverity;

    const MatrixResult run = runMatrix(
        PolicyDependencyStrength::Recommended, VS::Isolate, VS::Soft,
        /*aFails=*/true, /*bFails=*/true);
    require(severityRaisedBy(run.summary, run.registry) == IS::Isolate,
            "both failures must raise max(X, Y)");
    require(result(run.summary, ref("a")).ownApplyAttempted,
            "a policy that failed on its own must report ownApplyAttempted");
    require(result(run.summary, ref("a")).failureOrigin ==
                PolicyFailureOrigin::OwnApplyFailure,
            "an own-apply failure must report OwnApplyFailure");
}

// A policy with violation severity NONE never contributes to incident state,
// even when it fails.
void testNoneSeverityNeverRaises() {
    using VS = ::fic::core::ViolationSeverity;
    using IS = ::fic::core::IncidentSeverity;

    const MatrixResult run = runMatrix(
        PolicyDependencyStrength::Required, VS::None, VS::None,
        /*aFails=*/true, /*bFails=*/true);
    require(severityRaisedBy(run.summary, run.registry) == IS::Unlocked,
            "NONE severities must never raise an incident");
}

// The full mandatory matrix X\\Y, verified row by row.
void testFullRequiredDependencyMatrix() {
    using VS = ::fic::core::ViolationSeverity;
    using IS = ::fic::core::IncidentSeverity;
    const std::vector<VS> levels = {VS::None, VS::Soft, VS::Standard,
                                    VS::Hard, VS::Isolate};
    for (const VS x : levels) {
        for (const VS y : levels) {
            const MatrixResult run = runMatrix(
                PolicyDependencyStrength::Required, x, y,
                /*aFails=*/false, /*bFails=*/true);
            const ::fic::core::IncidentSeverity expected =
                ::fic::core::maxIncidentSeverity(
                    x == VS::None ? IS::Unlocked
                                  : ::fic::core::violationSeverityToIncidentSeverity(x),
                    y == VS::None ? IS::Unlocked
                                  : ::fic::core::violationSeverityToIncidentSeverity(y));
            require(severityRaisedBy(run.summary, run.registry) == expected,
                    "required matrix cell X=" +
                        ::fic::core::violationSeverityToken(x) +
                        " Y=" + ::fic::core::violationSeverityToken(y) +
                        " must raise the max of the two");
        }
    }
}

// A disabled policy must never raise an incident, even when its result set
// says otherwise, because only ENABLED policies react.
void testDisabledPolicyDoesNotRaise() {
    using VS = ::fic::core::ViolationSeverity;
    using IS = ::fic::core::IncidentSeverity;

    SeverityFixture fixture;
    {
        std::ofstream config(fixture.configPath, std::ios::trunc);
        config << "_schema_version=1\n"
               << "a.status=ENABLE\na.violation_severity=ISOLATE\n"
               << "b.status=DISABLE\nb.violation_severity=HARD\n";
    }

    PolicyBehavior aBehavior;
    PolicyBehavior bBehavior;
    std::vector<std::string> order;
    const PolicyRef b = ref("b");
    PolicyList policies;
    policies.push_back(std::make_unique<SeverityPolicy>(b, bBehavior, order));
    policies.push_back(std::make_unique<SeverityPolicy>(
        ref("a"), aBehavior, order,
        std::vector<PolicyDependency>{{b, PolicyDependencyStrength::Required, {}}}));
    PolicyRegistry registry = buildRegistry(std::move(policies));

    PolicyExecutionRequest request;
    request.requestedRoots.push_back(ref("a"));
    const PolicyApplySummary summary =
        PolicyExecutionPlanner(registry).execute(request);
    // The DISABLED dependency itself never raises (it is not an enabled
    // failing policy). The enabled dependent A is Failed because its required
    // dependency was not applied, so A raises its OWN ISOLATE severity.
    require(result(summary, ref("b")).status == PolicyApplyStatus::Disabled,
            "a disabled policy must report Disabled");
    require(result(summary, ref("a")).status == PolicyApplyStatus::Failed,
            "a policy blocked by a disabled required dependency must fail");
    require(severityRaisedBy(summary, registry) == IS::Isolate,
            "only the enabled failing policy may raise, using its own severity");
}

void testIncidentModeDependency(const std::filesystem::path& root) {
    const PolicyRef mode{"GLOBAL", "lock_settings", "incident_response_mode"};
    const PolicyRef ssh{"NET", "SshEdit", "ssh_use_pam"};
    const auto scenario = [&](const std::string& status, const std::string& value,
                              bool sshEnabled, bool required) {
        std::ofstream(root / "config/GLOBAL.conf", std::ios::trunc)
            << "_schema_version=1\nincident_response_mode.status=" << status
            << "\nincident_response_mode.value=" << value << "\n";
        std::ofstream(root / "config/NET.conf", std::ios::trunc)
            << "_schema_version=1\nssh_use_pam.status="
            << (sshEnabled ? "ENABLE" : "DISABLE")
            << "\nssh_use_pam.value=1\n";
        PolicyBehavior sshBehavior;
        std::vector<std::string> order;
        PolicyList policies;
        policies.push_back(std::make_unique<TestPolicy>(ssh, sshBehavior, order));
        policies.push_back(std::make_unique<GLOBAL_incident_response_mode>());
        PolicyRegistry registry = buildRegistry(std::move(policies));
        const auto dependents = enabledRequiredDependents(registry, ssh);
        require((!dependents.empty()) == required,
                "response mode conditional Required dependency is wrong");
        const auto json = policyToJson("GLOBAL", "lock_settings",
            "incident_response_mode", *registry.findPolicy(mode));
        require((json.at("required_dependencies").size() == 1) == required,
                "response mode API dependency diagnostics are wrong");
        PolicyExecutionRequest request;
        request.requestedRoots.push_back(mode);
        const auto summary = PolicyExecutionPlanner(registry).execute(request);
        require((sshBehavior.calls == 1) == (required && sshEnabled),
                "response mode dependency apply ordering is wrong");
        if (required && !sshEnabled)
            require(result(summary, mode).status == PolicyApplyStatus::Failed,
                    "ACTIVE must fail when ssh_use_pam is disabled");
    };
    scenario("DISABLE", "ACTIVE", true, false);
    scenario("ENABLE", "PASSIVE", true, false);
    scenario("ENABLE", "ACTIVE", true, true);
    scenario("ENABLE", "ACTIVE", false, true);
}

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-policy-execution-planner-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "config");
    fs::create_directories(root / "log");

    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);

    try {
        testRequiredDependencies(root);
        testRecommendedDependencies(root);
        testConditionalDependencies(root);
        testConditionalExcludedModule(root);
        testDisabledDependentDoesNotExpand(root);
        testChains(root);
        testSharedDependencyAndBatchRoots(root);
        testDeterministicRootsAndFrozenMetadata(root);
        testExcludedModule(root);
        testGraphValidation(root);
        testEnabledRequiredDependentsGuard(root);
        testSudoDependencyGraphShape(root);
        testRequiredDependencyRaisesBothOwnSeverities();
        testRecommendedDependencyDoesNotRaiseTheDependent();
        testRecommendedDependencyRaisesBothWhenBothFail();
        testNoneSeverityNeverRaises();
        testFullRequiredDependencyMatrix();
        testDisabledPolicyDoesNotRaise();
        testIncidentModeDependency(root);
    } catch (...) {
        fs::remove_all(root);
        throw;
    }

    fs::remove_all(root);
    return 0;
}
