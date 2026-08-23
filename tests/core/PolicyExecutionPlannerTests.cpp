#include <fic/core/FicRuntimePaths.h>

#include "core/PolicyDependencyGraph.h"
#include "core/PolicyApplication.h"
#include "core/PolicyExecutionPlanner.h"
#include "core/PolicyRegistryInitialization.h"

#include <algorithm>
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

class TestPolicy final : public Policy {
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
        for (const PolicyDependency& dependency : dependencies) {
            if (dependency.strength == PolicyDependencyStrength::Required) {
                addRequiredDependency(dependency.policy);
            } else {
                addRecommendedDependency(dependency.policy);
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

PolicyDependency required(const PolicyRef& dependency) {
    return {dependency, PolicyDependencyStrength::Required};
}

PolicyDependency recommended(const PolicyRef& dependency) {
    return {dependency, PolicyDependencyStrength::Recommended};
}

void writeModuleConfig(
    const std::filesystem::path& root,
    const std::string& module,
    const std::map<std::string, bool>& enabled) {
    std::ofstream output(root / "config" / (module + ".conf"), std::ios::trunc);
    output << "_schema_version=1\n";
    for (const auto& [policy, isEnabled] : enabled) {
        output << policy << ".status="
               << (isEnabled ? "ENABLE" : "DISABLE") << '\n';
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

    PolicyList mixedTarget;
    mixedTarget.push_back(std::make_unique<TestPolicy>(
        ref("a"), a, order,
        std::vector<PolicyDependency>{required(ref("b")), recommended(ref("b"))}));
    mixedTarget.push_back(std::make_unique<TestPolicy>(ref("b"), b, order));
    expectInvalid(
        std::move(mixedTarget), "both Required and Recommended");

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
    require(a.calls == 0 && b.calls == 0 && c.calls == 0,
            "invalid graph executed a policy");
}

} // namespace

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
        testDisabledDependentDoesNotExpand(root);
        testChains(root);
        testSharedDependencyAndBatchRoots(root);
        testDeterministicRootsAndFrozenMetadata(root);
        testExcludedModule(root);
        testGraphValidation(root);
    } catch (...) {
        fs::remove_all(root);
        throw;
    }

    fs::remove_all(root);
    return 0;
}
