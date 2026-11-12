#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/incident/IncidentSeverity.h>

#include "policy/registry/PolicyRegistry.h"
#include "policy/registry/PolicyRegistryInitialization.h"
#include "policy/registry/PolicyRegistryMutation.h"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TestPolicy : public ::Policy {
public:
    TestPolicy(const std::string& module,
               const std::string& submodule,
               const std::string& policy)
    {
        moduleName = module;
        submoduleName = submodule;
        policyName = policy;
        policyTypeValue =
            std::make_unique<PossibleListPolicyTypeValue>(
                std::vector<std::string>{"0", "1"});
        moduleConf = std::make_unique<ModuleConfigFileHandler>(moduleName);
        if (!moduleConf->loadConfig()) {
            throw std::runtime_error("could not load test policy config");
        }
    }

    bool apply() override { return true; }
};
PolicyRef makeRef(const std::string& policy,
                  const std::string& module = "TEST",
                  const std::string& submodule = "test") {
    return {module, submodule, policy};
}

PolicyList makePolicies() {
    PolicyList policies;
    policies.push_back(std::make_unique<TestPolicy>("DAC", "test", "sudo_timeout"));
    policies.push_back(std::make_unique<TestPolicy>("DAC", "test", "other_policy"));
    return policies;
}

PolicyRegistry buildRegistry() {
    PolicyRegistry registry;
    std::string error;
    require(
        buildPolicyRegistry(makePolicies(), registry, error),
        "registry build failed: " + error);
    return registry;
}

std::string readConfigFile(const std::filesystem::path& configDir,
                           const std::string& module) {
    std::ifstream input(configDir / (module + ".conf"));
    require(input.is_open(), "could not open config file");
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

bool hasViolationSeverity(const std::filesystem::path& configDir,
                          const std::string& module,
                          const std::string& policy,
                          const std::string& expected) {
    const std::string content = readConfigFile(configDir, module);
    const std::string key = policy + ".violation_severity=";
    return content.find(key + expected) != std::string::npos;
}

bool hasStatus(const std::filesystem::path& configDir,
               const std::string& module,
               const std::string& policy,
               const std::string& expected) {
    const std::string content = readConfigFile(configDir, module);
    const std::string key = policy + ".status=";
    return content.find(key + expected) != std::string::npos;
}

bool hasValue(const std::filesystem::path& configDir,
              const std::string& module,
              const std::string& policy,
              const std::string& expected) {
    const std::string content = readConfigFile(configDir, module);
    const std::string key = policy + ".value=";
    return content.find(key + expected) != std::string::npos;
}

} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-policy-violation-severity-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "config");
    fs::create_directories(root / "log");

    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);

    const std::string module = "DAC";
    const std::string policy = "sudo_timeout";

    // Write initial config: policy enabled, value set, no violation_severity.
    {
        std::ofstream output(root / "config" / (module + ".conf"),
                             std::ios::trunc);
        output << "_schema_version=1\n";
        output << policy << ".status=ENABLE\n";
        output << policy << ".value=60\n";
    }

    // Test default: missing violation_severity falls back to compiled-in default.
    {
        PolicyRegistry registry = buildRegistry();
        const auto* found = registry.findPolicy(
            {"DAC", "test", "sudo_timeout"});
        require(found != nullptr, "policy should exist in registry");
        const auto eff = found->getViolationSeverity();
        require(eff == fic::core::ViolationSeverity::None,
                "default severity should be NONE when not configured");
    }

    // Test 1: successful save of each of the five values.
    for (const std::string& severity :
         {"NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"}) {
        PolicyRegistry registry = buildRegistry();
        std::string err;
        const bool ok = setPolicyViolationSeverity(
            registry, module, policy, severity, err);
        require(ok, "setPolicyViolationSeverity(" + severity + ") failed: " + err);
        require(err.empty(), "error should be empty on success");
        require(hasViolationSeverity(root / "config", module, policy, severity),
                "config should contain violation_severity=" + severity);
    }

    // Test 2: rejection of unknown severity value.
    {
        PolicyRegistry registry = buildRegistry();
        std::string err;
        const bool ok = setPolicyViolationSeverity(
            registry, module, policy, "BOGUS", err);
        require(!ok, "unknown severity should be rejected");
        require(!err.empty(), "error should be set for unknown severity");
    }

    // Test 3: rejection of empty severity value.
    {
        PolicyRegistry registry = buildRegistry();
        std::string err;
        const bool ok = setPolicyViolationSeverity(
            registry, module, policy, "", err);
        require(!ok, "empty severity should be rejected");
    }

    // Test 4: rejection for non-existent policy.
    {
        PolicyRegistry registry = buildRegistry();
        std::string err;
        const bool ok = setPolicyViolationSeverity(
            registry, module, "nonexistent_policy", "HARD", err);
        require(!ok, "non-existent policy should be rejected");
        require(!err.empty(), "error should be set for non-existent policy");
    }

    // Test 5: .status and .value remain unchanged.
    {
        PolicyRegistry registry = buildRegistry();
        std::string err;
        const bool ok = setPolicyViolationSeverity(
            registry, module, policy, "HARD", err);
        require(ok, "setPolicyViolationSeverity(HARD) failed: " + err);
        require(hasStatus(root / "config", module, policy, "ENABLE"),
                ".status should remain ENABLE");
        require(hasValue(root / "config", module, policy, "60"),
                ".value should remain 60");
    }

    // Test 6: saved severity survives re-reading the config.
    {
        PolicyRegistry registry = buildRegistry();
        std::string err;
        require(setPolicyViolationSeverity(
                    registry, module, policy, "ISOLATE", err),
                "setPolicyViolationSeverity(ISOLATE) failed: " + err);
        ModuleConfigFileHandler fresh(module);
        require(fresh.loadConfig(), "fresh config load failed");
        const auto severity = fresh.getPolicyViolationSeverity(policy);
        require(severity == fic::core::ViolationSeverity::Isolate,
                "re-read severity should be ISOLATE");
    }

    std::cout << "All PolicyViolationSeverityTests passed" << std::endl;
    return 0;
}