// Production SSH MFA dependency-contract tests (D13-3C follow-up).
//
// The previous follow-up covered the planner with artificial TestPolicy
// dependencies; the original regression lived in the real Ssh constructor's
// platform-dependent dependency declaration. These tests therefore exercise
// the REAL ordinary SSH policy classes and the REAL Debian 12/13 profile
// sources:
//   * Debian 12 shares SshApplyContract::DebianVerified with Debian 13 but
//     does not register NET/SshEdit/ssh_mfa_required; declaring the
//     Recommended dependency there failed validatePolicyDependencyGraph()
//     and blocked daemon initialization.
//   * Debian 13 must declare the Recommended
//     BackendRequiresCapability("ssh_mfa") dependency on ssh_mfa_required so
//     MFA is applied before ordinary SSH policies in one batch pass.
//   * Only the literal ssh_mfa_required.status=DISABLE skips the conditional
//     dependency; a missing/empty/unknown status keeps it (fail closed).
//
// No policy apply() is ever invoked here: the planner runs with a recording
// OwnExecutor and direct probes only read the module configuration, so no
// sshd configuration, journal or service state is touched.
#include "modules/net/ssh/Ssh.h"
#include "modules/net/ssh/policies/NET_ssh_port.h"
#include "modules/net/ssh/policies/NET_ssh_max_auth_tries.h"
#include "modules/net/ssh/policies/NET_ssh_root_login.h"
#include "modules/net/ssh/policies/NET_ssh_pubkey_auth.h"
#include "modules/net/ssh/policies/NET_ssh_use_pam.h"
#include "modules/net/ssh/SshMfaPolicy.h"
#include "policy/execution/PolicyDependencyGraph.h"
#include "policy/execution/PolicyExecutionPlanner.h"
#include "policy/registry/PolicyRegistryInitialization.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/policy/PolicyApplyResult.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace fic::platform {
// Both production Debian profile sources are compiled into this test target
// with -DmakeBuildPlatformProfile=<name>, so both real profiles are
// available here regardless of the FIC_TARGET_PLATFORM the build was
// configured with (only one profile can be the build platform).
PlatformProfile makeDebian12ProfileForTest();
PlatformProfile makeDebian13ProfileForTest();
} // namespace fic::platform

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempTree {
public:
    TempTree(const std::string& pattern) {
        char* created = ::mkdtemp(const_cast<char*>(pattern.data()));
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = created;
    }

    ~TempTree() {
        std::error_code ignored;
        std::filesystem::permissions(root,
            std::filesystem::perms::owner_all, ignored);
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path root;
};

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        throw std::runtime_error("could not create " + path.string());
    }
    stream << content;
}

const char* kSshPolicyNames[] = {
    "ssh_port", "ssh_max_auth_tries", "ssh_root_login",
    "ssh_pubkey_auth", "ssh_use_pam"};

std::unique_ptr<Ssh> makeSshPolicy(
    const std::string& policyName,
    const fic::platform::SshPlatformConfig& config,
    const fic::platform::PlatformExecutableResolver& executables) {
    if (policyName == "ssh_port")
        return std::make_unique<NET_ssh_port>(config, executables);
    if (policyName == "ssh_max_auth_tries")
        return std::make_unique<NET_ssh_max_auth_tries>(config, executables);
    if (policyName == "ssh_root_login")
        return std::make_unique<NET_ssh_root_login>(config, executables);
    if (policyName == "ssh_pubkey_auth")
        return std::make_unique<NET_ssh_pubkey_auth>(config, executables);
    if (policyName == "ssh_use_pam")
        return std::make_unique<NET_ssh_use_pam>(config, executables);
    throw std::runtime_error("unknown SSH policy: " + policyName);
}

// Recording executor: never runs the real apply(); the tests drive the
// production planner to prove dependency expansion/order/warning behavior.
PolicyExecutionPlanner::OwnExecutor recordingExecutor(
    std::vector<std::string>& order) {
    return [&order](const PolicyRef& ref, Policy&) ->
        std::optional<PolicyApplyResult> {
        order.push_back(ref.policyName);
        PolicyApplyResult result{
            ref.moduleName, ref.submoduleName, ref.policyName,
            PolicyApplyStatus::Applied, "recorded by test executor"};
        result.ownApplyAttempted = true;
        return result;
    };
}

const PolicyApplyResult& result(
    const PolicyApplySummary& summary, const PolicyRef& policy) {
    for (const PolicyApplyResult& candidate : summary.getResults()) {
        if (PolicyRef{candidate.moduleName, candidate.submoduleName,
                      candidate.policyName} == policy) {
            return candidate;
        }
    }
    throw std::runtime_error(
        "missing result for " + formatPolicyRef(policy));
}

bool hasResult(const PolicyApplySummary& summary, const PolicyRef& policy) {
    for (const PolicyApplyResult& candidate : summary.getResults()) {
        if (PolicyRef{candidate.moduleName, candidate.submoduleName,
                      candidate.policyName} == policy) {
            return true;
        }
    }
    return false;
}

// Fixture: temp sshd_config plus a resolver that is never invoked (no real
// apply runs) and NET.conf written per scenario into the test config dir.
struct SshFixture {
    TempTree tree;
    std::unique_ptr<fic::platform::PlatformExecutableResolver> executables;

    SshFixture() : tree("/tmp/fic-ssh-mfa-dep-XXXXXX") {
        fic::platform::PlatformExecutables empty;
        fic::platform::PlatformExecutableResolverOptions options;
        options.enforceTrustedOwnership = false;
        executables =
            std::make_unique<fic::platform::PlatformExecutableResolver>(
                std::move(empty), options);
        writeFile(tree.root / "sshd_config", "Port 22\n");
    }

    fic::platform::SshPlatformConfig sshConfigFromProfile(
        const fic::platform::PlatformProfile& profile) const {
        // Contract fields (applyContract, sshMfaRequiredSupported, units)
        // come from the real profile; filesystem paths are redirected to the
        // hermetic fixture tree.
        fic::platform::SshPlatformConfig config = profile.ssh;
        config.configPath = tree.root / "sshd_config";
        config.includeBasePath = tree.root;
        return config;
    }

    void writeNetConfig(const std::string& mfaStatusLine) const {
        const std::filesystem::path configDir =
            fic::core::FicRuntimePaths::get().configDir;
        std::filesystem::create_directories(configDir);
        std::ofstream out(configDir / "NET.conf", std::ios::trunc);
        out << "_schema_version=1\n";
        for (const char* name : kSshPolicyNames) {
            out << name << ".status=ENABLE\n" << name << ".value=1\n";
        }
        out << mfaStatusLine;
    }
};

// Exact MFA status semantics of the real Ssh::requiresDependencyCapability:
// only the literal DISABLE skips the ssh_mfa dependency; a missing key, an
// empty value and an unknown token keep it (fail closed).
void testSshMfaStatusSemantics() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeDebian13ProfileForTest();
    SshFixture fixture;
    const auto config = fixture.sshConfigFromProfile(profile);

    struct StatusCase {
        const char* netConfLine;
        const char* description;
        bool dependencyActive;
    };
    const StatusCase cases[] = {
        {"ssh_mfa_required.status=ENABLE\n", "ENABLE", true},
        {"ssh_mfa_required.status=DISABLE\n", "DISABLE", false},
        {"", "missing status key", true},
        {"ssh_mfa_required.status=\n", "empty status value", true},
        {"ssh_mfa_required.status=BROKEN\n", "unknown status token", true},
    };

    for (const StatusCase& c : cases) {
        fixture.writeNetConfig(c.netConfLine);
        for (const char* name : kSshPolicyNames) {
            const auto policy = makeSshPolicy(name, config, *fixture.executables);
            require(policy->supportsDependencyCapability("ssh_mfa"),
                    std::string(name) + " must support the ssh_mfa capability (" +
                        c.description + ")");
            require(policy->requiresDependencyCapability("ssh_mfa") ==
                        c.dependencyActive,
                    std::string(name) + " must " +
                        (c.dependencyActive ? "keep" : "skip") +
                        " the MFA dependency for status " + c.description);
            // Unknown capabilities never disable a dependency.
            require(policy->requiresDependencyCapability("unrelated") &&
                        !policy->supportsDependencyCapability("unrelated"),
                    std::string(name) +
                        " must fail closed for unknown capabilities");
        }
    }
}

// With the literal DISABLE status the conditional Recommended dependency is
// skipped by the production planner: MFA is never executed, produces no
// result and the ordinary SSH policy applies without any MFA warning.
void testSshMfaDisabledSkipsDependencyWithoutWarning() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeDebian13ProfileForTest();
    SshFixture fixture;
    fixture.writeNetConfig("ssh_mfa_required.status=DISABLE\n");
    const auto config = fixture.sshConfigFromProfile(profile);

    PolicyList policies;
    policies.push_back(std::make_unique<fic::ssh::SshMfaPolicy>());
    policies.push_back(
        std::make_unique<NET_ssh_port>(config, *fixture.executables));
    policies.push_back(std::make_unique<NET_ssh_max_auth_tries>(
        config, *fixture.executables));
    PolicyRegistry registry;
    std::string error;
    require(buildPolicyRegistry(std::move(policies), registry, error),
            "DISABLE registry build failed: " + error);

    const PolicyRef mfa{"NET", "SshEdit", "ssh_mfa_required"};
    std::vector<std::string> order;
    PolicyExecutionPlanner planner(registry, recordingExecutor(order));
    const PolicyApplySummary summary = planner.execute(
        {{PolicyRef{"NET", "SshEdit", "ssh_port"}}, {}});

    require(order == std::vector<std::string>({"ssh_port"}),
            "explicitly disabled MFA must not be executed by the planner");
    require(!hasResult(summary, mfa),
            "skipped conditional dependency must produce no MFA result");
    const PolicyApplyResult& port =
        result(summary, PolicyRef{"NET", "SshEdit", "ssh_port"});
    require(port.status == PolicyApplyStatus::Applied,
            "ssh_port must apply when MFA is explicitly disabled");
    for (const PolicyDiagnostic& diagnostic : port.diagnostics) {
        require(diagnostic.message.find("ssh_mfa_required") ==
                    std::string::npos,
                "false MFA warning on explicitly disabled MFA: " +
                    diagnostic.message);
    }
    require(!summary.hasFailures(),
            "explicitly disabled MFA must not fail the apply");
}

// Debian 12 (P1 regression): the real profile keeps DebianVerified but must
// not declare the MFA dependency, so the production registry builds and the
// dependency graph validates without the unregistered MFA policy.
void testSshMfaDebian12ProfileDependencies() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeDebian12ProfileForTest();
    require(profile.id == "debian-12", "expected the real Debian 12 profile");
    require(profile.ssh.applyContract ==
                fic::platform::SshApplyContract::DebianVerified,
            "Debian 12 must keep its DebianVerified apply contract");
    require(!profile.ssh.sshMfaRequiredSupported,
            "Debian 12 must not declare SSH MFA support");

    SshFixture fixture;
    // ssh_mfa_required is not a Debian 12 policy: no status key at all.
    fixture.writeNetConfig("");
    const auto config = fixture.sshConfigFromProfile(profile);

    PolicyList policies;
    for (const char* name : kSshPolicyNames) {
        policies.push_back(makeSshPolicy(name, config, *fixture.executables));
    }
    PolicyRegistry registry;
    std::string error;
    require(buildPolicyRegistry(std::move(policies), registry, error),
            "Debian 12 production registry must build: " + error);
    require(validatePolicyDependencyGraph(registry, error),
            "Debian 12 dependency graph must validate without MFA: " + error);

    const PolicyRef mfa{"NET", "SshEdit", "ssh_mfa_required"};
    require(registry.findPolicy(mfa) == nullptr,
            "ssh_mfa_required must not be registered on Debian 12");
    for (const PolicyRef& ref : registry.policyRefs()) {
        Policy* policy = registry.findPolicy(ref);
        require(policy != nullptr, "policy disappeared from registry");
        for (const PolicyDependency& dependency : policy->dependencies()) {
            require(dependency.policy != mfa,
                    "Debian 12 policy " + formatPolicyRef(ref) +
                        " must not depend on ssh_mfa_required");
        }
    }

    // Batch apply of every ordinary SSH policy: all executed in one pass,
    // no MFA policy involved anywhere in the results.
    std::vector<std::string> order;
    PolicyExecutionPlanner planner(registry, recordingExecutor(order));
    std::vector<PolicyRef> roots;
    for (const char* name : kSshPolicyNames) {
        roots.push_back(PolicyRef{"NET", "SshEdit", name});
    }
    const PolicyApplySummary summary = planner.execute({roots, {}});
    require(order.size() == 5,
            "every ordinary SSH policy must be executed exactly once");
    require(!hasResult(summary, mfa),
            "Debian 12 batch apply must not involve the MFA policy");
    require(summary.requestedRootsApplied(),
            "Debian 12 batch apply must apply all roots in one pass");
}

// Debian 13: the real profile declares SSH MFA support, every ordinary SSH
// policy carries the exact Recommended BackendRequiresCapability("ssh_mfa")
// edge, the production graph (including SshMfaPolicy) validates, batch apply
// executes MFA first in one pass, and the Recommended edges never block
// disabling MFA.
void testSshMfaDebian13ProfileDependencies() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeDebian13ProfileForTest();
    require(profile.id == "debian-13", "expected the real Debian 13 profile");
    require(profile.ssh.applyContract ==
                fic::platform::SshApplyContract::DebianVerified,
            "Debian 13 must keep its DebianVerified apply contract");
    require(profile.ssh.sshMfaRequiredSupported,
            "Debian 13 must declare SSH MFA support");

    SshFixture fixture;
    fixture.writeNetConfig("ssh_mfa_required.status=ENABLE\n");
    const auto config = fixture.sshConfigFromProfile(profile);

    PolicyList policies;
    policies.push_back(std::make_unique<fic::ssh::SshMfaPolicy>());
    for (const char* name : kSshPolicyNames) {
        policies.push_back(makeSshPolicy(name, config, *fixture.executables));
    }
    PolicyRegistry registry;
    std::string error;
    require(buildPolicyRegistry(std::move(policies), registry, error),
            "Debian 13 production registry must build: " + error);
    require(validatePolicyDependencyGraph(registry, error),
            "Debian 13 dependency graph must validate with MFA: " + error);

    const PolicyRef mfa{"NET", "SshEdit", "ssh_mfa_required"};
    require(registry.findPolicy(mfa) != nullptr,
            "ssh_mfa_required must be registered on Debian 13");
    for (const char* name : kSshPolicyNames) {
        const Policy* policy =
            registry.findPolicy(PolicyRef{"NET", "SshEdit", name});
        require(policy != nullptr, "policy missing: " + std::string(name));
        const PolicyDependency* mfaDependency = nullptr;
        for (const PolicyDependency& dependency : policy->dependencies()) {
            if (dependency.policy == mfa) {
                mfaDependency = &dependency;
            }
        }
        require(mfaDependency != nullptr,
                std::string(name) + " must declare the MFA dependency");
        require(mfaDependency->strength ==
                    PolicyDependencyStrength::Recommended,
                std::string(name) + " MFA dependency must be Recommended");
        require(mfaDependency->condition.type ==
                    PolicyDependencyConditionType::BackendRequiresCapability,
                std::string(name) +
                    " MFA dependency must be BackendRequiresCapability");
        require(mfaDependency->condition.value == "ssh_mfa",
                std::string(name) + " MFA dependency must gate on ssh_mfa");
    }

    // Recommended dependents never block disabling MFA.
    require(enabledRequiredDependents(registry, mfa).empty(),
            "ordinary SSH policies must not be required dependents of MFA");

    // Batch apply of every ordinary SSH policy with MFA enabled: MFA runs
    // first (exactly once), then every root in a single pass.
    std::vector<std::string> order;
    PolicyExecutionPlanner planner(registry, recordingExecutor(order));
    std::vector<PolicyRef> roots;
    for (const char* name : kSshPolicyNames) {
        roots.push_back(PolicyRef{"NET", "SshEdit", name});
    }
    const PolicyApplySummary summary = planner.execute({roots, {}});
    require(order.size() == 6,
            "batch apply must execute MFA once plus the five roots");
    require(order.front() == "ssh_mfa_required",
            "batch apply must execute ssh_mfa_required before ordinary "
            "SSH policies");
    require(result(summary, mfa).status == PolicyApplyStatus::Applied,
            "MFA must be applied in the same batch pass");
    require(summary.requestedRootsApplied(),
            "Debian 13 batch apply must apply all roots in one pass");
    require(!summary.hasFailures(), "Debian 13 batch apply must not fail");
}

} // namespace

int main() {
    // Policy::log() and ModuleConfigFileHandler require initialized FIC
    // runtime paths (logger output, module config directory).
    TempTree runtimeTree("/tmp/fic-ssh-mfa-runtime-XXXXXX");
    {
        auto paths = fic::core::FicProductPaths::production();
        paths.privateBinDir = runtimeTree.root / "bin";
        paths.configDir = runtimeTree.root / "config";
        paths.languageDir = runtimeTree.root / "lang";
        paths.logDir = runtimeTree.root / "log";
        paths.notifyDir = runtimeTree.root / "notify";
        paths.dataDir = runtimeTree.root / "data";
        paths.shareDir = runtimeTree.root / "share";
        paths.imageDir = runtimeTree.root / "image";
        paths.runtimeDir = runtimeTree.root / "run";
        paths.lockStatusFile = runtimeTree.root / "lockstatus";
        paths.commandHashFile = runtimeTree.root / "data/commandhash.txt";
        paths.deviceDatabaseFile = runtimeTree.root / "data/devices.db";
        paths.deviceDatabaseLockFile = runtimeTree.root / "log/devices.lock";
        paths.lockDebugLogFile = runtimeTree.root / "log/db-lock.log";
        std::filesystem::create_directories(paths.configDir);
        std::filesystem::create_directories(paths.logDir);
        std::filesystem::create_directories(paths.dataDir);
        writeFile(paths.configDir / "AUDIT.conf",
                  "_schema_version=1\n"
                  "log_level.status=ENABLE\n"
                  "log_level.value=ERROR\n");
        std::string error;
        if (!fic::core::FicRuntimePaths::initialize(paths, error)) {
            std::cerr << "FAIL: runtime paths initialization: " << error
                      << '\n';
            return 1;
        }
    }

    const struct {
        const char* name;
        void (*test)();
    } tests[] = {
        {"SSH MFA status semantics", testSshMfaStatusSemantics},
        {"SSH MFA DISABLE skips dependency without warning",
         testSshMfaDisabledSkipsDependencyWithoutWarning},
        {"SSH MFA Debian 12 profile dependencies",
         testSshMfaDebian12ProfileDependencies},
        {"SSH MFA Debian 13 profile dependencies",
         testSshMfaDebian13ProfileDependencies},
    };

    std::size_t failures = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "FAIL: " << name << ": " << exception.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}
