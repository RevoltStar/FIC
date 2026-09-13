#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

using fic::identity::pam::PamAuthUpdateTopologyManager;
using fic::identity::pam::PamAuthUpdateTopologyManagerOptions;
using fic::identity::pam::PamConfiguration;
using fic::identity::pam::PamEffectiveStack;
using fic::identity::pam::PamTopologyManager;
using fic::platform::PamFaillockStrategy;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

class TestTree {
public:
    TestTree() {
        std::string pattern =
            (fs::temp_directory_path() / "fic-pam-auth-update-XXXXXX").string();
        char* created = ::mkdtemp(pattern.data());
        require(created != nullptr, "mkdtemp failed");
        root = created;
        fs::create_directories(root / "pam.d");
        fs::create_directories(root / "security");
        fs::create_directories(root / "var/lib/pam");
        fs::create_directories(root / "etc/pam.d");
        writeFile(root / "security/pam_faillock.so", "fixture\n", 0555);
        writeFile(root / "security/pam_unix.so", "fixture\n", 0555);
        writeFile(root / "security/pam_sss.so", "fixture\n", 0555);
        writeFile(root / "security/pam_tcb.so", "fixture\n", 0555);
        writeFile(root / "pam.d/common-auth", kClean);
        writeFile(root / "pam.d/common-account", "account required pam_unix.so\n");
    }

    ~TestTree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    static void writeFile(const fs::path& path, const std::string& content,
                          mode_t mode = 0644) {
        fs::create_directories(path.parent_path());
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output.is_open()) {
            throw std::runtime_error("cannot write " + path.string());
        }
        output << content;
        output.close();
        ::chmod(path.c_str(), mode);
    }

    fs::path root;
    fs::path authFile() const { return root / "pam.d/common-auth"; }
    fs::path stateDir() const { return root / "var/lib/pam"; }

    fic::platform::PamPlatformConfig platform(
        const std::vector<std::string>& services = {"common-auth"}) const {
        fic::platform::PamPlatformConfig platform;
        platform.configDirectories = {root / "pam.d"};
        platform.moduleDirectories = {root / "security"};
        platform.scopes = {
            {fic::platform::PamScope::EffectiveAuthenticationStack, services},
            {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
        platform.capabilities = {
            {fic::platform::PamCapability::AuthenticationLockout,
             fic::platform::PamProviderKind::PamFaillock,
             fic::platform::PamScope::EffectiveAuthenticationStack,
             root / "security/faillock.conf",
             fic::platform::PamTopologyStrategyKind::PamAuthUpdate}};
        platform.capabilities.front().supportedFaillockStrategies = {
            PamFaillockStrategy::PreauthRequired,
            PamFaillockStrategy::PreauthRequisite,
            PamFaillockStrategy::Authsucc};
        platform.capabilities.front().defaultFaillockStrategy =
            PamFaillockStrategy::PreauthRequired;
        platform.capabilities.front().strategyActivations = {
            {PamFaillockStrategy::PreauthRequisite,
             {"fic-faillock-notify", "fic-faillock-authfail"}},
            {PamFaillockStrategy::PreauthRequired,
             {"fic-faillock-preauth-required", "fic-faillock-authfail"}},
            {PamFaillockStrategy::Authsucc,
             {"fic-faillock-authsucc", "fic-faillock-authfail"}}};
        return platform;
    }

    static const char* kClean;
};

const char* TestTree::kClean =
    "auth [success=1 default=ignore] pam_unix.so nullok\n"
    "auth requisite pam_deny.so\n"
    "auth required pam_permit.so\n";

struct FakePamAuthUpdate {
    int calls = 0;
    bool failWithoutChanges = false;
    bool partialWriteThenFail = false;
    bool applyWrongStrategy = false;
    bool corruptAfterApply = false;
    bool sabotageRollback = false;
    std::vector<std::string> lastArguments;
    std::optional<PamFaillockStrategy> applied;
};

std::string strategyContent(PamFaillockStrategy strategy,
                            const TestTree& tree) {
    const std::string conf = " conf=" +
        (tree.root / "security/faillock.conf").string();
    switch (strategy) {
    case PamFaillockStrategy::PreauthRequisite:
        return "auth requisite pam_faillock.so preauth" + conf + "\n" +
               "auth [success=2 default=ignore] pam_unix.so nullok\n"
               "auth [default=die] pam_faillock.so authfail" + conf + "\n" +
               "auth requisite pam_deny.so\n"
               "auth required pam_permit.so\n"
               "account required pam_faillock.so" + conf + "\n" +
               "account required pam_unix.so\n";
    case PamFaillockStrategy::PreauthRequired:
        return "auth required pam_faillock.so preauth" + conf + "\n" +
               "auth [success=2 default=ignore] pam_unix.so nullok\n"
               "auth [default=die] pam_faillock.so authfail" + conf + "\n" +
               "auth requisite pam_deny.so\n"
               "auth required pam_permit.so\n"
               "account required pam_faillock.so" + conf + "\n" +
               "account required pam_unix.so\n";
    case PamFaillockStrategy::Authsucc:
        return "auth [success=2 default=ignore] pam_unix.so nullok\n"
               "auth [default=die] pam_faillock.so authfail" + conf + "\n" +
               "auth requisite pam_deny.so\n"
               "auth required pam_permit.so\n"
               "auth required pam_faillock.so authsucc" + conf + "\n";
    }
    throw std::runtime_error("unknown strategy");
}

std::vector<std::string> strategyIds(PamFaillockStrategy strategy) {
    switch (strategy) {
    case PamFaillockStrategy::PreauthRequisite:
        return {"fic-faillock-notify", "fic-faillock-authfail"};
    case PamFaillockStrategy::PreauthRequired:
        return {"fic-faillock-preauth-required", "fic-faillock-authfail"};
    case PamFaillockStrategy::Authsucc:
        return {"fic-faillock-authsucc", "fic-faillock-authfail"};
    }
    throw std::runtime_error("unknown strategy");
}

// Simulated pam-auth-update: applies the combined --disable/--enable
// selection, rewrites the effective stack and the state database.
ProcessResult runFakePamAuthUpdate(FakePamAuthUpdate& fake,
                                   const TestTree& tree,
                                   const std::string& executable,
                                   const std::vector<std::string>& arguments,
                                   const ProcessOptions&) {
    ++fake.calls;
    fake.lastArguments = arguments;
    ProcessResult result;
    result.started = true;
    if (fake.failWithoutChanges) {
        result.exitCode = 1;
        result.standardError = "injected pam-auth-update failure";
        return result;
    }
    std::vector<std::string> enableIds;
    bool collecting = false;
    for (const std::string& argument : arguments) {
        if (argument == "--enable") {
            collecting = true;
            continue;
        }
        if (argument.rfind("--", 0) == 0) {
            collecting = false;
            continue;
        }
        if (collecting) {
            enableIds.push_back(argument);
        }
    }
    std::optional<PamFaillockStrategy> requested;
    for (PamFaillockStrategy strategy : {
             PamFaillockStrategy::PreauthRequisite,
             PamFaillockStrategy::PreauthRequired,
             PamFaillockStrategy::Authsucc}) {
        std::vector<std::string> ids = strategyIds(strategy);
        if (ids == enableIds) {
            requested = strategy;
        }
    }
    if (!requested.has_value()) {
        result.exitCode = 1;
        return result;
    }
    PamFaillockStrategy appliedStrategy = *requested;
    if (fake.applyWrongStrategy) {
        appliedStrategy = appliedStrategy == PamFaillockStrategy::Authsucc
            ? PamFaillockStrategy::PreauthRequisite
            : PamFaillockStrategy::Authsucc;
    }
    TestTree::writeFile(tree.authFile(), strategyContent(appliedStrategy, tree));
    std::string stateContent;
    for (const std::string& id : strategyIds(appliedStrategy)) {
        stateContent += "Module: " + id + "\n";
    }
    TestTree::writeFile(tree.stateDir() / "auth", stateContent);
    TestTree::writeFile(tree.stateDir() / "account", stateContent);
    if (fake.corruptAfterApply) {
        // Break strategy provability after the mutation, as if the
        // generated stack was inconsistent.
        TestTree::writeFile(
            tree.authFile(),
            strategyContent(appliedStrategy, tree) +
                "auth required pam_faillock.so preauth\n");
    }
    if (fake.partialWriteThenFail || fake.sabotageRollback) {
        if (fake.sabotageRollback) {
            fs::remove(tree.authFile());
            fs::create_directories(tree.authFile());
        }
        result.exitCode = 1;
        result.standardError = "injected pam-auth-update failure";
        return result;
    }
    fake.applied = appliedStrategy;
    result.exitCode = 0;
    return result;
}

// The resolver requires the platform to declare the pam-auth-update
// executable; tests point it at a fake script location.
fic::platform::PlatformExecutableResolver fakeResolver(const TestTree& tree) {
    const fs::path pamAuthUpdate = tree.root / "bin/pam-auth-update";
    TestTree::writeFile(pamAuthUpdate, "#!/bin/sh\nexit 0\n", 0755);
    fic::platform::PlatformExecutables executableConfig;
    executableConfig.entries = {
        {fic::platform::ExecutableId::PamAuthUpdate, {pamAuthUpdate}}};
    return fic::platform::PlatformExecutableResolver(
        executableConfig, {.enforceTrustedOwnership = false});
}

PamAuthUpdateTopologyManagerOptions makeOptions(
    const TestTree& tree, FakePamAuthUpdate& fake) {
    PamAuthUpdateTopologyManagerOptions options;
    options.stateDirectory = tree.stateDir();
    options.configDirectory = tree.root / "pam.d";
    options.runner = [&fake, &tree](
        const std::string& executable,
        const std::vector<std::string>& arguments,
        const ProcessOptions& processOptions) {
        return runFakePamAuthUpdate(
            fake, tree, executable, arguments, processOptions);
    };
    return options;
}

std::optional<PamFaillockStrategy> detectedStrategy(const TestTree& tree,
                                                    std::string& error) {
    auto platform = tree.platform();
    PamConfiguration configuration(platform);
    PamEffectiveStack stack;
    if (!configuration.buildEffectiveStack(
            "common-auth", fic::identity::pam::PamManagementGroup::Auth,
            stack, error)) {
        return std::nullopt;
    }
    return fic::identity::pam::detectPamFaillockStrategy(stack, error);
}

void resetTree(const TestTree& tree) {
    TestTree::writeFile(tree.authFile(), TestTree::kClean);
    TestTree::writeFile(
        tree.root / "pam.d/common-account", "account required pam_unix.so\n");
    std::error_code ignored;
    fs::remove(tree.stateDir() / "auth", ignored);
    fs::remove(tree.stateDir() / "account", ignored);
}

const std::vector<PamFaillockStrategy> kStrategies = {
    PamFaillockStrategy::PreauthRequisite,
    PamFaillockStrategy::PreauthRequired,
    PamFaillockStrategy::Authsucc};

void testEnableFromDisabledAndIdempotency(const TestTree& tree) {
    FakePamAuthUpdate fake;
    auto platform = tree.platform();
    fic::platform::PlatformExecutableResolver resolver = fakeResolver(tree);
    PamAuthUpdateTopologyManager manager(
        platform, platform.capabilities.front(), {"common-auth"}, resolver,
        makeOptions(tree, fake));
    std::string error;
    require(manager.enableStrategy(PamFaillockStrategy::PreauthRequired,
                                   error),
            error);
    require(fake.calls == 1, "activation used more than one invocation");
    require(fake.lastArguments == std::vector<std::string>{
                "--disable", "fic-faillock-notify",
                "fic-faillock-authsucc", "--enable",
                "fic-faillock-preauth-required", "fic-faillock-authfail"},
            "activation from a clean state did not use one reset+enable call");
    require(readFile(tree.authFile()) ==
                strategyContent(PamFaillockStrategy::PreauthRequired, tree),
            "activation did not generate the requested strategy stack");
    PamTopologyManager& topology = manager;
    fic::identity::pam::PamTopologyStatus status;
    require(topology.inspect(status, error) &&
                status.state == fic::identity::pam::PamTopologyState::Enabled &&
                status.manageable &&
                status.activeStrategy ==
                    PamFaillockStrategy::PreauthRequired,
            error);
    // Idempotency: no second invocation, byte-identical files.
    const std::string before = readFile(tree.authFile());
    require(manager.enableStrategy(PamFaillockStrategy::PreauthRequired,
                                   error),
            error);
    require(fake.calls == 1,
            "idempotent re-application invoked pam-auth-update");
    require(readFile(tree.authFile()) == before,
            "idempotent re-application changed the stack");
}

void testSixPairwiseTransitions(const TestTree& tree) {
    for (PamFaillockStrategy from : kStrategies) {
        for (PamFaillockStrategy to : kStrategies) {
            if (from == to) {
                continue;
            }
            resetTree(tree);
            FakePamAuthUpdate fake;
            auto platform = tree.platform();
            fic::platform::PlatformExecutableResolver resolver =
                fakeResolver(tree);
            PamAuthUpdateTopologyManager manager(
                platform, platform.capabilities.front(), {"common-auth"},
                resolver, makeOptions(tree, fake));
            std::string error;
            // Enable the source strategy first (from the clean stack).
            require(manager.enableStrategy(from, error),
                std::string("enable ") + fic::platform::pamFaillockStrategyName(from) + ": " + error);
            const std::string sourceStack = readFile(tree.authFile());
            require(sourceStack == strategyContent(from, tree),
                    "source strategy stack mismatch");
            // Transition to the target strategy.
            require(manager.enableStrategy(to, error),
                std::string("transition ") + fic::platform::pamFaillockStrategyName(from) + " -> " + fic::platform::pamFaillockStrategyName(to) + ": " + error);
            require(fake.calls == 2,
                    "transition used more than one invocation");
            require(fake.lastArguments.front() == "--disable",
                    "transition did not reset the previous strategy");
            require(readFile(tree.authFile()) == strategyContent(to, tree),
                    "transition did not generate the requested strategy");
            std::string detectionError;
            auto strategy = detectedStrategy(tree, detectionError);
            require(strategy == to,
                    "transitioned topology does not prove the requested "
                    "strategy: " + detectionError);
            // Idempotency after the transition.
            const std::string before = readFile(tree.authFile());
            require(manager.enableStrategy(to, error), error);
            require(fake.calls == 2 && readFile(tree.authFile()) == before,
                    "post-transition idempotency failed");
        }
    }
}

void testEnableFailureRollsBack(const TestTree& tree) {
    // pam-auth-update fails after partially writing the new strategy: the
    // transaction must restore the exact previous state.
    resetTree(tree);
    FakePamAuthUpdate fake;
    auto platform = tree.platform();
    fic::platform::PlatformExecutableResolver resolver = fakeResolver(tree);
    PamAuthUpdateTopologyManager manager(
        platform, platform.capabilities.front(), {"common-auth"}, resolver,
        makeOptions(tree, fake));
    std::string error;
    require(manager.enableStrategy(PamFaillockStrategy::PreauthRequisite,
                                   error),
            error);
    const std::string original = readFile(tree.authFile());
    const std::string originalState = readFile(tree.stateDir() / "auth");
    fake.partialWriteThenFail = true;
    require(!manager.enableStrategy(PamFaillockStrategy::Authsucc, error),
            "failing mutation was accepted");
    require(error.find("original PAM configuration restored") !=
                std::string::npos,
            "rollback was not reported: " + error);
    require(readFile(tree.authFile()) == original,
            "rollback did not restore the previous stack");
    require(readFile(tree.stateDir() / "auth") == originalState,
            "rollback did not restore the profile selection");
    std::string detectionError;
    require(detectedStrategy(tree, detectionError) ==
                PamFaillockStrategy::PreauthRequisite,
            "rollback did not restore the previous strategy");
}

void testPostconditionFailuresRollBack(const TestTree& tree) {
    // The mutation reports success but the generated topology cannot prove
    // the requested strategy: rollback must restore the original state.
    resetTree(tree);
    FakePamAuthUpdate fake;
    auto platform = tree.platform();
    fic::platform::PlatformExecutableResolver resolver = fakeResolver(tree);
    PamAuthUpdateTopologyManager manager(
        platform, platform.capabilities.front(), {"common-auth"}, resolver,
        makeOptions(tree, fake));
    std::string error;
    require(manager.enableStrategy(PamFaillockStrategy::PreauthRequired,
                                   error),
            error);
    const std::string original = readFile(tree.authFile());
    fake.corruptAfterApply = true;
    require(!manager.enableStrategy(PamFaillockStrategy::Authsucc, error),
            "postcondition failure was accepted");
    require(error.find("original PAM configuration restored") !=
                std::string::npos,
            "rollback was not reported: " + error);
    require(readFile(tree.authFile()) == original,
            "postcondition rollback did not restore the stack");
    require(detectedStrategy(tree, error) ==
                PamFaillockStrategy::PreauthRequired,
            error);

    // Wrong strategy after the mutation: rollback must restore.
    fake.corruptAfterApply = false;
    fake.applyWrongStrategy = true;
    require(!manager.enableStrategy(PamFaillockStrategy::Authsucc, error),
            "wrong strategy after mutation was accepted");
    require(readFile(tree.authFile()) == original,
            "wrong-strategy rollback did not restore the stack");
    fake.applyWrongStrategy = false;
}

void testRollbackFailureIsCritical(const TestTree& tree) {
    resetTree(tree);
    FakePamAuthUpdate fake;
    auto platform = tree.platform();
    fic::platform::PlatformExecutableResolver resolver = fakeResolver(tree);
    PamAuthUpdateTopologyManager manager(
        platform, platform.capabilities.front(), {"common-auth"}, resolver,
        makeOptions(tree, fake));
    std::string error;
    require(manager.enableStrategy(PamFaillockStrategy::PreauthRequired,
                                   error),
            error);
    // Sabotage the mutation so that the rollback itself cannot restore the
    // original file (the target path is replaced by a directory).
    fake.sabotageRollback = true;
    require(!manager.enableStrategy(PamFaillockStrategy::Authsucc, error),
            "sabotaged mutation was accepted");
    require(error.find("CRITICAL") != std::string::npos &&
                error.find("PAM configuration may be inconsistent") !=
                    std::string::npos,
            "rollback failure was not reported as critical: " + error);
    fs::remove_all(tree.authFile());
}

void testExternalTopologyIsNotMutated(const TestTree& tree) {
    // An administrator-configured faillock topology without FIC profile
    // selection is external: inspectable, not mutable.
    const std::string conf = " conf=" +
        (tree.root / "security/faillock.conf").string();
    TestTree::writeFile(tree.authFile(),
                        "auth required pam_faillock.so preauth" + conf + "\n" +
                        "auth [success=2 default=ignore] pam_unix.so nullok\n"
                        "auth [default=die] pam_faillock.so authfail" + conf +
                        "\n"
                        "auth requisite pam_deny.so\n"
                        "auth required pam_permit.so\n"
                        "account required pam_faillock.so" + conf + "\n"
                        "account required pam_unix.so\n");
    fs::remove(tree.stateDir() / "auth");
    fs::remove(tree.stateDir() / "account");
    FakePamAuthUpdate fake;
    auto platform = tree.platform();
    fic::platform::PlatformExecutableResolver resolver = fakeResolver(tree);
    PamAuthUpdateTopologyManager manager(
        platform, platform.capabilities.front(), {"common-auth"}, resolver,
        makeOptions(tree, fake));
    std::string error;
    fic::identity::pam::PamTopologyStatus status;
    require(manager.inspect(status, error) &&
                status.state == fic::identity::pam::PamTopologyState::Enabled &&
                !status.manageable,
            "external topology was not recognized as unmanaged");
    require(!manager.canEnableStrategy(PamFaillockStrategy::Authsucc, error) &&
                error.find("external") != std::string::npos,
            "external topology was not refused: " + error);
    require(!manager.enableStrategy(PamFaillockStrategy::Authsucc, error),
            "external topology was mutated");
    require(fake.calls == 0, "refused transition invoked pam-auth-update");
    // Restore the clean stack for the following tests.
    TestTree::writeFile(tree.authFile(), TestTree::kClean);
    std::error_code ignored;
    fs::remove(tree.stateDir() / "auth", ignored);
    fs::remove(tree.stateDir() / "account", ignored);
}

void testConflictingStrategiesAcrossServices(const TestTree& tree) {
    resetTree(tree);
    TestTree::writeFile(tree.authFile(),
                        strategyContent(PamFaillockStrategy::PreauthRequired,
                                        tree));
    TestTree::writeFile(tree.root / "pam.d/sshd",
                        strategyContent(PamFaillockStrategy::Authsucc, tree));
    std::string stateContent;
    for (const std::string& id :
         strategyIds(PamFaillockStrategy::PreauthRequired)) {
        stateContent += "Module: " + id + "\n";
    }
    TestTree::writeFile(tree.stateDir() / "auth", stateContent);
    TestTree::writeFile(tree.stateDir() / "account", stateContent);
    FakePamAuthUpdate fake;
    auto platform = tree.platform({"common-auth", "sshd"});
    fic::platform::PlatformExecutableResolver resolver = fakeResolver(tree);
    PamAuthUpdateTopologyManager manager(
        platform, platform.capabilities.front(), {"common-auth", "sshd"},
        resolver, makeOptions(tree, fake));
    std::string error;
    fic::identity::pam::PamTopologyStatus status;
    require(!manager.inspect(status, error) &&
                status.state == fic::identity::pam::PamTopologyState::Broken &&
                error.find("conflicting pam_faillock strategies") !=
                    std::string::npos,
            "conflicting strategies across services were not rejected: " +
                error);
    require(!manager.enableStrategy(PamFaillockStrategy::Authsucc, error),
            "broken topology was mutated");
    resetTree(tree);
    fs::remove(tree.root / "pam.d/sshd");
}

void testPartialProfileSelectionIsBroken(const TestTree& tree) {
    // Only one of the two recipe profiles is selected: the selection does
    // not match any declared recipe and must fail closed.
    resetTree(tree);
    TestTree::writeFile(tree.authFile(),
                        strategyContent(PamFaillockStrategy::PreauthRequired,
                                        tree));
    TestTree::writeFile(tree.stateDir() / "auth",
                        "Module: fic-faillock-preauth-required\n");
    std::error_code ignored;
    fs::remove(tree.stateDir() / "account", ignored);
    FakePamAuthUpdate fake;
    auto platform = tree.platform();
    fic::platform::PlatformExecutableResolver resolver = fakeResolver(tree);
    PamAuthUpdateTopologyManager manager(
        platform, platform.capabilities.front(), {"common-auth"}, resolver,
        makeOptions(tree, fake));
    std::string error;
    fic::identity::pam::PamTopologyStatus status;
    require(!manager.inspect(status, error) &&
                status.state == fic::identity::pam::PamTopologyState::Broken,
            "partial FIC profile selection was accepted");
    require(!manager.enableStrategy(PamFaillockStrategy::Authsucc, error),
            "partial selection topology was mutated");
    require(fake.calls == 0, "broken topology invoked pam-auth-update");
    resetTree(tree);
}

} // namespace

int main() {
    const auto paths = fic::core::FicProductPaths::production();
    std::string pathsError;
    if (!fic::core::FicRuntimePaths::initialize(paths, pathsError)) {
        std::cerr << "FicRuntimePaths::initialize failed: " << pathsError
                  << '\n';
        return EXIT_FAILURE;
    }
    try {
        TestTree tree;
        testEnableFromDisabledAndIdempotency(tree);
        testSixPairwiseTransitions(tree);
        testEnableFailureRollsBack(tree);
        testPostconditionFailuresRollBack(tree);
        testRollbackFailureIsCritical(tree);
        testExternalTopologyIsNotMutated(tree);
        testConflictingStrategiesAcrossServices(tree);
        testPartialProfileSelectionIsBroken(tree);
    } catch (const std::exception& exception) {
        std::cerr << "PamAuthUpdateTopologyManagerTests failed: "
                  << exception.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "PamAuthUpdateTopologyManagerTests passed\n";
    return EXIT_SUCCESS;
}
