#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"
#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"
#include "modules/identity_access/pam/PamTopologyManagerFactory.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::filesystem::path& path,
               const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::trunc);
    require(stream.is_open(), "could not write " + path.string());
    stream << content;
}

fic::platform::PamPlatformConfig makePlatform(
    const std::filesystem::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.scopes = {
        {fic::platform::PamScope::EffectiveAuthenticationStack, {"login"}},
        {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
    platform.capabilities = {
        {fic::platform::PamCapability::AuthenticationLockout,
         fic::platform::PamProviderKind::PamFaillock,
         fic::platform::PamScope::EffectiveAuthenticationStack,
         root / "security/faillock.conf",
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate},
        {fic::platform::PamCapability::PasswordHistory,
         fic::platform::PamProviderKind::PamPwhistory,
         fic::platform::PamScope::EffectivePasswordStack,
         root / "security/pwhistory.conf",
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate},
        {fic::platform::PamCapability::PasswordQuality,
         fic::platform::PamProviderKind::PamPwquality,
         fic::platform::PamScope::EffectivePasswordStack,
         root / "security/pwquality.conf",
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate}};
    platform.capabilities[0].activationIdentifiers = {
        "fic-faillock-notify", "fic-faillock"};
    platform.capabilities[1].activationIdentifiers = {"fic-pwhistory"};
    platform.capabilities[2].activationIdentifiers = {"pwquality"};
    return platform;
}

struct ManagerState {
    int inspectCalls = 0;
    int canEnableCalls = 0;
    int enableCalls = 0;
    int disableCalls = 0;
    bool inspectResult = true;
    bool canEnableResult = true;
    bool enableResult = true;
    fic::identity::pam::PamTopologyState topologyState =
        fic::identity::pam::PamTopologyState::Disabled;
};

class FakeManager final : public fic::identity::pam::PamTopologyManager {
public:
    explicit FakeManager(std::shared_ptr<ManagerState> state)
        : state_(std::move(state)) {}

    bool inspect(fic::identity::pam::PamTopologyStatus& status,
                 std::string& error) override {
        ++state_->inspectCalls;
        status = {state_->topologyState, true, "fake topology"};
        error = state_->inspectResult ? "" : "inspection failed";
        return state_->inspectResult;
    }
    bool canEnable(std::string& error) const override {
        ++state_->canEnableCalls;
        error = state_->canEnableResult ? "" : "cannot enable";
        return state_->canEnableResult;
    }
    bool enable(std::string& error) override {
        ++state_->enableCalls;
        error = state_->enableResult ? "" : "enable failed";
        return state_->enableResult;
    }
    bool disable(std::string& error) override {
        ++state_->disableCalls;
        error.clear();
        return true;
    }

private:
    std::shared_ptr<ManagerState> state_;
};

PamCapabilityActivationPolicy makePolicy(
    const fic::platform::PamPlatformConfig& platform,
    fic::platform::PamCapability capability,
    const std::shared_ptr<ManagerState>& managerState,
    std::vector<bool> verificationResults,
    int& verifierCalls,
    fic::platform::PamCapability& factoryCapability) {
    auto results = std::make_shared<std::vector<bool>>(
        std::move(verificationResults));
    PamCapabilityActivationPolicyOptions options;
    options.verifier =
        [results, &verifierCalls](const auto&, const auto&,
                                  auto& verification) mutable {
            const std::size_t index = static_cast<std::size_t>(verifierCalls++);
            const bool result = index < results->size() && (*results)[index];
            verification.state = result
                ? fic::identity::pam::PamEnforcementState::Effective
                : fic::identity::pam::PamEnforcementState::Inactive;
            verification.detail = result ? "" : "inactive";
            return result;
        };
    options.managerFactory =
        [managerState, &factoryCapability](const auto& capabilityConfig,
                                           const auto&,
                                           std::string& error) {
            factoryCapability = capabilityConfig.capability;
            error.clear();
            return std::make_unique<FakeManager>(managerState);
        };
    return PamCapabilityActivationPolicy(platform, capability,
                                         std::move(options));
}

} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-pam-activation-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    try {
        auto paths = fic::core::FicProductPaths::production();
        paths.configDir = root / "config";
        paths.logDir = root / "log";
        paths.dataDir = root / "data";
        paths.runtimeDir = root / "run";
        paths.commandHashFile = root / "data/commandhash.txt";
        std::string error;
        require(fic::core::FicRuntimePaths::initialize(paths, error), error);
        writeFile(
            root / "config/IDENTITY_ACCESS.conf",
            "enable_authentication_lockout.status=ENABLE\n"
            "enable_authentication_lockout.value=ENABLE\n"
            "enable_password_history.status=ENABLE\n"
            "enable_password_history.value=ENABLE\n"
            "enable_password_quality.status=DISABLE\n"
            "enable_password_quality.value=ENABLE\n");
        const auto platform = makePlatform(root);

        auto state = std::make_shared<ManagerState>();
        int verifierCalls = 0;
        auto factoryCapability =
            fic::platform::PamCapability::PasswordQuality;
        auto alreadyEnabled = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {true, true}, verifierCalls, factoryCapability);
        require(alreadyEnabled.policyName == "enable_authentication_lockout" &&
                    alreadyEnabled.capability() ==
                        fic::platform::PamCapability::AuthenticationLockout &&
                    alreadyEnabled.apply() && alreadyEnabled.apply() &&
                    verifierCalls == 2 &&
                    state->inspectCalls == 0 && state->enableCalls == 0,
                "repeated already-enabled activation was not idempotent");

        state = std::make_shared<ManagerState>();
        verifierCalls = 0;
        auto activated = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {false, true, true}, verifierCalls, factoryCapability);
        require(activated.policyName == "enable_password_history" &&
                    activated.apply() && verifierCalls == 2 &&
                    factoryCapability ==
                        fic::platform::PamCapability::PasswordHistory &&
                    state->inspectCalls == 1 && state->canEnableCalls == 1 &&
                    state->enableCalls == 1 && state->disableCalls == 0,
                "disabled topology was not activated and freshly verified");

        state = std::make_shared<ManagerState>();
        verifierCalls = 0;
        auto invalidPostcondition = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {false, false}, verifierCalls, factoryCapability);
        require(!invalidPostcondition.apply() && state->enableCalls == 1 &&
                    state->disableCalls == 0,
                "invalid post-activation topology was accepted or disabled");

        state = std::make_shared<ManagerState>();
        state->enableResult = false;
        verifierCalls = 0;
        auto failedEnable = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {false}, verifierCalls, factoryCapability);
        require(!failedEnable.apply() && state->enableCalls == 1,
                "native activation failure was accepted");

        state = std::make_shared<ManagerState>();
        state->inspectResult = false;
        verifierCalls = 0;
        auto broken = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {false}, verifierCalls, factoryCapability);
        require(!broken.apply() && state->enableCalls == 0,
                "broken topology was mutated");

        state = std::make_shared<ManagerState>();
        verifierCalls = 0;
        auto disabled = makePolicy(
            platform, fic::platform::PamCapability::PasswordQuality,
            state, {false}, verifierCalls, factoryCapability);
        require(!disabled.isEnabled() && state->disableCalls == 0 &&
                    disabled.getDefaultValue() == "ENABLE",
                "disabled activation policy changed topology semantics");

        const fs::path pamAuthUpdate = root / "bin/pam-auth-update";
        writeFile(pamAuthUpdate, "#!/bin/sh\nexit 0\n");
        require(::chmod(pamAuthUpdate.c_str(), 0755) == 0,
                "could not make fake pam-auth-update executable");
        fic::platform::PlatformExecutables executableConfig;
        executableConfig.entries = {{
            fic::platform::ExecutableId::PamAuthUpdate,
            {pamAuthUpdate}}};
        fic::platform::PlatformExecutableResolver resolver(
            executableConfig, {.enforceTrustedOwnership = false});
        std::string observedExecutable;
        std::vector<std::string> observedArguments;
        bool observedClearEnvironment = false;
        fic::identity::pam::PamAuthUpdateTopologyManagerOptions commandOptions;
        commandOptions.runner =
            [&](const std::string& executable,
                const std::vector<std::string>& arguments,
                const ProcessOptions& processOptions) {
                observedExecutable = executable;
                observedArguments = arguments;
                observedClearEnvironment = processOptions.clearEnvironment;
                ProcessResult result;
                result.started = true;
                result.exitCode = 0;
                return result;
            };
        fic::identity::pam::PamAuthUpdateTopologyManager commandManager(
            platform, platform.capabilities[0], {"login"}, resolver,
            commandOptions);
        require(commandManager.enable(error) &&
                    observedExecutable == pamAuthUpdate.string() &&
                    observedArguments == std::vector<std::string>{
                        "--enable", "fic-faillock-notify",
                        "fic-faillock"} &&
                    observedClearEnvironment,
                "pam-auth-update activation did not use typed argv");
        require(!commandManager.disable(error),
                "pam-auth-update manager allowed automatic deactivation");

        auto factoryManager =
            fic::identity::pam::createPamTopologyManager(
                platform, platform.capabilities[0], {"login"}, resolver,
                error);
        require(dynamic_cast<fic::identity::pam::
                    PamAuthUpdateTopologyManager*>(factoryManager.get()) !=
                    nullptr,
                "factory did not select pam-auth-update by typed strategy");

        auto staticQuality = platform.capabilities[2];
        staticQuality.topology =
            fic::platform::PamTopologyStrategyKind::StaticVerifyOnly;
        staticQuality.activationIdentifiers.clear();
        factoryManager = fic::identity::pam::createPamTopologyManager(
            platform, staticQuality, {"passwd"}, resolver, error);
        require(factoryManager != nullptr &&
                    !factoryManager->canEnable(error),
                "StaticVerifyOnly factory result allowed topology mutation");

        auto altLockout = platform.capabilities[0];
        altLockout.topology =
            fic::platform::PamTopologyStrategyKind::AltTcbManaged;
        altLockout.activationIdentifiers.clear();
        factoryManager = fic::identity::pam::createPamTopologyManager(
            platform, altLockout, {"login"}, resolver, error);
        require(dynamic_cast<fic::identity::pam::
                    AltPamFaillockTopologyManager*>(factoryManager.get()) !=
                    nullptr,
                "factory did not select the ALT faillock manager");
    } catch (const std::exception& exception) {
        std::cerr << "PamCapabilityActivationPolicyTests failed: "
                  << exception.what() << '\n';
        fs::remove_all(root);
        return EXIT_FAILURE;
    }
    fs::remove_all(root);
    std::cout << "PamCapabilityActivationPolicyTests passed\n";
    return EXIT_SUCCESS;
}
