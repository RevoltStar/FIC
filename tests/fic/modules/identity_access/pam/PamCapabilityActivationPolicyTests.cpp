#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"
#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"
#include "modules/identity_access/pam/PamAuthUpdateTopologyManager.h"
#include "modules/identity_access/pam/PamTopologyManagerFactory.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
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
    int factoryCalls = 0;
    int inspectCalls = 0;
    int canEnableCalls = 0;
    int enableCalls = 0;
    int disableCalls = 0;
    bool inspectResult = true;
    bool canEnableResult = true;
    bool enableResult = true;
    bool transitionToEnabled = true;
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
        if (state_->enableResult && state_->transitionToEnabled) {
            state_->topologyState =
                fic::identity::pam::PamTopologyState::Enabled;
        }
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
            ++managerState->factoryCalls;
            factoryCapability = capabilityConfig.capability;
            error.clear();
            return std::make_unique<FakeManager>(managerState);
        };
    return PamCapabilityActivationPolicy(platform, capability,
                                         std::move(options));
}

fic::platform::PamPlatformConfig makeAltLockoutPlatform(
    const std::filesystem::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.scopes = {{
        fic::platform::PamScope::EffectiveAuthenticationStack,
        {"system-auth-local-only"}}};
    platform.capabilities = {{
        fic::platform::PamCapability::AuthenticationLockout,
        fic::platform::PamProviderKind::PamFaillock,
        fic::platform::PamScope::EffectiveAuthenticationStack,
        "/etc/security/faillock.conf",
        fic::platform::PamTopologyStrategyKind::AltTcbManaged}};
    platform.capabilities.front().managedTopologyTargets = {{
        root / "pam.d/system-auth-local-only",
        fic::platform::PamManagedTopologyTargetRole::AuthenticationAndAccount}};
    return platform;
}

fic::identity::pam::AltPamFaillockTopologyOptions altLockoutOptions(
    const std::filesystem::path& root) {
    fic::identity::pam::AltPamFaillockTopologyOptions options;
    options.lockFilePath = root / "run/pam-faillock.lock";
    options.lockDebugLogPath = root / "lock-debug.log";
    return options;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    require(stream.is_open(), "could not read " + path.string());
    return std::string(std::istreambuf_iterator<char>(stream),
                       std::istreambuf_iterator<char>());
}

PamCapabilityActivationPolicy makeAltLockoutPolicy(
    const fic::platform::PamPlatformConfig& platform,
    const std::filesystem::path& root) {
    PamCapabilityActivationPolicyOptions options;
    options.managerFactory =
        [platform, root](const auto&, const auto&, std::string& error) {
            error.clear();
            return std::make_unique<fic::identity::pam::
                AltPamFaillockTopologyManager>(
                    platform, altLockoutOptions(root));
        };
    return PamCapabilityActivationPolicy(
        platform, fic::platform::PamCapability::AuthenticationLockout,
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
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
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
                    state->factoryCalls == 2 && state->inspectCalls == 2 &&
                    state->canEnableCalls == 0 && state->enableCalls == 0,
                "manager-first repeated activation was not idempotent");

        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Enabled;
        verifierCalls = 0;
        auto enabledButStructurallyInvalid = makePolicy(
            platform, fic::platform::PamCapability::AuthenticationLockout,
            state, {false}, verifierCalls, factoryCapability);
        require(!enabledButStructurallyInvalid.apply() &&
                    state->factoryCalls == 1 && state->inspectCalls == 1 &&
                    state->enableCalls == 0 && verifierCalls == 1,
                "manager-enabled topology bypassed fresh verification");

        state = std::make_shared<ManagerState>();
        state->inspectResult = false;
        verifierCalls = 0;
        auto inspectionFailure = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {}, verifierCalls, factoryCapability);
        require(!inspectionFailure.apply() && state->inspectCalls == 1 &&
                    state->canEnableCalls == 0 && state->enableCalls == 0 &&
                    verifierCalls == 0,
                "topology inspection failure was not fail-closed");

        state = std::make_shared<ManagerState>();
        verifierCalls = 0;
        auto activated = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {true}, verifierCalls, factoryCapability);
        require(activated.policyName == "enable_password_history" &&
                    activated.apply() && verifierCalls == 1 &&
                    factoryCapability ==
                        fic::platform::PamCapability::PasswordHistory &&
                    state->inspectCalls == 2 && state->canEnableCalls == 1 &&
                    state->enableCalls == 1 && state->disableCalls == 0,
                "disabled topology was not activated and freshly verified");

        state = std::make_shared<ManagerState>();
        verifierCalls = 0;
        auto invalidPostcondition = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {false}, verifierCalls, factoryCapability);
        require(!invalidPostcondition.apply() && state->inspectCalls == 2 &&
                    state->enableCalls == 1 && state->disableCalls == 0 &&
                    verifierCalls == 1,
                "invalid post-activation topology was accepted or disabled");

        state = std::make_shared<ManagerState>();
        state->enableResult = false;
        verifierCalls = 0;
        auto failedEnable = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {}, verifierCalls, factoryCapability);
        require(!failedEnable.apply() && state->inspectCalls == 1 &&
                    state->enableCalls == 1 && verifierCalls == 0,
                "native activation failure was accepted");

        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Broken;
        verifierCalls = 0;
        auto broken = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {}, verifierCalls, factoryCapability);
        require(!broken.apply() && state->inspectCalls == 1 &&
                    state->canEnableCalls == 0 && state->enableCalls == 0 &&
                    verifierCalls == 0,
                "broken topology was mutated");

        state = std::make_shared<ManagerState>();
        state->topologyState =
            fic::identity::pam::PamTopologyState::Unavailable;
        verifierCalls = 0;
        auto unavailable = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {}, verifierCalls, factoryCapability);
        require(!unavailable.apply() && state->inspectCalls == 1 &&
                    state->canEnableCalls == 0 && state->enableCalls == 0 &&
                    verifierCalls == 0,
                "unavailable topology was mutated");

        state = std::make_shared<ManagerState>();
        state->transitionToEnabled = false;
        verifierCalls = 0;
        auto ownershipNotEstablished = makePolicy(
            platform, fic::platform::PamCapability::PasswordHistory,
            state, {}, verifierCalls, factoryCapability);
        require(!ownershipNotEstablished.apply() &&
                    state->inspectCalls == 2 && state->enableCalls == 1 &&
                    verifierCalls == 0,
                "post-enable non-enabled ownership state was accepted");

        state = std::make_shared<ManagerState>();
        verifierCalls = 0;
        auto disabled = makePolicy(
            platform, fic::platform::PamCapability::PasswordQuality,
            state, {false}, verifierCalls, factoryCapability);
        require(!disabled.isEnabled() && state->disableCalls == 0 &&
                    disabled.getDefaultValue() == "ENABLE",
                "disabled activation policy changed topology semantics");

        const fs::path externalAltRoot = root / "alt-external";
        writeFile(externalAltRoot / "security/pam_faillock.so", "fixture\n");
        writeFile(externalAltRoot / "security/pam_tcb.so", "fixture\n");
        writeFile(externalAltRoot / "pam.d/system-auth-local-only",
                  "#%PAM-1.0\n"
                  "auth required pam_tcb.so shadow fork nullok\n"
                  "account required pam_tcb.so shadow fork\n");
        fs::create_directories(externalAltRoot / "run");
        const auto externalAltPlatform =
            makeAltLockoutPlatform(externalAltRoot);
        fic::identity::pam::AltPamFaillockTopologyManager seedExternalManager(
            externalAltPlatform, altLockoutOptions(externalAltRoot));
        require(seedExternalManager.enable(error), error);
        std::istringstream managedInput(readFile(
            externalAltRoot / "pam.d/system-auth-local-only"));
        std::string externalAltFaillock;
        std::string managedLine;
        while (std::getline(managedInput, managedLine)) {
            if (managedLine.rfind("# BEGIN FIC ", 0) == 0 ||
                managedLine.rfind("# END FIC ", 0) == 0 ||
                managedLine.rfind("# FIC ORIGINAL ", 0) == 0) {
                continue;
            }
            externalAltFaillock += managedLine + "\n";
        }
        writeFile(externalAltRoot / "pam.d/system-auth-local-only",
                  externalAltFaillock);
        fic::identity::pam::PamConfiguration externalAltConfiguration(
            externalAltPlatform);
        fic::identity::pam::PamCapabilityVerification externalVerification;
        require(fic::identity::pam::PamCapabilityVerifier::verify(
                    externalAltConfiguration, externalAltPlatform,
                    {"system-auth-local-only"},
                    fic::platform::PamCapability::AuthenticationLockout,
                    fic::platform::PamProviderKind::PamFaillock,
                    externalVerification,
                    fic::identity::pam::
                        PamCapabilityVerificationMode::Structural),
                "external ALT faillock fixture was not structurally effective: " +
                    fic::identity::pam::formatPamCapabilityVerification(
                        externalVerification));
        fic::identity::pam::AltPamFaillockTopologyManager externalManager(
            externalAltPlatform, altLockoutOptions(externalAltRoot));
        fic::identity::pam::PamTopologyStatus externalStatus;
        require(externalManager.inspect(externalStatus, error) &&
                    externalStatus.state !=
                        fic::identity::pam::PamTopologyState::Enabled,
                "ALT manager reported external structurally valid faillock as "
                "FIC-owned enabled topology");
        auto externalAltPolicy = makeAltLockoutPolicy(
            externalAltPlatform, externalAltRoot);
        require(!externalAltPolicy.apply() &&
                    readFile(externalAltRoot /
                             "pam.d/system-auth-local-only") ==
                        externalAltFaillock,
                "activation policy bypassed ALT faillock ownership or mutated it");

        const fs::path ownedAltRoot = root / "alt-owned";
        writeFile(ownedAltRoot / "security/pam_faillock.so", "fixture\n");
        writeFile(ownedAltRoot / "security/pam_tcb.so", "fixture\n");
        writeFile(
            ownedAltRoot / "pam.d/system-auth-local-only",
            "#%PAM-1.0\n"
            "auth required pam_tcb.so shadow fork nullok\n"
            "account required pam_tcb.so shadow fork\n");
        fs::create_directories(ownedAltRoot / "run");
        const auto ownedAltPlatform = makeAltLockoutPlatform(ownedAltRoot);
        fic::identity::pam::AltPamFaillockTopologyManager ownedManager(
            ownedAltPlatform, altLockoutOptions(ownedAltRoot));
        require(ownedManager.enable(error), error);
        const std::string ownedAltFaillock = readFile(
            ownedAltRoot / "pam.d/system-auth-local-only");
        auto ownedAltPolicy = makeAltLockoutPolicy(
            ownedAltPlatform, ownedAltRoot);
        require(ownedAltPolicy.apply() &&
                    readFile(ownedAltRoot /
                             "pam.d/system-auth-local-only") ==
                        ownedAltFaillock,
                "FIC-owned enabled ALT faillock was mutated or rejected");

        const fs::path externalHistoryRoot = root / "alt-external-history";
        writeFile(externalHistoryRoot / "security/pam_pwhistory.so",
                  "fixture\n");
        writeFile(externalHistoryRoot / "security/pam_tcb.so", "fixture\n");
        const std::string externalHistory =
            "#%PAM-1.0\n"
            "password required pam_pwhistory.so use_authtok "
            "conf=/etc/security/fic-pwhistory.conf\n"
            "password required pam_tcb.so use_authtok shadow fork nullok "
            "write_to=tcb\n";
        writeFile(externalHistoryRoot / "pam.d/system-auth-local-only",
                  externalHistory);
        fs::create_directories(externalHistoryRoot / "run");
        fic::platform::PamPlatformConfig externalHistoryPlatform;
        externalHistoryPlatform.configDirectories = {
            externalHistoryRoot / "pam.d"};
        externalHistoryPlatform.moduleDirectories = {
            externalHistoryRoot / "security"};
        externalHistoryPlatform.scopes = {{
            fic::platform::PamScope::LocalPasswordChange,
            {"system-auth-local-only"}}};
        externalHistoryPlatform.capabilities = {{
            fic::platform::PamCapability::PasswordHistory,
            fic::platform::PamProviderKind::PamPwhistory,
            fic::platform::PamScope::LocalPasswordChange,
            "/etc/security/fic-pwhistory.conf",
            fic::platform::PamTopologyStrategyKind::AltTcbManaged,
            externalHistoryRoot / "pam.d/system-auth-local-only"}};
        fic::identity::pam::PamConfiguration externalHistoryConfiguration(
            externalHistoryPlatform);
        fic::identity::pam::PamCapabilityVerification historyVerification;
        require(fic::identity::pam::PamCapabilityVerifier::verify(
                    externalHistoryConfiguration, externalHistoryPlatform,
                    {"system-auth-local-only"},
                    fic::platform::PamCapability::PasswordHistory,
                    fic::platform::PamProviderKind::PamPwhistory,
                    historyVerification,
                    fic::identity::pam::
                        PamCapabilityVerificationMode::Structural),
                "external ALT password-history fixture was not structurally "
                "effective: " +
                    fic::identity::pam::formatPamCapabilityVerification(
                        historyVerification));
        fic::identity::pam::AltPamPasswordHistoryTopologyOptions historyOptions;
        historyOptions.lockFilePath = externalHistoryRoot / "run/topology.lock";
        historyOptions.lockDebugLogPath =
            externalHistoryRoot / "lock-debug.log";
        historyOptions.stateDirectory = externalHistoryRoot / "state";
        historyOptions.historyFile = historyOptions.stateDirectory / "opasswd";
        historyOptions.transactionLockFile =
            historyOptions.stateDirectory / ".lock";
        historyOptions.storageOwner = ::geteuid();
        historyOptions.storageGroup = ::getegid();
        historyOptions.semanticVerifier = [](std::string& semanticError) {
            semanticError.clear();
            return true;
        };
        fic::identity::pam::AltPamPasswordHistoryTopologyManager historyManager(
            externalHistoryPlatform, historyOptions);
        fic::identity::pam::PamTopologyStatus historyStatus;
        require(!historyManager.inspect(historyStatus, error) &&
                    historyStatus.state ==
                        fic::identity::pam::PamTopologyState::Broken,
                "ALT manager accepted external structurally valid password "
                "history");
        PamCapabilityActivationPolicyOptions historyPolicyOptions;
        historyPolicyOptions.managerFactory =
            [externalHistoryPlatform, historyOptions](
                const auto&, const auto&, std::string& factoryError) {
                factoryError.clear();
                return std::make_unique<fic::identity::pam::
                    AltPamPasswordHistoryTopologyManager>(
                        externalHistoryPlatform, historyOptions);
            };
        PamCapabilityActivationPolicy externalHistoryPolicy(
            externalHistoryPlatform,
            fic::platform::PamCapability::PasswordHistory,
            std::move(historyPolicyOptions));
        require(!externalHistoryPolicy.apply() &&
                    readFile(externalHistoryRoot /
                             "pam.d/system-auth-local-only") ==
                        externalHistory &&
                    !fs::exists(historyOptions.stateDirectory),
                "activation policy bypassed ALT password-history ownership or "
                "mutated it");

        writeFile(
            root / "config/IDENTITY_ACCESS.conf",
            "enable_authentication_lockout.status=ENABLE\n"
            "enable_authentication_lockout.value=ENABLE\n"
            "enable_password_history.status=ENABLE\n"
            "enable_password_history.value=ENABLE\n"
            "enable_password_quality.status=ENABLE\n"
            "enable_password_quality.value=ENABLE\n");
        const fs::path staticRoot = root / "static-passwdqc";
        writeFile(staticRoot / "security/pam_passwdqc.so", "fixture\n");
        writeFile(staticRoot / "passwdqc.conf",
                  "min=disabled,24,11,8,7\n");
        writeFile(staticRoot / "pam.d/passwd",
                  "password required pam_passwdqc.so config=" +
                      (staticRoot / "passwdqc.conf").string() + "\n");
        fic::platform::PamPlatformConfig staticPlatform;
        staticPlatform.configDirectories = {staticRoot / "pam.d"};
        staticPlatform.moduleDirectories = {staticRoot / "security"};
        staticPlatform.scopes = {{
            fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
        staticPlatform.capabilities = {{
            fic::platform::PamCapability::PasswordQuality,
            fic::platform::PamProviderKind::PamPasswdqc,
            fic::platform::PamScope::EffectivePasswordStack,
            staticRoot / "passwdqc.conf",
            fic::platform::PamTopologyStrategyKind::StaticVerifyOnly}};
        fic::platform::PlatformExecutableResolver staticResolver(
            {}, {.enforceTrustedOwnership = false});
        PamCapabilityActivationPolicyOptions staticOptions;
        staticOptions.managerFactory =
            [&staticPlatform, &staticResolver](const auto& capability,
                                               const auto& services,
                                               std::string& factoryError) {
                return fic::identity::pam::createPamTopologyManager(
                    staticPlatform, capability, services, staticResolver,
                    factoryError);
            };
        const std::string staticPamBefore =
            readFile(staticRoot / "pam.d/passwd");
        PamCapabilityActivationPolicy staticPolicy(
            staticPlatform, fic::platform::PamCapability::PasswordQuality,
            std::move(staticOptions));
        require(staticPolicy.apply() &&
                    readFile(staticRoot / "pam.d/passwd") == staticPamBefore,
                "StaticVerifyOnly passwdqc was mutated or rejected");

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

        const std::string faillockConfigArgument =
            " conf=" + (root / "security/faillock.conf").string();
        const std::string effectiveLockout =
            "#%PAM-1.0\n"
            "auth requisite pam_faillock.so preauth" +
            faillockConfigArgument + "\n" +
            "auth sufficient pam_tcb.so shadow fork nullok\n"
            "auth [default=die] pam_faillock.so authfail" +
            faillockConfigArgument + "\n" +
            "account required pam_faillock.so" +
            faillockConfigArgument + "\n" +
            "account required pam_tcb.so shadow fork\n";
        writeFile(root / "security/pam_faillock.so", "fixture\n");
        writeFile(root / "security/pam_tcb.so", "fixture\n");
        int pamAuthUpdateCalls = 0;
        fic::identity::pam::PamAuthUpdateTopologyManagerOptions policyCommand;
        policyCommand.runner =
            [&](const std::string&,
                const std::vector<std::string>&,
                const ProcessOptions&) {
                ++pamAuthUpdateCalls;
                writeFile(root / "pam.d/login", effectiveLockout);
                ProcessResult result;
                result.started = true;
                result.exitCode = 0;
                return result;
            };
        const auto makePamAuthUpdatePolicy = [&]() {
            PamCapabilityActivationPolicyOptions policyOptions;
            policyOptions.managerFactory =
                [&](const auto& capability, const auto& services,
                    std::string& factoryError) {
                    factoryError.clear();
                    return std::make_unique<fic::identity::pam::
                        PamAuthUpdateTopologyManager>(
                            platform, capability, services, resolver,
                            policyCommand);
                };
            return PamCapabilityActivationPolicy(
                platform,
                fic::platform::PamCapability::AuthenticationLockout,
                std::move(policyOptions));
        };

        writeFile(root / "pam.d/login", effectiveLockout);
        auto pamAuthUpdateAlreadyEnabled = makePamAuthUpdatePolicy();
        require(pamAuthUpdateAlreadyEnabled.apply() &&
                    pamAuthUpdateCalls == 0,
                "already-enabled pam-auth-update topology was mutated");

        writeFile(root / "pam.d/login",
                  "auth required pam_tcb.so shadow fork nullok\n"
                  "account required pam_tcb.so shadow fork\n");
        auto pamAuthUpdateDisabled = makePamAuthUpdatePolicy();
        require(pamAuthUpdateDisabled.apply() && pamAuthUpdateCalls == 1,
                "disabled pam-auth-update topology was not activated once");
        require(pamAuthUpdateDisabled.apply() && pamAuthUpdateCalls == 1,
                "repeated pam-auth-update activation was not idempotent");

        writeFile(root / "pam.d/login", "auth include login\n");
        auto pamAuthUpdateBroken = makePamAuthUpdatePolicy();
        require(!pamAuthUpdateBroken.apply() && pamAuthUpdateCalls == 1,
                "broken pam-auth-update topology was mutated");

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
