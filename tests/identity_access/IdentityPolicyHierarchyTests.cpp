#include "modules/identity_access/submodules/composite/CompositePolicy.h"
#include "modules/identity_access/submodules/kerberos/KerberosPolicy.h"
#include "modules/identity_access/submodules/nss/NssPolicy.h"
#include "modules/identity_access/submodules/pam/PamOptionFile.h"
#include "modules/identity_access/submodules/pam/PamPolicy.h"
#include "modules/identity_access/submodules/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.h"
#include "modules/identity_access/submodules/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.h"
#include "modules/identity_access/submodules/pam/policies/PamPasswordHistoryEnforceForRootPolicy.h"
#include "modules/identity_access/submodules/pam/policies/RequiredPamEnforcementPolicy.h"
#include "modules/identity_access/submodules/sssd/SssdPolicy.h"

#include <fic/core/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
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
               const std::string& content,
               mode_t mode = 0644) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
    output.close();
    require(::chmod(path.c_str(), mode) == 0,
            "could not chmod " + path.string());
}

void writeIdentityConfig(const std::filesystem::path& root,
                         const std::string& rootHistoryValue,
                         const std::string& rootLockoutValue = "yes") {
    writeFile(
        root / "config/IDENTITY_ACCESS.conf",
        "dummy.status=ENABLE\n"
        "dummy.value=expected\n"
        "password_history_enforce_for_root.status=ENABLE\n"
        "password_history_enforce_for_root.value=" + rootHistoryValue + "\n"
        "failed_authentication_enforce_for_root.status=ENABLE\n"
        "failed_authentication_enforce_for_root.value=" + rootLockoutValue +
            "\n"
        "required_pam_enforcement.status=ENABLE\n"
        "required_pam_enforcement.value=pam_faillock,pam_pwhistory\n");
}

void initializeRuntimePaths(const std::filesystem::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";

    std::filesystem::create_directories(paths.configDir);
    std::filesystem::create_directories(paths.logDir);
    std::filesystem::create_directories(paths.dataDir);

    writeIdentityConfig(root, "yes");

    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

fic::platform::PamPlatformConfig makePasswordHistoryPlatform(
    const std::filesystem::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.passwordServices = {"passwd"};
    platform.passwordHistoryConfigPath =
        root / "security-config/pwhistory.conf";
    return platform;
}

fic::platform::PamPlatformConfig makeAuthenticationPlatform(
    const std::filesystem::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.authenticationServices = {"login"};
    platform.faillockConfigPath = root / "security-config/faillock.conf";
    return platform;
}

template <typename Base>
void initializeDummyPolicy(Base& policy) {
    policy.policyName = "dummy";
}

class DummyPamPolicy final : public PamPolicy {
public:
    DummyPamPolicy() {
        initializeDummyPolicy(*this);
        policyTypeValue =
            std::make_unique<FixedPolicyTypeValue>("expected");
    }

    std::string observed;

private:
    bool applyPam(const std::string& expectedValue) override {
        observed = expectedValue;
        return true;
    }
};

class DummySssdPolicy final : public SssdPolicy {
public:
    DummySssdPolicy() {
        initializeDummyPolicy(*this);
        policyTypeValue =
            std::make_unique<FixedPolicyTypeValue>("expected");
    }

    std::string observed;

private:
    bool applySssd(
        fic::identity::sssd::SssdConfiguration&,
        const std::string& expectedValue) override {
        observed = expectedValue;
        return true;
    }
};

class DummyKerberosPolicy final : public KerberosPolicy {
public:
    DummyKerberosPolicy() {
        initializeDummyPolicy(*this);
        policyTypeValue =
            std::make_unique<FixedPolicyTypeValue>("expected");
    }

    std::string observed;

private:
    bool applyKerberos(
        fic::identity::kerberos::KerberosConfiguration&,
        const std::string& expectedValue) override {
        observed = expectedValue;
        return true;
    }
};

class DummyNssPolicy final : public NssPolicy {
public:
    DummyNssPolicy() {
        initializeDummyPolicy(*this);
        policyTypeValue =
            std::make_unique<FixedPolicyTypeValue>("expected");
    }

    std::string observed;

private:
    bool applyNss(
        fic::identity::nss::NssConfiguration&,
        const std::string& expectedValue) override {
        observed = expectedValue;
        return true;
    }
};

class NoOpPreparedChange final
    : public fic::identity::PreparedConfigurationChange {
public:
    NoOpPreparedChange(std::string identifier,
                       std::vector<std::string>& events)
        : identifier_(std::move(identifier)),
          events_(events) {
    }

    std::string id() const override {
        return identifier_;
    }

    bool needsCommit() const noexcept override {
        return false;
    }

    bool needsActivation() const noexcept override {
        return false;
    }

    fic::identity::ConfigurationStepResult commitPersistent() override {
        return unexpected("commit");
    }

    fic::identity::ConfigurationStepResult verifyPersistent() override {
        events_.push_back(identifier_ + ":verify-persistent");
        return fic::identity::ConfigurationStepResult::success();
    }

    fic::identity::ConfigurationStepResult activate() override {
        return unexpected("activate");
    }

    fic::identity::ConfigurationStepResult verifyEffective() override {
        events_.push_back(identifier_ + ":verify-effective");
        return fic::identity::ConfigurationStepResult::success();
    }

    fic::identity::ConfigurationStepResult rollbackPersistent() override {
        return unexpected("rollback-persistent");
    }

    fic::identity::ConfigurationStepResult
    restoreRuntimeAfterRollback() override {
        return unexpected("restore-runtime");
    }

    fic::identity::ConfigurationStepResult verifyRollback() override {
        return unexpected("verify-rollback");
    }

private:
    fic::identity::ConfigurationStepResult unexpected(
        const std::string& step) {
        events_.push_back(identifier_ + ":unexpected-" + step);
        return fic::identity::ConfigurationStepResult::failure(
            "unexpected transaction step");
    }

    std::string identifier_;
    std::vector<std::string>& events_;
};

class RecordingParticipant final
    : public fic::identity::ConfigurationParticipant {
public:
    RecordingParticipant(std::string identifier,
                         std::vector<std::string>& observedValues,
                         std::vector<std::string>& events,
                         bool failPreparation = false)
        : identifier_(std::move(identifier)),
          observedValues_(observedValues),
          events_(events),
          failPreparation_(failPreparation) {
    }

    std::string id() const override {
        return identifier_;
    }

    fic::identity::ConfigurationPreparationResult prepare(
        const std::string& expectedValue) override {
        observedValues_.push_back(identifier_ + "=" + expectedValue);
        events_.push_back(identifier_ + ":prepare");
        if (failPreparation_) {
            return {nullptr, "injected preparation failure"};
        }
        return {
            std::make_unique<NoOpPreparedChange>(identifier_, events_),
            {}};
    }

private:
    std::string identifier_;
    std::vector<std::string>& observedValues_;
    std::vector<std::string>& events_;
    bool failPreparation_;
};

class DummyCompositePolicy final : public CompositePolicy {
public:
    DummyCompositePolicy(std::vector<std::string>& observedValues,
                         std::vector<std::string>& events,
                         bool failSecondPreparation = false) {
        initializeDummyPolicy(*this);
        policyTypeValue =
            std::make_unique<FixedPolicyTypeValue>("expected");
        addParticipant(std::make_unique<RecordingParticipant>(
            "kerberos", observedValues, events));
        addParticipant(std::make_unique<RecordingParticipant>(
            "sssd", observedValues, events, failSecondPreparation));
    }
};

template <typename PolicyType>
void requireLeaf(PolicyType& policy, const std::string& submodule) {
    require(
        policy.moduleName == "IDENTITY_ACCESS",
        "leaf policy has the wrong module name");
    require(
        policy.submoduleName == submodule,
        "leaf policy has the wrong submodule name");
    require(policy.apply(), "leaf apply wrapper failed");
    require(
        policy.observed == "expected",
        "leaf hook did not receive the configured value");
}

} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-identity-hierarchy-test-" + std::to_string(::getpid()));
    fs::remove_all(root);

    try {
        initializeRuntimePaths(root);

        const auto passwordHistoryPlatform =
            makePasswordHistoryPlatform(root);
        writeFile(
            root / "pam.d/passwd",
            "password required pam_pwhistory.so\n");
        writeFile(root / "security/pam_pwhistory.so", "test", 0555);
        writeFile(
            passwordHistoryPlatform.passwordHistoryConfigPath,
            "remember = 5\n");

        PamPasswordHistoryEnforceForRootPolicy rootHistoryEnabled(
            passwordHistoryPlatform);
        require(
            rootHistoryEnabled.moduleName == "IDENTITY_ACCESS" &&
                rootHistoryEnabled.submoduleName == "PAM" &&
                rootHistoryEnabled.policyName ==
                    "password_history_enforce_for_root",
            "root-history policy has the wrong identity metadata");
        require(
            rootHistoryEnabled.getDefaultValue() == "yes" &&
                rootHistoryEnabled.validate("yes") &&
                rootHistoryEnabled.validate("no") &&
                !rootHistoryEnabled.validate("true"),
            "root-history policy value contract is incorrect");
        const PolicyEditorSpec rootHistoryEditor =
            rootHistoryEnabled.getPolicyTypeValue().getEditorSpec();
        require(
            rootHistoryEditor.editor == "combobox" &&
                rootHistoryEditor.possibleValues ==
                    std::vector<std::string>{"yes", "no"},
            "root-history policy has the wrong editor values");
        require(rootHistoryEnabled.apply(),
                "root-history policy failed to enable the PAM flag");
        std::string flagError;
        require(
            fic::identity::pam::PamOptionFile::hasFlag(
                passwordHistoryPlatform.passwordHistoryConfigPath,
                "enforce_for_root",
                true,
                flagError),
            flagError);

        writeIdentityConfig(root, "no");
        PamPasswordHistoryEnforceForRootPolicy rootHistoryDisabled(
            passwordHistoryPlatform);
        require(rootHistoryDisabled.apply(),
                "root-history policy failed to disable the PAM flag");
        require(
            fic::identity::pam::PamOptionFile::hasFlag(
                passwordHistoryPlatform.passwordHistoryConfigPath,
                "enforce_for_root",
                false,
                flagError),
            flagError);

        const auto authenticationPlatform =
            makeAuthenticationPlatform(root);
        writeFile(
            root / "pam.d/login",
            "auth required pam_faillock.so preauth\n"
            "auth [success=1 default=bad] pam_unix.so\n"
            "auth [default=die] pam_faillock.so authfail\n"
            "auth sufficient pam_faillock.so authsucc\n"
            "auth required pam_deny.so\n");
        writeFile(root / "security/pam_faillock.so", "test", 0555);
        writeFile(
            authenticationPlatform.faillockConfigPath,
            "deny = 5\n"
            "unlock_time = 600\n");

        PamFailedAuthenticationEnforceForRootPolicy rootLockoutEnabled(
            authenticationPlatform);
        require(
            rootLockoutEnabled.moduleName == "IDENTITY_ACCESS" &&
                rootLockoutEnabled.submoduleName == "PAM" &&
                rootLockoutEnabled.policyName ==
                    "failed_authentication_enforce_for_root",
            "root-lockout policy has the wrong identity metadata");
        require(
            rootLockoutEnabled.getDefaultValue() == "yes" &&
                rootLockoutEnabled.validate("yes") &&
                rootLockoutEnabled.validate("no") &&
                !rootLockoutEnabled.validate("true"),
            "root-lockout policy value contract is incorrect");
        const PolicyEditorSpec rootLockoutEditor =
            rootLockoutEnabled.getPolicyTypeValue().getEditorSpec();
        require(
            rootLockoutEditor.editor == "combobox" &&
                rootLockoutEditor.possibleValues ==
                    std::vector<std::string>{"yes", "no"},
            "root-lockout policy has the wrong editor values");
        require(rootLockoutEnabled.apply(),
                "root-lockout policy failed to enable the PAM flag");
        require(
            fic::identity::pam::PamOptionFile::hasFlag(
                authenticationPlatform.faillockConfigPath,
                "even_deny_root",
                true,
                flagError),
            flagError);

        writeIdentityConfig(root, "no", "no");
        PamFailedAuthenticationEnforceForRootPolicy rootLockoutDisabled(
            authenticationPlatform);
        require(rootLockoutDisabled.apply(),
                "root-lockout policy failed to disable the PAM flag");
        require(
            fic::identity::pam::PamOptionFile::hasFlag(
                authenticationPlatform.faillockConfigPath,
                "even_deny_root",
                false,
                flagError),
            flagError);

        auto requiredPlatform = authenticationPlatform;
        requiredPlatform.passwordServices =
            passwordHistoryPlatform.passwordServices;
        requiredPlatform.passwordHistoryConfigPath =
            passwordHistoryPlatform.passwordHistoryConfigPath;
        RequiredPamEnforcementPolicy requiredPam(requiredPlatform);
        require(
            requiredPam.getPolicyTypeValue().getEditorSpec().editor ==
                "textedit" &&
                requiredPam.validate("pam_faillock, pam_pwhistory") &&
                !requiredPam.validate("pam_vendor"),
            "required-PAM policy value contract is incorrect");
        require(requiredPam.apply(),
                "required-PAM policy rejected effective providers");

        writeFile(
            root / "pam.d/login",
            "auth sufficient pam_permit.so\n"
            "auth required pam_faillock.so preauth\n"
            "auth [success=1 default=bad] pam_unix.so\n"
            "auth [default=die] pam_faillock.so authfail\n"
            "auth sufficient pam_faillock.so authsucc\n"
            "auth required pam_deny.so\n");
        require(!requiredPam.apply(),
                "required-PAM policy accepted an authentication bypass");
        require(rootHistoryDisabled.apply(),
                "broken faillock must not block an independent history policy");
        writeFile(
            root / "pam.d/login",
            "auth required pam_faillock.so preauth\n"
            "auth [success=1 default=bad] pam_unix.so\n"
            "auth [default=die] pam_faillock.so authfail\n"
            "auth sufficient pam_faillock.so authsucc\n"
            "auth required pam_deny.so\n");

        writeFile(
            authenticationPlatform.faillockConfigPath,
            "deny = 5\n"
            "root_unlock_time = 60\n");
        PamFailedAuthenticationEnforceForRootPolicy conflictingRootLockout(
            authenticationPlatform);
        require(
            !conflictingRootLockout.apply(),
            "root_unlock_time must prevent disabling root lockout");
        require(
            fic::identity::pam::PamOptionFile::hasFlag(
                authenticationPlatform.faillockConfigPath,
                "even_deny_root",
                false,
                flagError),
            "root-lockout conflict must not add even_deny_root");

        DummyPamPolicy pam;
        PamFailedAuthenticationCountingPeriodPolicy countingPeriod({});
        DummySssdPolicy sssd;
        DummyKerberosPolicy kerberos;
        DummyNssPolicy nss;
        std::vector<std::string> observedValues;
        std::vector<std::string> compositeEvents;
        DummyCompositePolicy composite(observedValues, compositeEvents);

        requireLeaf(pam, "PAM");
        require(
            countingPeriod.moduleName == "IDENTITY_ACCESS" &&
                countingPeriod.submoduleName == "PAM" &&
                countingPeriod.policyName ==
                    "failed_authentication_counting_period",
            "counting-period policy has the wrong identity metadata");
        require(
            countingPeriod.getDefaultValue() == "900",
            "counting-period policy has the wrong default");
        const PolicyEditorSpec countingPeriodEditor =
            countingPeriod.getPolicyTypeValue().getEditorSpec();
        require(
            countingPeriodEditor.editor == "spinbox" &&
                countingPeriodEditor.min == 1 &&
                countingPeriodEditor.max == 86400,
            "counting-period policy has the wrong editor bounds");
        require(
            countingPeriod.validate("1") &&
                countingPeriod.validate("86400") &&
                !countingPeriod.validate("0") &&
                !countingPeriod.validate("86401") &&
                !countingPeriod.validate("not-a-number"),
            "counting-period policy validation is incorrect");
        requireLeaf(sssd, "SSSD");
        requireLeaf(kerberos, "KERBEROS");
        requireLeaf(nss, "NSS");
        require(
            composite.moduleName == "IDENTITY_ACCESS" &&
                composite.submoduleName == "COMPOSITE",
            "composite policy has the wrong module hierarchy");
        require(composite.apply(), "composite apply wrapper failed");
        require(
            observedValues == std::vector<std::string>{
                "kerberos=expected", "sssd=expected"},
            "composite participants did not receive one policy value");
        require(
            compositeEvents == std::vector<std::string>{
                "kerberos:prepare", "sssd:prepare",
                "kerberos:verify-persistent", "sssd:verify-persistent",
                "kerberos:verify-effective", "sssd:verify-effective"},
            "composite did not prepare every participant before execution");

        std::vector<std::string> failedObservedValues;
        std::vector<std::string> failedEvents;
        DummyCompositePolicy failingComposite(
            failedObservedValues, failedEvents, true);
        require(
            !failingComposite.apply(),
            "composite preparation failure must fail apply");
        require(
            failedEvents == std::vector<std::string>{
                "kerberos:prepare", "sssd:prepare"},
            "preflight failure must not execute prepared changes");
    } catch (const std::exception& error) {
        std::cerr << "IdentityPolicyHierarchyTests failed: "
                  << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }

    fs::remove_all(root);
    std::cout << "IdentityPolicyHierarchyTests passed\n";
    return 0;
}
