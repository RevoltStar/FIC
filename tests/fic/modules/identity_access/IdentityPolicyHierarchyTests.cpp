#include "modules/identity_access/composite/CompositePolicy.h"
#include "modules/identity_access/kerberos/KerberosPolicy.h"
#include "modules/identity_access/nss/NssPolicy.h"
#include "modules/identity_access/pam/PamOptionFile.h"
#include "modules/identity_access/pam/PamPolicy.h"
#include "modules/identity_access/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.h"
#include "modules/identity_access/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.h"
#include "modules/identity_access/pam/policies/PamPasswordHistoryEnforceForRootPolicy.h"
#include "modules/identity_access/pam/policies/PamPasswordQualityPolicies.h"
#include "modules/identity_access/pam/policies/RequiredPamEnforcementPolicy.h"
#include "modules/identity_access/sssd/SssdPolicy.h"

#include <fic/core/runtime/FicRuntimePaths.h>

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
                         const std::string& rootLockoutValue = "yes",
                         const std::string& additionalConfig = "",
                         const std::string& requiredPamValue =
                             "pam_faillock,pam_pwhistory") {
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
        "required_pam_enforcement.value=" + requiredPamValue + "\n" +
            additionalConfig);
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

fic::platform::PamPlatformConfig makePasswordQualityPlatform(
    const std::filesystem::path& root) {
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {root / "pam.d"};
    platform.moduleDirectories = {root / "security"};
    platform.passwordServices = {"passwd"};
    platform.passwordQualityConfigPath =
        root / "security-config/pwquality.conf";
    return platform;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

std::string configuredValue(const std::string& content,
                            const std::string& key) {
    const std::string prefix = key + "=";
    const std::size_t position = content.find(prefix);
    require(position == 0 ||
                (position != std::string::npos && content[position - 1] == '\n'),
            "missing generated config key: " + key);
    const std::size_t valueStart = position + prefix.size();
    const std::size_t lineEnd = content.find('\n', valueStart);
    return content.substr(valueStart, lineEnd - valueStart);
}

template <typename PolicyType>
void applyPasswordQualityAssignment(
    const std::filesystem::path& root,
    const fic::platform::PamPlatformConfig& platform,
    const std::string& policyName,
    const std::string& logicalValue,
    const std::string& option,
    const std::string& nativeValue) {
    writeIdentityConfig(
        root, "yes", "yes",
        policyName + ".status=ENABLE\n" +
            policyName + ".value=" + logicalValue + "\n");
    PolicyType policy(platform);
    require(policy.policyName == policyName, "wrong policy name: " + policyName);
    require(policy.apply(), "failed to apply " + policyName + "=" + logicalValue);
    std::string error;
    require(
        fic::identity::pam::PamOptionFile::hasOnlyValue(
            platform.passwordQualityConfigPath,
            option, nativeValue, error),
        error);
    const std::string firstContent =
        readFile(platform.passwordQualityConfigPath);
    require(policy.apply(), "idempotent apply failed for " + policyName);
    require(
        readFile(platform.passwordQualityConfigPath) == firstContent,
        "idempotent apply changed the file for " + policyName);
}

template <typename PolicyType>
void testMinimumCreditPolicy(
    const std::filesystem::path& root,
    const fic::platform::PamPlatformConfig& platform,
    const std::string& policyName,
    const std::string& option) {
    for (const auto& value : std::vector<std::pair<std::string, std::string>>{
             {"1", "-1"}, {"2", "-2"}, {"0", "0"}}) {
        applyPasswordQualityAssignment<PolicyType>(
            root, platform, policyName, value.first, option, value.second);
    }
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

        const auto passwordQualityPlatform =
            makePasswordQualityPlatform(root);
        const auto writePasswordQualityGraph =
            [&](const std::string& arguments = "") {
                writeFile(
                    root / "pam.d/passwd",
                    "password requisite pam_pwquality.so" + arguments +
                        "\npassword required pam_unix.so\n");
                const auto provider = root / "security/pam_pwquality.so";
                if (!std::filesystem::exists(provider)) {
                    writeFile(provider, "test", 0555);
                }
            };
        writePasswordQualityGraph();
        writeFile(passwordQualityPlatform.passwordQualityConfigPath, "");

        applyPasswordQualityAssignment<PamPasswordCheckUsernamePolicy>(
            root, passwordQualityPlatform,
            "password_check_username", "yes", "usercheck", "1");
        applyPasswordQualityAssignment<PamPasswordCheckUsernamePolicy>(
            root, passwordQualityPlatform,
            "password_check_username", "no", "usercheck", "0");
        writePasswordQualityGraph(" usercheck=1");
        writeIdentityConfig(
            root, "yes", "yes",
            "password_check_username.status=ENABLE\n"
            "password_check_username.value=no\n");
        const std::string usernameBefore =
            readFile(passwordQualityPlatform.passwordQualityConfigPath);
        PamPasswordCheckUsernamePolicy conflictingUsername(
            passwordQualityPlatform);
        require(
            !conflictingUsername.apply(),
            "usercheck PAM argument override must fail");
        require(
            readFile(passwordQualityPlatform.passwordQualityConfigPath) ==
                usernameBefore,
            "usercheck override failure modified canonical config");

        writePasswordQualityGraph();
        applyPasswordQualityAssignment<PamPasswordCheckGecosPolicy>(
            root, passwordQualityPlatform,
            "password_check_gecos", "yes", "gecoscheck", "1");
        applyPasswordQualityAssignment<PamPasswordCheckGecosPolicy>(
            root, passwordQualityPlatform,
            "password_check_gecos", "no", "gecoscheck", "0");
        writePasswordQualityGraph(" gecoscheck=1");
        writeIdentityConfig(
            root, "yes", "yes",
            "password_check_gecos.status=ENABLE\n"
            "password_check_gecos.value=no\n");
        PamPasswordCheckGecosPolicy conflictingGecos(passwordQualityPlatform);
        require(
            !conflictingGecos.apply(),
            "gecoscheck PAM argument override must fail");

        writePasswordQualityGraph();
        writeIdentityConfig(
            root, "yes", "yes",
            "password_quality_enforce_for_root.status=ENABLE\n"
            "password_quality_enforce_for_root.value=yes\n");
        PamPasswordQualityEnforceForRootPolicy qualityForRootEnabled(
            passwordQualityPlatform);
        require(
            qualityForRootEnabled.apply(),
            "failed to enable pam_pwquality enforce_for_root");
        std::string optionError;
        require(
            fic::identity::pam::PamOptionFile::hasFlag(
                passwordQualityPlatform.passwordQualityConfigPath,
                "enforce_for_root", true, optionError),
            optionError);
        const std::string enabledFlagContent =
            readFile(passwordQualityPlatform.passwordQualityConfigPath);
        require(
            qualityForRootEnabled.apply() &&
                readFile(passwordQualityPlatform.passwordQualityConfigPath) ==
                    enabledFlagContent,
            "enforce_for_root enable is not idempotent");
        writeIdentityConfig(
            root, "yes", "yes",
            "password_quality_enforce_for_root.status=ENABLE\n"
            "password_quality_enforce_for_root.value=no\n");
        PamPasswordQualityEnforceForRootPolicy qualityForRootDisabled(
            passwordQualityPlatform);
        require(
            qualityForRootDisabled.apply(),
            "failed to disable pam_pwquality enforce_for_root");
        require(
            fic::identity::pam::PamOptionFile::hasFlag(
                passwordQualityPlatform.passwordQualityConfigPath,
                "enforce_for_root", false, optionError),
            optionError);
        writeFile(
            passwordQualityPlatform.passwordQualityConfigPath,
            "enforce_for_root=1\n");
        writeIdentityConfig(
            root, "yes", "yes",
            "password_quality_enforce_for_root.status=ENABLE\n"
            "password_quality_enforce_for_root.value=yes\n");
        PamPasswordQualityEnforceForRootPolicy malformedQualityFlag(
            passwordQualityPlatform);
        require(
            !malformedQualityFlag.apply(),
            "valued enforce_for_root directive must fail");
        require(
            readFile(passwordQualityPlatform.passwordQualityConfigPath) ==
                "enforce_for_root=1\n",
            "malformed flag failure modified canonical config");

        writeFile(passwordQualityPlatform.passwordQualityConfigPath, "");
        applyPasswordQualityAssignment<
            PamPasswordMinChangedCharactersPolicy>(
                root, passwordQualityPlatform,
                "password_min_changed_characters", "5", "difok", "5");
        writePasswordQualityGraph(" difok=4");
        writeIdentityConfig(
            root, "yes", "yes",
            "password_min_changed_characters.status=ENABLE\n"
            "password_min_changed_characters.value=5\n");
        PamPasswordMinChangedCharactersPolicy conflictingDifok(
            passwordQualityPlatform);
        require(
            !conflictingDifok.apply(),
            "difok PAM argument override must fail");
        writePasswordQualityGraph();
        writeIdentityConfig(
            root, "yes", "yes",
            "password_min_changed_characters.status=ENABLE\n"
            "password_min_changed_characters.value=-1\n");
        PamPasswordMinChangedCharactersPolicy invalidDifok(
            passwordQualityPlatform);
        require(!invalidDifok.apply(), "negative difok FIC value must fail");

        testMinimumCreditPolicy<PamPasswordMinLowercasePolicy>(
            root, passwordQualityPlatform,
            "password_min_lowercase", "lcredit");
        testMinimumCreditPolicy<PamPasswordMinUppercasePolicy>(
            root, passwordQualityPlatform,
            "password_min_uppercase", "ucredit");
        testMinimumCreditPolicy<PamPasswordMinDigitsPolicy>(
            root, passwordQualityPlatform,
            "password_min_digits", "dcredit");
        testMinimumCreditPolicy<PamPasswordMinOtherPolicy>(
            root, passwordQualityPlatform,
            "password_min_other", "ocredit");

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
        const std::string generatedIdentityConfig =
            readFile(FIC_GENERATED_IDENTITY_CONFIG_PATH);
        const std::string expectedRequiredPamDefault =
            std::string(FIC_TARGET_PLATFORM_NAME) == "alt-p11"
            ? "pam_faillock,pam_passwdqc"
            : "pam_faillock,pam_pwquality,pam_pwhistory";
        require(
            requiredPam.getPolicyTypeValue().getEditorSpec().editor ==
                    "textedit" &&
                requiredPam.getPolicyTypeValue().getEditorSpec().textDelimiter ==
                    "," &&
                requiredPam.validate("pam_faillock, pam_pwhistory") &&
                requiredPam.validate("pam_faillock, pam_pwquality") &&
                requiredPam.validate("pam_passwdqc") &&
                !requiredPam.validate("pam_vendor"),
            "required-PAM policy value contract is incorrect");
        require(
            requiredPam.getDefaultValue() == configuredValue(
                generatedIdentityConfig,
                "required_pam_enforcement.value") &&
                requiredPam.getDefaultValue() == expectedRequiredPamDefault,
            "required-PAM policy and generated config defaults diverged");
        require(
            configuredValue(
                generatedIdentityConfig,
                "required_pam_enforcement.status") == "DISABLE",
            "required-PAM generated status must remain disabled");
        require(
            requiredPam.getPolicyRestriction().find("pam_passwdqc") !=
                std::string::npos,
            "required-PAM editor metadata omits pam_passwdqc");
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

        writeIdentityConfig(
            root, "no", "no", "",
            "pam_passwdqc");
        writeFile(
            root / "pam.d/passwd",
            "password required pam_passwdqc.so\n"
            "password required pam_unix.so\n");
        writeFile(root / "security/pam_passwdqc.so", "test", 0555);
        RequiredPamEnforcementPolicy requiredPasswdqc(requiredPlatform);
        require(
            requiredPasswdqc.apply(),
            "required-PAM policy did not verify effective pam_passwdqc on "
            "password services");
        writeFile(
            root / "pam.d/passwd",
            "password required pam_unix.so\n");
        require(
            !requiredPasswdqc.apply(),
            "required-PAM policy accepted missing pam_passwdqc");
        writeFile(
            root / "pam.d/passwd",
            "password required pam_pwhistory.so\n");

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
