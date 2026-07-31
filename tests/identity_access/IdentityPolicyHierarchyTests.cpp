#include "modules/identity_access/submodules/composite/CompositePolicy.h"
#include "modules/identity_access/submodules/kerberos/KerberosPolicy.h"
#include "modules/identity_access/submodules/nss/NssPolicy.h"
#include "modules/identity_access/submodules/pam/PamPolicy.h"
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
#include <unistd.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
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

    std::ofstream config(paths.configDir / "IDENTITY_ACCESS.conf");
    config << "dummy.status=ENABLE\n"
              "dummy.value=expected\n";
    config.close();

    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
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
    bool applySssd(const std::string& expectedValue) override {
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
    bool applyKerberos(const std::string& expectedValue) override {
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
    bool applyNss(const std::string& expectedValue) override {
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

        DummyPamPolicy pam;
        DummySssdPolicy sssd;
        DummyKerberosPolicy kerberos;
        DummyNssPolicy nss;
        std::vector<std::string> observedValues;
        std::vector<std::string> compositeEvents;
        DummyCompositePolicy composite(observedValues, compositeEvents);

        requireLeaf(pam, "PAM");
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
