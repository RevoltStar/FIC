#include "modules/identity_access/sssd/SssdRuntime.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <filesystem>
#include <utility>

namespace fic::identity::sssd {
namespace {

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "command timed out";
    }
    if (!result.standardError.empty()) {
        return result.standardError;
    }
    return "exit code " + std::to_string(result.exitCode);
}

class SssdRuntimeChange final : public PreparedConfigurationChange {
public:
    SssdRuntimeChange(
        std::unique_ptr<PreparedConfigurationChange> persistent,
        std::filesystem::path systemctl,
        std::string activeUnit,
        SssdCommandRunner runner)
        : persistent_(std::move(persistent)),
          systemctl_(std::move(systemctl)),
          activeUnit_(std::move(activeUnit)),
          runner_(std::move(runner)) {
    }

    std::string id() const override {
        return persistent_->id();
    }

    bool needsCommit() const noexcept override {
        return persistent_->needsCommit();
    }

    bool needsActivation() const noexcept override {
        return persistent_->needsCommit() && !activeUnit_.empty();
    }

    ConfigurationStepResult commitPersistent() override {
        return persistent_->commitPersistent();
    }

    ConfigurationStepResult verifyPersistent() override {
        return persistent_->verifyPersistent();
    }

    ConfigurationStepResult activate() override {
        activationAttempted_ = true;
        return restart("restart");
    }

    ConfigurationStepResult verifyEffective() override {
        const auto persistent = persistent_->verifyPersistent();
        if (!persistent.ok || activeUnit_.empty()) {
            return persistent;
        }
        ProcessOptions options;
        options.clearEnvironment = true;
        const auto status = runner_(
            systemctl_.string(), {"is-active", "--quiet", activeUnit_}, options);
        if (!status.success()) {
            return ConfigurationStepResult::failure(
                activeUnit_ + " is not active after restart: " +
                processFailure(status));
        }
        return ConfigurationStepResult::success();
    }

    ConfigurationStepResult rollbackPersistent() override {
        return persistent_->rollbackPersistent();
    }

    ConfigurationStepResult restoreRuntimeAfterRollback() override {
        if (!activationAttempted_ || activeUnit_.empty()) {
            return ConfigurationStepResult::success();
        }
        return restart("restart after rollback");
    }

    ConfigurationStepResult verifyRollback() override {
        const auto persistent = persistent_->verifyRollback();
        if (!persistent.ok || !activationAttempted_ || activeUnit_.empty()) {
            return persistent;
        }
        ProcessOptions options;
        options.clearEnvironment = true;
        const auto status = runner_(
            systemctl_.string(), {"is-active", "--quiet", activeUnit_}, options);
        if (!status.success()) {
            return ConfigurationStepResult::failure(
                activeUnit_ + " is not active after rollback: " +
                processFailure(status));
        }
        return ConfigurationStepResult::success();
    }

private:
    ConfigurationStepResult restart(const std::string& operation) {
        ProcessOptions options;
        options.clearEnvironment = true;
        const auto result = runner_(
            systemctl_.string(), {"restart", activeUnit_}, options);
        if (!result.success()) {
            return ConfigurationStepResult::failure(
                "failed to " + operation + " " + activeUnit_ + ": " +
                processFailure(result));
        }
        return ConfigurationStepResult::success(true);
    }

    std::unique_ptr<PreparedConfigurationChange> persistent_;
    std::filesystem::path systemctl_;
    std::string activeUnit_;
    SssdCommandRunner runner_;
    bool activationAttempted_ = false;
};

} // namespace

SssdRuntime::SssdRuntime(
    const fic::platform::PlatformExecutableResolver& executables,
    std::vector<std::string> serviceUnits,
    SssdCommandRunner runner)
    : executables_(executables),
      serviceUnits_(std::move(serviceUnits)),
      runner_(std::move(runner)) {
    if (!runner_) {
        runner_ = VerifiedProcessExecutor::execute;
    }
}

ConfigurationPreparationResult SssdRuntime::attach(
    std::unique_ptr<PreparedConfigurationChange> persistentChange) const {
    if (persistentChange == nullptr) {
        return {nullptr, "cannot attach SSSD runtime to a null change"};
    }
    if (!persistentChange->needsCommit()) {
        return {
            std::make_unique<SssdRuntimeChange>(
                std::move(persistentChange),
                std::filesystem::path{},
                std::string{},
                runner_),
            {}};
    }

    std::filesystem::path systemctl;
    std::string error;
    if (!executables_.resolve(
            fic::platform::ExecutableId::Systemctl, systemctl, error)) {
        return {nullptr, "SSSD runtime activation is unavailable: " + error};
    }

    ProcessOptions options;
    options.clearEnvironment = true;
    std::string activeUnit;
    for (const auto& unit : serviceUnits_) {
        const auto status = runner_(
            systemctl.string(), {"is-active", "--quiet", unit}, options);
        if (!status.started || status.timedOut || !status.error.empty()) {
            return {
                nullptr,
                "failed to inspect SSSD service " + unit + ": " +
                    processFailure(status)};
        }
        if (status.success()) {
            activeUnit = unit;
            break;
        }
        if (status.exitCode != 3 && status.exitCode != 4) {
            return {
                nullptr,
                "failed to inspect SSSD service " + unit + ": " +
                    processFailure(status)};
        }
    }

    return {
        std::make_unique<SssdRuntimeChange>(
            std::move(persistentChange),
            std::move(systemctl),
            std::move(activeUnit),
            runner_),
        {}};
}

} // namespace fic::identity::sssd
