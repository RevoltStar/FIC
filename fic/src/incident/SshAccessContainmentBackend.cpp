#include "incident/SshAccessContainmentBackend.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <filesystem>
#include <vector>

namespace fic::incident {
namespace {
SshCommandRunner commandRunner(SshCommandRunner runner) {
    if (runner) return runner;
    return [](const std::string& executable, const std::vector<std::string>& args,
              const ProcessOptions& options) {
        return VerifiedProcessExecutor::execute(executable, args, options);
    };
}

bool unitState(const std::string& systemctl, const std::string& unit,
               const SshCommandRunner& runner, std::string& state,
               std::string& error) {
    ProcessOptions clean;
    clean.clearEnvironment = true;
    const auto result = runner(systemctl,
                               {"show", "--property=ActiveState", unit}, clean);
    if (!result.success()) {
        error = "cannot inspect SSH listener " + unit;
        return false;
    }
    const std::string prefix = "ActiveState=";
    if (result.standardOutput.rfind(prefix, 0) != 0 ||
        result.standardOutput.empty() || result.standardOutput.back() != '\n' ||
        result.standardOutput.find('\n') != result.standardOutput.size() - 1) {
        error = "SSH listener state is unproven: " + unit;
        return false;
    }
    state = result.standardOutput.substr(prefix.size(),
                                         result.standardOutput.size() - prefix.size() - 1);
    if (state != "active" && state != "inactive" && state != "activating" &&
        state != "deactivating" && state != "failed") {
        error = "SSH listener state is unproven: " + unit;
        return false;
    }
    return true;
}

bool change(const std::string& systemctl, const std::string& action,
            const std::string& unit, const SshCommandRunner& runner,
            std::string& error) {
    ProcessOptions clean;
    clean.clearEnvironment = true;
    if (!runner(systemctl, {action, unit}, clean).success()) {
        error = "SSH " + action + " failed: " + unit;
        return false;
    }
    std::string state;
    if (!unitState(systemctl, unit, runner, state, error)) return false;
    if (state != (action == "start" ? "active" : "inactive")) {
        error = "SSH " + action + " did not reach expected state: " + unit;
        return false;
    }
    return true;
}
} // namespace

bool SshAccessContainmentBackend::block(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner) {
    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    runner = commandRunner(std::move(runner));
    const auto stop = [&](const std::string& unit, std::set<std::string>& owned) {
        std::string state;
        if (!unitState(systemctl.string(), unit, runner, state, error)) return false;
        if (state == "inactive") return true;
        // Remember ownership before the action: if systemctl exits after
        // stopping the unit, a later pass may still restore FIC's change.
        owned.insert(unit);
        return change(systemctl.string(), "stop", unit, runner, error);
    };
    for (const auto& unit : platform.socketUnits)
        if (!stop(unit, stoppedSockets_)) return false;
    for (const auto& unit : platform.serviceUnits)
        if (!stop(unit, stoppedServices_)) return false;
    error.clear();
    return true;
}

bool SshAccessContainmentBackend::restore(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner) {
    (void)platform;
    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    runner = commandRunner(std::move(runner));
    for (auto it = stoppedServices_.begin(); it != stoppedServices_.end();) {
        if (!change(systemctl.string(), "start", *it, runner, error)) return false;
        it = stoppedServices_.erase(it);
    }
    for (auto it = stoppedSockets_.begin(); it != stoppedSockets_.end();) {
        if (!change(systemctl.string(), "start", *it, runner, error)) return false;
        it = stoppedSockets_.erase(it);
    }
    error.clear();
    return true;
}

} // namespace fic::incident
