#include "incident/SshIncidentPamRuntimeReconciler.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <set>
#include <utility>

namespace fic::incident {

SshPamBridgeReadinessResult SshIncidentPamRuntimeReconciler::evaluateReadiness(
    bool sshUsePamEnabled,
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    SshCommandRunner runner, SshProcessReader processReader) {
    if (!sshUsePamEnabled)
        return SshIncidentPamBridgeVerifier::evaluateReadiness(
            false, platform, executables);
    std::string error;
    if (!reconcile(platform, executables, error,
                   std::move(runner), std::move(processReader)))
        return {false, false, "SSH runtime reconciliation failed: " + error};
    return {true, false, "SSH IncidentAccessGate bridge is proven after reload"};
}

bool SshIncidentPamRuntimeReconciler::reconcile(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner, SshProcessReader processReader) {
    if (!SshIncidentPamBridgeVerifier::prove(
            platform, executables, error, runner, processReader)) return false;
    const auto before = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    if (before.status != SshActivationStatus::Proven) {
        error = before.diagnostic;
        return false;
    }
    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    if (!runner) runner = [](const std::string& executable,
                             const std::vector<std::string>& args,
                             const ProcessOptions& options) {
        return VerifiedProcessExecutor::execute(executable, args, options);
    };
    std::set<std::string> reloaded;
    for (const auto& launch : before.launches) {
        if (!launch.activeProcess || !reloaded.insert(launch.serviceUnit).second)
            continue;
        ProcessOptions options;
        options.clearEnvironment = true;
        const auto result = runner(systemctl.string(),
                                   {"reload", launch.serviceUnit}, options);
        if (!result.success()) {
            error = "SSH service reload failed: " + launch.serviceUnit;
            return false;
        }
    }
    if (!SshIncidentPamBridgeVerifier::prove(
            platform, executables, error, runner, processReader)) return false;
    const auto after = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    if (after.status != SshActivationStatus::Proven ||
        before.trustedDevice != after.trustedDevice ||
        before.trustedInode != after.trustedInode) {
        error = "SSH service identity changed after reload";
        return false;
    }
    for (const auto& unit : reloaded) {
        bool active = false;
        for (const auto& launch : after.launches)
            active |= launch.serviceUnit == unit && launch.activeProcess;
        if (!active) {
            error = "SSH service is no longer active after reload: " + unit;
            return false;
        }
    }
    error.clear();
    return true;
}

} // namespace fic::incident
