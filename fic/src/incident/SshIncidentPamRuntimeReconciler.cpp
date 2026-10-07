#include "incident/SshIncidentPamRuntimeReconciler.h"
#include "modules/net/ssh/SshConfigAudit.h"

#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <set>
#include <utility>

namespace fic::incident {
namespace {

void appendField(std::string& output, const std::string& value) {
    output += std::to_string(value.size()) + ":" + value;
}

bool proofIdentity(const SshActivationProof& proof,
                   const platform::SshPlatformConfig& platform,
                   std::string& identity, std::string& error) {
    if (proof.status != SshActivationStatus::Proven) {
        error = proof.diagnostic;
        return false;
    }
    std::string parts;
    appendField(parts, std::to_string(proof.trustedDevice));
    appendField(parts, std::to_string(proof.trustedInode));
    appendField(parts, std::to_string(proof.services.size()));
    for (const auto& service : proof.services) {
        appendField(parts, service.unit);
        appendField(parts, service.effectiveIdentity);
    }
    appendField(parts, std::to_string(proof.launches.size()));
    for (const auto& launch : proof.launches) {
        SshConfigAuditOptions options;
        options.configPath = launch.configPath;
        options.includeBasePath = platform.includeBasePath;
        options.requireTrustedInputs = true;
        std::string sources;
        if (!SshConfigAudit(options).sourceIdentity(sources, error)) return false;
        appendField(parts, launch.serviceUnit);
        appendField(parts, launch.argvZero);
        appendField(parts, launch.configPath.string());
        appendField(parts, sources);
        appendField(parts, std::to_string(launch.mainPid));
        appendField(parts, launch.startTime);
        appendField(parts, std::to_string(launch.arguments.size()));
        for (const auto& arg : launch.arguments)
            appendField(parts, arg);
        appendField(parts, std::to_string(launch.configurationArguments.size()));
        for (const auto& arg : launch.configurationArguments)
            appendField(parts, arg);
    }
    identity = fic::core::ContentDigest::sha256Hex(parts);
    error.clear();
    return true;
}

const SshLaunchProof* activeLaunch(const SshActivationProof& proof,
                                   const std::string& unit) {
    for (const auto& launch : proof.launches)
        if (launch.serviceUnit == unit && launch.activeProcess) return &launch;
    return nullptr;
}

} // namespace

SshPamBridgeReadinessResult SshIncidentPamRuntimeReconciler::evaluateReadiness(
    bool sshUsePamEnabled,
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    SshCommandRunner runner, SshProcessReader processReader) {
    if (!sshUsePamEnabled) {
        reconciledIdentity_.clear();
        reconciledEpoch_ = 0;
        return SshIncidentPamBridgeVerifier::evaluateReadiness(
            false, platform, executables);
    }
    std::string error;
    if (!reconcile(platform, executables, error,
                   std::move(runner), std::move(processReader))) {
        reconciledIdentity_.clear();
        reconciledEpoch_ = 0;
        return {false, false, "SSH runtime reconciliation failed: " + error};
    }
    return {true, false, "SSH IncidentAccessGate runtime bridge is proven"};
}

bool SshIncidentPamRuntimeReconciler::reconcile(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner, SshProcessReader processReader) {
    const auto activationEpoch = SshRuntime::activationEpoch();
    const auto before = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    std::string beforeIdentity;
    if (!proofIdentity(before, platform, beforeIdentity, error)) return false;
    if (!SshIncidentPamBridgeVerifier::prove(
            platform, executables, error, runner, processReader)) return false;
    const auto confirmed = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    std::string confirmedIdentity;
    if (!proofIdentity(confirmed, platform, confirmedIdentity, error) ||
        beforeIdentity != confirmedIdentity ||
        activationEpoch != SshRuntime::activationEpoch()) {
        if (error.empty()) error = "SSH activation or source changed during read-only proof";
        return false;
    }
    if (reconciledIdentity_ == beforeIdentity &&
        reconciledEpoch_ == activationEpoch) return true;

    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    if (!runner) runner = [](const std::string& executable,
                             const std::vector<std::string>& args,
                             const ProcessOptions& options) {
        return VerifiedProcessExecutor::execute(executable, args, options);
    };
    std::set<std::string> restarted;
    std::set<std::string> reloaded;
    for (const auto& service : before.services) {
        if (!activeLaunch(before, service.unit)) continue;
        const bool synchronous = service.reconciliation ==
            SshRuntimeReconciliationKind::SynchronousReload;
        ProcessOptions options;
        options.clearEnvironment = true;
        const auto result = runner(systemctl.string(),
                                   {synchronous ? "reload" : "restart", service.unit},
                                   options);
        if (!result.success()) {
            error = "SSH service reconciliation failed: " + service.unit;
            return false;
        }
        if (synchronous) reloaded.insert(service.unit);
        else restarted.insert(service.unit);
    }
    if (!SshIncidentPamBridgeVerifier::prove(
            platform, executables, error, runner, processReader)) return false;
    const auto after = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    std::string afterIdentity;
    if (!proofIdentity(after, platform, afterIdentity, error)) return false;
    if (before.trustedDevice != after.trustedDevice ||
        before.trustedInode != after.trustedInode ||
        before.services.size() != after.services.size()) {
        error = "SSH service identity changed after reconciliation";
        return false;
    }
    for (std::size_t i = 0; i < before.services.size(); ++i) {
        if (before.services[i].unit != after.services[i].unit ||
            before.services[i].effectiveIdentity != after.services[i].effectiveIdentity) {
            error = "SSH service lifecycle changed after reconciliation";
            return false;
        }
    }
    for (const auto& unit : restarted) {
        const auto* oldLaunch = activeLaunch(before, unit);
        const auto* newLaunch = activeLaunch(after, unit);
        if (!oldLaunch || !newLaunch ||
            (oldLaunch->mainPid == newLaunch->mainPid &&
             oldLaunch->startTime == newLaunch->startTime)) {
            error = "SSH restart did not prove a new process generation: " + unit;
            return false;
        }
    }
    for (const auto& unit : reloaded)
        if (!activeLaunch(after, unit)) {
            error = "SSH service is no longer active after reload: " + unit;
            return false;
        }
    for (const auto& service : after.services)
        if (reloaded.count(service.unit) && service.reloadResult != "success") {
            error = "SSH synchronous reload result is not proven successful: " +
                    service.unit;
            return false;
        }
    // Recheck source identity after all runtime actions. A transaction that
    // performed an asynchronous HUP advances the activation epoch and cannot
    // reuse a previous reconciliation result even if source bytes were restored.
    const auto stable = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    std::string stableIdentity;
    if (!proofIdentity(stable, platform, stableIdentity, error) ||
        stableIdentity != afterIdentity ||
        activationEpoch != SshRuntime::activationEpoch()) {
        if (error.empty()) error = "SSH source changed after reconciliation";
        return false;
    }
    reconciledIdentity_ = std::move(afterIdentity);
    reconciledEpoch_ = activationEpoch;
    error.clear();
    return true;
}

} // namespace fic::incident
