#include "incident/SshIncidentPamBridgeVerifier.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <sstream>
#include <sys/stat.h>
#include <utility>

namespace fic::incident {
namespace {

enum class ActualPamRouting { LegacyExecutableName, ConfigurablePamServiceName,
                              Unproven };

ActualPamRouting classifyPamRouting(
    const SshLaunchProof& launch,
    const platform::PlatformExecutableResolver& executables,
    const SshCommandRunner& runner,
    SshRuntime& runtime,
    std::string& error) {
    std::vector<std::string> values;
    std::string detail;
    if (runtime.effectiveValues("PAMServiceName", values, detail)) {
        if (values.size() == 1 && !values.front().empty())
            return ActualPamRouting::ConfigurablePamServiceName;
        error = "ambiguous PAMServiceName in trusted sshd output";
        return ActualPamRouting::Unproven;
    }
    if (detail.find("does not contain parameter PAMServiceName") ==
            std::string::npos) {
        error = "trusted sshd capability is inconclusive: " + detail;
        return ActualPamRouting::Unproven;
    }
    std::filesystem::path sshd;
    if (!executables.resolve(platform::ExecutableId::Sshd, sshd, error))
        return ActualPamRouting::Unproven;
    ProcessOptions options;
    options.clearEnvironment = true;
    std::vector<std::string> args{"-T"};
    args.insert(args.end(), launch.configurationArguments.begin(),
                launch.configurationArguments.end());
    args.insert(args.end(), {"-o", "PAMServiceName=fic-capability-probe"});
    const auto command = runner ? runner : SshCommandRunner{
        [](const std::string& executable, const std::vector<std::string>& arguments,
           const ProcessOptions& processOptions) {
            return VerifiedProcessExecutor::execute(executable, arguments, processOptions);
        }};
    const ProcessResult result = command(sshd.string(), args, options);
    if (result.success()) {
        std::istringstream output(result.standardOutput);
        std::string line;
        int matches = 0;
        while (std::getline(output, line)) {
            if (line == "pamservicename fic-capability-probe") ++matches;
        }
        if (matches == 1) return ActualPamRouting::ConfigurablePamServiceName;
    } else if (result.started && !result.timedOut) {
        std::string message = result.standardError;
        std::transform(message.begin(), message.end(), message.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (message.find("bad configuration option: pamservicename") !=
                std::string::npos ||
            message.find("unsupported option pamservicename") !=
                std::string::npos) {
            return ActualPamRouting::LegacyExecutableName;
        }
    }
    error = "trusted sshd PAMServiceName capability probe was inconclusive";
    return ActualPamRouting::Unproven;
}

} // namespace

bool SshIncidentPamBridgeVerifier::prove(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error,
    SshCommandRunner runner,
    SshProcessReader processReader) {
    const auto activation = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    if (activation.status != SshActivationStatus::Proven) {
        error = "SSH systemd activation is not proven: " + activation.diagnostic;
        return false;
    }
    for (const auto& launch : activation.launches) {
        SshRuntimeOptions options{launch.configPath,
                                  platform.includeBasePath,
                                  platform.serviceUnits};
        options.useLaunchArguments = true;
        options.launchArguments = launch.configurationArguments;
        options.requireTrustedInputs = true;
        SshRuntime runtime(std::move(options), executables, runner);
        if (!runtime.verifyPolicyValue("UsePAM", "yes", error)) {
            error = "SSH UsePAM=yes is not proven for " + launch.serviceUnit +
                    ": " + error;
            return false;
        }
        const auto routing = classifyPamRouting(
            launch, executables, runner, runtime, error);
        if (routing == ActualPamRouting::Unproven) return false;
        if (routing == ActualPamRouting::ConfigurablePamServiceName) {
            if (!runtime.verifyPolicyValue("PAMServiceName", "sshd", error)) {
                error = "SSH PAM service sshd is not proven for " +
                        launch.serviceUnit + ": " + error;
                return false;
            }
        } else if (std::filesystem::path(launch.argvZero).filename() != "sshd") {
            error = "legacy SSH PAM service name is not sshd for " +
                    launch.serviceUnit;
            return false;
        }
    }
    std::filesystem::path sshd;
    if (!executables.resolve(platform::ExecutableId::Sshd, sshd, error))
        return false;
    struct stat current {};
    if (::stat(sshd.c_str(), &current) != 0 ||
        static_cast<std::uint64_t>(current.st_dev) != activation.trustedDevice ||
        static_cast<std::uint64_t>(current.st_ino) != activation.trustedInode) {
        error = "trusted sshd changed during bridge verification";
        return false;
    }
    const auto confirmation = SshSystemdActivationVerifier::prove(
        platform, executables, runner, processReader);
    if (confirmation.status != SshActivationStatus::Proven ||
        confirmation.trustedDevice != activation.trustedDevice ||
        confirmation.trustedInode != activation.trustedInode ||
        confirmation.launches.size() != activation.launches.size()) {
        error = "SSH activation changed during bridge verification";
        return false;
    }
    for (std::size_t index = 0; index < activation.launches.size(); ++index) {
        const auto& initial = activation.launches[index];
        const auto& final = confirmation.launches[index];
        if (initial.serviceUnit != final.serviceUnit ||
            initial.argvZero != final.argvZero ||
            initial.configurationArguments != final.configurationArguments ||
            initial.configPath != final.configPath ||
            initial.activeProcess != final.activeProcess) {
            error = "SSH launch changed during bridge verification";
            return false;
        }
    }
    error.clear();
    return true;
}

SshPamBridgeReadinessResult SshIncidentPamBridgeVerifier::evaluateReadiness(
    bool sshUsePamEnabled,
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    SshCommandRunner runner,
    SshProcessReader processReader) {
    if (!sshUsePamEnabled) {
        return {true, true,
                "SSH IncidentAccessGate coverage is not guaranteed: "
                "ssh_use_pam is disabled"};
    }
    std::string error;
    if (!prove(platform, executables, error,
               std::move(runner), std::move(processReader))) {
        return {false, false,
                "SSH IncidentAccessGate bridge is not proven: " + error};
    }
    return {true, false, "SSH IncidentAccessGate bridge is proven"};
}

} // namespace fic::incident
