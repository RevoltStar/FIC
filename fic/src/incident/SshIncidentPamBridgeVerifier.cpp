#include "incident/SshIncidentPamBridgeVerifier.h"

#include <fic/core/process/VerifiedProcessExecutor.h>

#include <sstream>
#include <utility>

namespace fic::incident {
namespace {

bool proveLegacyServiceLaunch(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    const SshCommandRunner& runner,
    std::string& error) {
    std::filesystem::path sshd;
    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Sshd, sshd, error) ||
        !executables.resolve(platform::ExecutableId::Systemctl, systemctl, error)) {
        error = "legacy SSH PAM service launch proof unavailable: " + error;
        return false;
    }
    if (sshd.filename() != "sshd") {
        error = "trusted SSH executable is not named sshd";
        return false;
    }
    const SshCommandRunner command = runner ? runner : SshCommandRunner{
        [](const std::string& executable,
           const std::vector<std::string>& arguments,
           const ProcessOptions& options) {
            return VerifiedProcessExecutor::execute(
                executable, arguments, options);
        }};
    ProcessOptions options;
    options.clearEnvironment = true;
    bool loaded = false;
    for (const std::string& unit : platform.serviceUnits) {
        const ProcessResult result = command(
            systemctl.string(),
            {"show", "--property=LoadState", "--property=ExecStart", unit},
            options);
        if (!result.success()) {
            error = "failed to inspect SSH service launch " + unit;
            return false;
        }
        std::string loadState;
        std::string execStart;
        std::istringstream lines(result.standardOutput);
        std::string line;
        while (std::getline(lines, line)) {
            if (line.rfind("LoadState=", 0) == 0) {
                loadState = line.substr(10);
            } else if (line.rfind("ExecStart=", 0) == 0) {
                execStart = line.substr(10);
            }
        }
        if (loadState == "not-found") {
            continue;
        }
        if (loadState != "loaded") {
            error = "SSH service " + unit + " is not demonstrably loaded";
            return false;
        }
        loaded = true;
        const std::string pathToken = "{ path=";
        const std::string argvToken = " ; argv[]=";
        const std::size_t pathStart = execStart.find(pathToken);
        const std::size_t argvStart = execStart.find(argvToken);
        if (pathStart != 0 || argvStart == std::string::npos ||
            execStart.find(pathToken, pathToken.size()) != std::string::npos) {
            error = "SSH service " + unit + " has an unsupported ExecStart";
            return false;
        }
        const std::string path = execStart.substr(
            pathToken.size(), argvStart - pathToken.size());
        const std::size_t argStart = argvStart + argvToken.size();
        const std::size_t argEnd = execStart.find_first_of(" ;", argStart);
        const std::string argvZero = execStart.substr(
            argStart, argEnd - argStart);
        if (path != sshd.string() || argvZero != sshd.string()) {
            error = "SSH service " + unit +
                    " does not launch the trusted sshd with argv[0]=sshd";
            return false;
        }
    }
    if (!loaded) {
        error = "no declared SSH service unit is loaded";
        return false;
    }
    return true;
}

} // namespace

bool SshIncidentPamBridgeVerifier::prove(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error,
    SshCommandRunner runner) {
    if (platform.pamServiceRouting ==
        platform::SshPamServiceRouting::Unknown) {
        error = "SSH PAM service routing capability is unknown";
        return false;
    }

    SshRuntime runtime({platform.configPath, platform.includeBasePath,
                        platform.serviceUnits}, executables, runner);
    if (!runtime.verifyPolicyValue("UsePAM", "yes", error)) {
        error = "SSH UsePAM=yes is not proven: " + error;
        return false;
    }
    if (platform.pamServiceRouting ==
        platform::SshPamServiceRouting::ConfigurablePamServiceName &&
        !runtime.verifyPolicyValue("PAMServiceName", "sshd", error)) {
        error = "SSH PAM service sshd is not proven: " + error;
        return false;
    }
    if (platform.pamServiceRouting ==
            platform::SshPamServiceRouting::LegacyExecutableName &&
        !proveLegacyServiceLaunch(platform, executables, runner, error)) {
        error = "SSH PAM service sshd is not proven: " + error;
        return false;
    }
    error.clear();
    return true;
}

SshPamBridgeReadinessResult SshIncidentPamBridgeVerifier::evaluateReadiness(
    bool sshUsePamEnabled,
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    SshCommandRunner runner) {
    if (!sshUsePamEnabled) {
        return {true, true,
                "SSH IncidentAccessGate coverage is not guaranteed: "
                "ssh_use_pam is disabled"};
    }
    std::string error;
    if (!prove(platform, executables, error, std::move(runner))) {
        return {false, false,
                "SSH IncidentAccessGate bridge is not proven: " + error};
    }
    return {true, false, "SSH IncidentAccessGate bridge is proven"};
}

} // namespace fic::incident
