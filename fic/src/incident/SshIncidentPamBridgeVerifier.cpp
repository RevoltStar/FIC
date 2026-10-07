#include "incident/SshIncidentPamBridgeVerifier.h"

#include "modules/net/ssh/SshInputAuthority.h"

#include <fic/core/fs/TrustedFileReader.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::incident {
namespace {
using Properties = std::map<std::string, std::string>;

SshCommandRunner commandRunner(SshCommandRunner runner) {
    if (runner) return runner;
    return [](const std::string& executable, const std::vector<std::string>& args,
              const ProcessOptions& options) {
        return VerifiedProcessExecutor::execute(executable, args, options);
    };
}

bool showUnit(const std::string& systemctl, const std::string& unit,
              const SshCommandRunner& runner, Properties& props, std::string& error) {
    ProcessOptions options;
    options.clearEnvironment = true;
    const auto result = runner(systemctl,
        {"show", "--property=Id", "--property=Names", "--property=LoadState",
         "--property=ActiveState", "--property=MainPID", "--property=ExecStart",
         "--property=ExecCondition", "--property=ExecStartPre",
         "--property=ExecStartPost", "--property=Environment",
         "--property=EnvironmentFiles", "--property=PassEnvironment",
         "--property=UnsetEnvironment", "--property=RootDirectory",
         "--property=RootImage", "--property=User", "--property=Group",
         "--property=DynamicUser", "--property=NoNewPrivileges",
         "--property=Type", "--property=Triggers", "--property=Accept", unit},
        options);
    if (!result.success()) {
        error = "cannot inspect SSH unit " + unit;
        return false;
    }
    std::istringstream lines(result.standardOutput);
    std::string line;
    while (std::getline(lines, line)) {
        const auto equal = line.find('=');
        if (equal == std::string::npos || equal == 0 ||
            !props.emplace(line.substr(0, equal), line.substr(equal + 1)).second) {
            error = "malformed SSH unit properties: " + unit;
            return false;
        }
    }
    if (!lines.eof()) {
        error = "incomplete SSH unit properties: " + unit;
        return false;
    }
    return true;
}

bool command(const std::string& group, const std::string& path,
             const std::string& argv) {
    const std::string prefix = "{ path=" + path + " ; argv[]=" + argv +
                               " ; ignore_errors=no";
    if (group.rfind(prefix, 0) != 0 || group.size() < prefix.size() + 2 ||
        group.compare(group.size() - 2, 2, " }") != 0)
        return false;
    std::string metadata = group.substr(prefix.size(),
                                        group.size() - prefix.size() - 2);
    while (!metadata.empty()) {
        if (metadata.rfind(" ; ", 0) != 0) return false;
        metadata.erase(0, 3);
        const auto next = metadata.find(" ; ");
        const auto field = metadata.substr(0, next);
        if (field.rfind("start_time=", 0) != 0 &&
            field.rfind("stop_time=", 0) != 0 &&
            field.rfind("pid=", 0) != 0 &&
            field.rfind("code=", 0) != 0 &&
            field.rfind("status=", 0) != 0)
            return false;
        metadata = next == std::string::npos ? "" : metadata.substr(next);
    }
    return true;
}

bool stockPrehooks(const std::string& value, const std::string& sshd,
                   std::string& error) {
    if (value.empty()) return true;
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto end = value.find(" }", offset);
        if (end == std::string::npos) return false;
        const auto group = value.substr(offset, end + 2 - offset);
        if (!command(group, sshd, sshd + " -t") &&
            !(command(group, "/usr/bin/ssh-keygen", "/usr/bin/ssh-keygen -A") &&
              ssh::trustedSshInput("/usr/bin/ssh-keygen", false, false, error)))
            return false;
        offset = end + 2;
        if (offset < value.size() && value[offset++] != ' ') return false;
    }
    return true;
}

bool stockOptionFile(const platform::SshPlatformConfig& platform,
                     std::string& error) {
    const auto path = platform.optionFile;
    if (path.empty() || !ssh::trustedSshInput(
            path, false, platform.optionFileOptional, error)) return false;
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    std::string content;
    int systemError = 0;
    if (!fic::core::readTrustedFile(path, options, content, error,
                                    nullptr, {}, &systemError)) {
        if (platform.optionFileOptional && systemError == ENOENT &&
            ssh::trustedSshInput(path, false, true, error)) {
            error.clear();
            return true;
        }
        return false;
    }
    if (content.size() > 4096) {
        error = "SSH option file is too large";
        return false;
    }
    std::istringstream lines(content);
    std::string line;
    bool seen = false;
    while (std::getline(lines, line)) {
        if (line.empty() || line.front() == '#') continue;
        if (seen || line != platform.optionVariable + "=") {
            error = "custom SSH option file is not supported by ACTIVE mode";
            return false;
        }
        seen = true;
    }
    return lines.eof();
}

struct Topology {
    std::vector<std::string> activeServices;
};

bool inspect(const platform::SshPlatformConfig& platform,
             const platform::PlatformExecutableResolver& executables,
             const SshCommandRunner& runner, bool current,
             Topology& topology, std::string& error,
             const SshMainProcessVerifier& processVerifier) {
    if (platform.serviceUnits.empty() || platform.socketUnits.empty() ||
        platform.optionVariable.empty()) {
        error = "SSH package topology is not declared";
        return false;
    }
    std::filesystem::path sshd, systemctl;
    if (!executables.resolve(platform::ExecutableId::Sshd, sshd, error) ||
        !executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    struct stat trusted {};
    if (::stat(sshd.c_str(), &trusted) != 0) {
        error = "trusted sshd is unavailable";
        return false;
    }
    if (!stockOptionFile(platform, error)) return false;
    const std::set<std::string> declared(platform.serviceUnits.begin(),
                                          platform.serviceUnits.end());
    std::set<std::string> loaded;
    for (const auto& name : platform.serviceUnits) {
        Properties props;
        if (!showUnit(systemctl.string(), name, runner, props, error)) return false;
        if (props["LoadState"] == "not-found") continue;
        const auto unit = props["Id"];
        if (props["LoadState"] != "loaded" || !declared.count(unit)) {
            error = "unsupported SSH service identity: " + name;
            return false;
        }
        if (!loaded.insert(unit).second) continue;
        const auto state = props["ActiveState"];
        if (state != "active" && state != "inactive") {
            error = "unsupported SSH service state: " + unit;
            return false;
        }
        if (props["Type"] != "simple" && props["Type"] != "notify") {
            error = "unsupported SSH service type: " + unit;
            return false;
        }
        if (!props["ExecCondition"].empty() || !props["ExecStartPost"].empty() ||
            !stockPrehooks(props["ExecStartPre"], sshd.string(), error)) {
            error = "custom SSH lifecycle hook is not supported: " + unit;
            return false;
        }
        if (!props["Environment"].empty() || !props["PassEnvironment"].empty() ||
            !props["UnsetEnvironment"].empty() ||
            !props["RootDirectory"].empty() || !props["RootImage"].empty() ||
            !props["User"].empty() || !props["Group"].empty() ||
            props["DynamicUser"] != "no" ||
            props["NoNewPrivileges"] != "no") {
            error = "custom SSH execution context is not supported: " + unit;
            return false;
        }
        const std::string expectedFile = platform.optionFile.string() +
            (platform.optionFileOptional ? " (ignore_errors=yes)" :
                                           " (ignore_errors=no)");
        if (props["EnvironmentFiles"] != expectedFile ||
            !command(props["ExecStart"], sshd.string(), sshd.string() +
                     " -D $" + platform.optionVariable)) {
            error = "custom sshd ExecStart or option file is not supported: " + unit;
            return false;
        }
        if (state == "active") {
            topology.activeServices.push_back(unit);
            if (current) {
                const std::string pidText = props["MainPID"];
                unsigned int pid = 0;
                const auto parsed = std::from_chars(
                    pidText.data(), pidText.data() + pidText.size(), pid);
                if (parsed.ec != std::errc() || parsed.ptr != pidText.data() +
                    pidText.size() || pid == 0) {
                    error = "active SSH service has no MainPID: " + unit;
                    return false;
                }
                bool trustedProcess = false;
                if (processVerifier) {
                    trustedProcess = processVerifier(pid, sshd, error);
                } else {
                    struct stat actual {};
                    trustedProcess =
                        ::stat(("/proc/" + std::to_string(pid) + "/exe").c_str(),
                               &actual) == 0 && actual.st_dev == trusted.st_dev &&
                        actual.st_ino == trusted.st_ino;
                }
                if (!trustedProcess) {
                    error = "active SSH service executable is not trusted: " + unit;
                    return false;
                }
            }
        }
    }
    if (loaded.empty()) {
        error = "no declared SSH service is loaded";
        return false;
    }
    for (const auto& socket : platform.socketUnits) {
        Properties props;
        if (!showUnit(systemctl.string(), socket, runner, props, error)) return false;
        if (props["LoadState"] == "not-found") continue;
        if (props["LoadState"] != "loaded" ||
            (props["ActiveState"] != "active" &&
             props["ActiveState"] != "inactive") ||
            props["Accept"] != "no" || !loaded.count(props["Triggers"])) {
            error = "unsupported SSH socket activation topology: " + socket;
            return false;
        }
    }
    SshRuntimeOptions options;
    options.configPath = platform.configPath;
    options.includeBasePath = platform.includeBasePath;
    options.serviceUnits = platform.serviceUnits;
    options.requireTrustedInputs = true;
    SshRuntime runtime(options, executables, runner);
    if (!runtime.verifyPolicyValue("UsePAM", "yes", error)) return false;
    std::vector<std::string> values;
    std::string detail;
    if (runtime.effectiveValues("PAMServiceName", values, detail)) {
        if (values != std::vector<std::string>{"sshd"}) {
            error = "SSH PAMServiceName is not sshd";
            return false;
        }
    } else if (detail.find("does not contain parameter PAMServiceName") !=
               std::string::npos) {
        ProcessOptions clean;
        clean.clearEnvironment = true;
        const auto result = runner(sshd.string(),
            {"-T", "-f", platform.configPath.string(), "-o",
             "PAMServiceName=fic-capability-probe"}, clean);
        std::string message = result.standardError;
        std::transform(message.begin(), message.end(), message.begin(),
                       [](unsigned char ch) { return std::tolower(ch); });
        if (result.success() || !result.started || result.timedOut ||
            (message.find("bad configuration option: pamservicename") ==
                 std::string::npos &&
             message.find("unsupported option pamservicename") ==
                 std::string::npos)) {
            error = "legacy SSH PAM routing is not proven";
            return false;
        }
    } else {
        error = "SSH PAM routing is not proven: " + detail;
        return false;
    }
    error.clear();
    return true;
}
} // namespace

bool SshIncidentPamBridgeVerifier::proveFuture(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner) {
    Topology topology;
    return inspect(platform, executables, commandRunner(std::move(runner)),
                   false, topology, error, {});
}

bool SshIncidentPamBridgeVerifier::proveCurrent(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner,
    SshMainProcessVerifier processVerifier) {
    Topology topology;
    return inspect(platform, executables, commandRunner(std::move(runner)),
                   true, topology, error, processVerifier);
}

bool SshIncidentPamBridgeVerifier::activate(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    std::string& error, SshCommandRunner runner,
    SshMainProcessVerifier processVerifier) {
    runner = commandRunner(std::move(runner));
    Topology before;
    if (!inspect(platform, executables, runner, false, before, error, {})) return false;
    std::filesystem::path systemctl;
    if (!executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return false;
    for (const auto& unit : before.activeServices) {
        ProcessOptions clean;
        clean.clearEnvironment = true;
        if (!runner(systemctl.string(), {"restart", unit}, clean).success()) {
            error = "SSH restart failed: " + unit;
            return false;
        }
    }
    Topology after;
    if (!inspect(platform, executables, runner, true, after, error,
                 processVerifier)) return false;
    for (const auto& unit : before.activeServices)
        if (std::find(after.activeServices.begin(), after.activeServices.end(), unit) ==
            after.activeServices.end()) {
            error = "SSH service did not return active: " + unit;
            return false;
        }
    return true;
}

} // namespace fic::incident
