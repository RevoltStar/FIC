#include "incident/SshSystemdActivationVerifier.h"
#include "modules/net/ssh/SshInputAuthority.h"

#include <fic/core/process/VerifiedProcessExecutor.h>
#include <fic/core/fs/TrustedFileReader.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <utility>

namespace fic::incident {
namespace {

using Properties = std::map<std::string, std::string>;

bool parseProperties(const std::string& output, Properties& properties) {
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        const auto equal = line.find('=');
        if (equal == std::string::npos || equal == 0 ||
            !properties.emplace(line.substr(0, equal), line.substr(equal + 1)).second) {
            return false;
        }
    }
    return !properties.empty();
}

bool readProcess(unsigned int pid, SshProcessSnapshot& result, std::string& error) {
    const std::string base = "/proc/" + std::to_string(pid);
    const auto statStart = [&](std::string& start) {
        std::ifstream stream(base + "/stat");
        std::string line;
        if (!std::getline(stream, line)) return false;
        const auto end = line.rfind(") ");
        if (end == std::string::npos) return false;
        std::istringstream fields(line.substr(end + 2));
        std::string field;
        // The suffix begins at field 3; starttime is field 22.
        for (int index = 3; index <= 22; ++index) {
            if (!(fields >> field)) return false;
        }
        start = field;
        return true;
    };
    std::string before, after;
    if (!statStart(before)) {
        error = "cannot read SSH process start time";
        return false;
    }
    struct stat info {};
    if (::stat((base + "/exe").c_str(), &info) != 0) {
        error = "cannot identify SSH process executable";
        return false;
    }
    struct stat processRoot {}, hostRoot {}, processMount {}, hostMount {};
    if (::stat((base + "/root").c_str(), &processRoot) != 0 ||
        ::stat("/", &hostRoot) != 0 ||
        ::stat((base + "/ns/mnt").c_str(), &processMount) != 0 ||
        ::stat("/proc/self/ns/mnt", &hostMount) != 0 ||
        processRoot.st_dev != hostRoot.st_dev ||
        processRoot.st_ino != hostRoot.st_ino ||
        processMount.st_dev != hostMount.st_dev ||
        processMount.st_ino != hostMount.st_ino) {
        error = "SSH process filesystem view differs from verifier";
        return false;
    }
    std::ifstream stream(base + "/cmdline", std::ios::binary);
    const std::string data{std::istreambuf_iterator<char>(stream),
                           std::istreambuf_iterator<char>()};
    if (!stream.eof() || data.empty() || data.back() != '\0') {
        error = "cannot read complete SSH process argv";
        return false;
    }
    std::vector<std::string> argv;
    std::size_t pos = 0;
    while (pos < data.size()) {
        const auto end = data.find('\0', pos);
        if (end == std::string::npos || end == pos) {
            error = "malformed SSH process argv";
            return false;
        }
        argv.push_back(data.substr(pos, end - pos));
        pos = end + 1;
    }
    if (!statStart(after) || before != after) {
        error = "SSH process changed during inspection";
        return false;
    }
    result = {static_cast<std::uint64_t>(info.st_dev),
              static_cast<std::uint64_t>(info.st_ino), before, std::move(argv)};
    return true;
}

bool words(const std::string& input, std::vector<std::string>& out) {
    std::string value;
    char quote = 0;
    bool escaped = false, token = false;
    for (char c : input) {
        if (escaped) { value += c; escaped = false; token = true; continue; }
        if (c == '\\') { escaped = true; token = true; continue; }
        if (quote) {
            if (c == quote) quote = 0;
            else value += c;
            token = true;
        } else if (c == '\'' || c == '"') {
            quote = c; token = true;
        } else if (c == ' ' || c == '\t') {
            if (token) { out.push_back(value); value.clear(); token = false; }
        } else { value += c; token = true; }
    }
    if (escaped || quote) return false;
    if (token) out.push_back(value);
    return true;
}

std::string stableCommandProperty(std::string value) {
    // systemctl show augments effective commands with execution timestamps,
    // PIDs and results. These change on restart without changing the recipe.
    for (const char* field : {"start_time", "stop_time", "pid", "code", "status"}) {
        const std::string marker = std::string(" ; ") + field + "=";
        std::size_t at = 0;
        while ((at = value.find(marker, at)) != std::string::npos) {
            const auto nextField = value.find(" ; ", at + marker.size());
            const auto commandEnd = value.find(" }", at + marker.size());
            if (commandEnd == std::string::npos) break;
            const auto end = nextField != std::string::npos && nextField < commandEnd
                ? nextField : commandEnd;
            value.erase(at, end - at);
        }
    }
    return value;
}

bool lifecycleHooks(const Properties& props, const std::filesystem::path& sshd,
                    std::string& error) {
    for (const char* key : {"ExecCondition", "ExecStartPre", "ExecStartPost"}) {
        const auto found = props.find(key);
        if (found == props.end()) {
            error = std::string("SSH lifecycle property is missing: ") + key;
            return false;
        }
        const std::string& value = found->second;
        if (value.empty()) continue;
        // systemctl show serializes each effective command as one brace group.
        std::size_t offset = 0;
        while (offset < value.size()) {
            if (value.compare(offset, 7, "{ path=") != 0) {
                error = std::string("unsupported SSH ") + key + " format";
                return false;
            }
            const auto end = value.find(" }", offset);
            const auto argvAt = value.find(" ; argv[]=", offset);
            const auto flagsAt = value.find(" ; ignore_errors=no", offset);
            if (end == std::string::npos || argvAt == std::string::npos ||
                flagsAt == std::string::npos || argvAt >= flagsAt ||
                flagsAt + sizeof(" ; ignore_errors=no") - 1 > end) {
                error = std::string("unsupported SSH ") + key + " format";
                return false;
            }
            const std::string path = value.substr(offset + 7, argvAt - offset - 7);
            const std::string metadata = value.substr(
                flagsAt + sizeof(" ; ignore_errors=no") - 1,
                end - flagsAt - (sizeof(" ; ignore_errors=no") - 1));
            if (!metadata.empty()) {
                std::size_t field = 0;
                while (field < metadata.size()) {
                    if (metadata.compare(field, 3, " ; ") != 0) {
                        error = std::string("unsupported SSH ") + key + " metadata";
                        return false;
                    }
                    field += 3;
                    const auto next = metadata.find(" ; ", field);
                    const std::string item = metadata.substr(field, next - field);
                    if (item.rfind("start_time=", 0) != 0 &&
                        item.rfind("stop_time=", 0) != 0 &&
                        item.rfind("pid=", 0) != 0 &&
                        item.rfind("code=", 0) != 0 &&
                        item.rfind("status=", 0) != 0) {
                        error = std::string("unsupported SSH ") + key + " metadata";
                        return false;
                    }
                    field = next == std::string::npos ? metadata.size() : next;
                }
            }
            std::vector<std::string> args;
            if (!words(value.substr(argvAt + 10, flagsAt - argvAt - 10), args) ||
                args.empty() || args.front() != path) {
                error = std::string("unsupported SSH ") + key + " argv";
                return false;
            }
            const bool validateOnly = std::string(key) == "ExecStartPre" &&
                path == sshd.string() && args == std::vector<std::string>{path, "-t"};
            const bool hostKeysOnly = std::string(key) == "ExecStartPre" &&
                path == "/usr/bin/ssh-keygen" &&
                args == std::vector<std::string>{path, "-A"} &&
                ssh::trustedSshInput(path, false, false, error);
            if (!validateOnly && !hostKeysOnly) {
                error = std::string("unproven SSH ") + key + " action: " + path;
                return false;
            }
            offset = end + 2;
            if (offset < value.size()) {
                if (value[offset] != ' ') {
                    error = std::string("unsupported SSH ") + key + " separator";
                    return false;
                }
                ++offset;
            }
        }
    }
    return true;
}

bool lifecycle(const Properties& props, const std::filesystem::path& sshd,
               SshServiceLifecycleProof& proof, std::string& error) {
    for (const char* key : {"Type", "ExecCondition", "ExecStartPre", "ExecStartPost",
                            "ExecReload"}) {
        if (!props.count(key)) {
            error = std::string("SSH lifecycle property is missing: ") + key;
            return false;
        }
        proof.effectiveIdentity += std::string(key) + "=" +
            stableCommandProperty(props.at(key)) + "\n";
    }
    const auto canReload = props.find("CanReload");
    const auto reloadResult = props.find("ReloadResult");
    const auto notifyAccess = props.find("NotifyAccess");
    proof.effectiveIdentity += "CanReload=" +
        (canReload == props.end() ? std::string{} : canReload->second) + "\n";
    proof.effectiveIdentity += "NotifyAccess=" +
        (notifyAccess == props.end() ? std::string{} : notifyAccess->second) + "\n";
    proof.reloadResult = reloadResult == props.end() ? std::string{} :
        reloadResult->second;
    const auto& type = props.at("Type");
    if (type != "simple" && type != "exec" && type != "notify" &&
        type != "notify-reload" && type != "forking") {
        error = "unsupported SSH service Type: " + type;
        return false;
    }
    if (!lifecycleHooks(props, sshd, error)) return false;
    // notify-reload waits for READY=1 after RELOADING=1. An ExecReload
    // command is not classified as synchronous merely from its exit status.
    if (type == "notify-reload" && props.at("ExecReload").empty() &&
        canReload != props.end() && canReload->second == "yes" &&
        reloadResult != props.end() && notifyAccess != props.end() &&
        notifyAccess->second == "main")
        proof.reconciliation = SshRuntimeReconciliationKind::SynchronousReload;
    else proof.reconciliation = SshRuntimeReconciliationKind::RestartRequired;
    return true;
}

bool environmentFile(const std::string& path, bool optional,
                     std::map<std::string, std::string>& values,
                     std::string& error) {
    if (path.find_first_of("*?[%\\") != std::string::npos) {
        error = "SSH EnvironmentFile wildcard or expansion is unsupported: " + path;
        return false;
    }
    if (!ssh::trustedSshInput(path, false, optional, error)) return false;
    fic::core::TrustedFileReadOptions readOptions;
    readOptions.expectedOwner = ::geteuid();
    readOptions.forbiddenMode = S_IWGRP | S_IWOTH;
    std::string content;
    int systemError = 0;
    if (!fic::core::readTrustedFile(path, readOptions, content, error,
                                    nullptr, {}, &systemError)) {
        if (optional && systemError == ENOENT &&
            ssh::trustedSshInput(path, false, true, error)) {
            error.clear();
            return true;
        }
        return false;
    }
    std::istringstream file(content);
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto equal = line.find('=');
        if (equal == std::string::npos || equal == 0 ||
            line.find_first_of(" \t", 0) < equal) {
            error = "unsupported SSH environment file syntax: " + path;
            return false;
        }
        const std::string key = line.substr(0, equal);
        std::string value = line.substr(equal + 1);
        if (!value.empty() && (value.front() == '\'' || value.front() == '"')) {
            const char quote = value.front();
            if (value.size() < 2 || value.back() != quote) {
                error = "unsupported SSH environment value: " + path;
                return false;
            }
            value = value.substr(1, value.size() - 2);
        } else if (!value.empty() &&
                   (value.front() == ' ' || value.front() == '\t' ||
                    value.back() == ' ' || value.back() == '\t')) {
            error = "unsupported SSH environment value: " + path;
            return false;
        }
        if (value.find_first_of("\\\"'\r\n$") != std::string::npos) {
            error = "unsupported SSH environment value: " + path;
            return false;
        }
        values[key] = std::move(value);
    }
    if (!file.eof()) { error = "failed to read SSH environment file"; return false; }
    return true;
}

bool expandedArgv(const Properties& props, std::vector<std::string>& argv,
                  std::string& executable, std::string& error) {
    const auto found = props.find("ExecStart");
    if (found == props.end()) { error = "SSH ExecStart is missing"; return false; }
    const std::string& exec = found->second;
    const std::string prefix = "{ path=", separator = " ; argv[]=", suffix = " ; ignore_errors=no";
    const auto mid = exec.find(separator), end = exec.find(suffix);
    if (exec.rfind(prefix, 0) != 0 || mid == std::string::npos ||
        end == std::string::npos || mid <= prefix.size() || end <= mid ||
        exec.find('{', 1) != std::string::npos ||
        exec.find('}') != exec.size() - 1 ||
        exec.find(separator, mid + separator.size()) != std::string::npos) {
        error = "unsupported SSH ExecStart format";
        return false;
    }
    executable = exec.substr(prefix.size(), mid - prefix.size());
    if (!words(exec.substr(mid + separator.size(),
                           end - mid - separator.size()), argv) || argv.empty()) {
        error = "unsupported SSH ExecStart argv";
        return false;
    }
    std::map<std::string, std::string> environment;
    const auto unitEnv = props.find("Environment");
    if (unitEnv != props.end() && !unitEnv->second.empty()) {
        std::vector<std::string> assignments;
        if (!words(unitEnv->second, assignments)) {
            error = "unsupported SSH Environment property"; return false;
        }
        if (assignments.size() != 1) {
            error = "ambiguous SSH Environment property"; return false;
        }
        for (const auto& assignment : assignments) {
            const auto equal = assignment.find('=');
            if (equal == std::string::npos || equal == 0) {
                error = "unsupported SSH Environment assignment"; return false;
            }
            environment[assignment.substr(0, equal)] = assignment.substr(equal + 1);
        }
    }
    const auto files = props.find("EnvironmentFiles");
    if (files != props.end() && !files->second.empty()) {
        std::istringstream fields(files->second);
        std::string path, flag;
        while (fields >> path) {
            if (!(fields >> flag)) {
                error = "malformed SSH EnvironmentFiles property"; return false;
            }
            if ((flag != "(ignore_errors=yes)" && flag != "(ignore_errors=no)") ||
                path.empty() || path[0] != '/') {
                error = "unsupported SSH EnvironmentFiles property"; return false;
            }
            if (!environmentFile(path, flag == "(ignore_errors=yes)", environment, error))
                return false;
        }
        if (!fields.eof()) { error = "malformed SSH EnvironmentFiles property"; return false; }
    }
    for (const char* key : {"UnsetEnvironment", "RootDirectory", "RootImage",
                            "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem",
                            "ExtensionImages", "ExtensionDirectories"}) {
        const auto property = props.find(key);
        if (property != props.end() && !property->second.empty()) {
            error = std::string("unsupported SSH systemd isolation property: ") + key;
            return false;
        }
    }
    std::vector<std::string> resolved;
    for (const auto& arg : argv) {
        if (arg.size() > 1 && arg[0] == '$' && arg[1] != '{') {
            const auto name = arg.substr(1);
            const auto value = environment.find(name);
            if (value == environment.end()) {
                error = "unresolved SSH ExecStart variable: " + name; return false;
            }
            std::vector<std::string> split;
            if (!words(value->second, split)) {
                error = "unsupported SSH ExecStart expansion"; return false;
            }
            resolved.insert(resolved.end(), split.begin(), split.end());
        } else if (arg.find('$') != std::string::npos ||
                   arg.find('%') != std::string::npos) {
            error = "unsupported SSH ExecStart expansion"; return false;
        } else resolved.push_back(arg);
    }
    argv = std::move(resolved);
    return !argv.empty();
}

bool launchArguments(const std::vector<std::string>& argv,
                     const platform::SshPlatformConfig& platform,
                     SshLaunchProof& proof, std::string& error) {
    if (argv.empty() || argv.front().find('\0') != std::string::npos) {
        error = "SSH argv[0] is unavailable"; return false;
    }
    proof.argvZero = argv.front();
    proof.arguments = argv;
    proof.configPath = platform.configPath;
    bool explicitConfig = false;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        const auto& arg = argv[i];
        if (arg == "-D" || arg == "-e" || arg == "-q" ||
            arg == "-4" || arg == "-6") continue;
        if (arg == "-f" || arg == "-o") {
            if (++i == argv.size() || argv[i].empty()) {
                error = "SSH launch option lacks an argument"; return false;
            }
            proof.configurationArguments.push_back(arg);
            proof.configurationArguments.push_back(argv[i]);
            if (arg == "-f") {
                if (explicitConfig) { error = "multiple SSH -f options"; return false; }
                proof.configPath = argv[i];
                explicitConfig = true;
            }
        } else if (arg.size() > 2 && (arg.rfind("-f", 0) == 0 ||
                                      arg.rfind("-o", 0) == 0)) {
            proof.configurationArguments.push_back(arg.substr(0, 2));
            proof.configurationArguments.push_back(arg.substr(2));
            if (arg[1] == 'f') {
                if (explicitConfig) { error = "multiple SSH -f options"; return false; }
                proof.configPath = arg.substr(2);
                explicitConfig = true;
            }
        } else { error = "unsupported SSH launch option: " + arg; return false; }
    }
    if (!proof.configPath.is_absolute()) {
        error = "SSH launch config path is not absolute"; return false;
    }
    return true;
}

} // namespace

SshActivationProof SshSystemdActivationVerifier::prove(
    const platform::SshPlatformConfig& platform,
    const platform::PlatformExecutableResolver& executables,
    SshCommandRunner runner,
    SshProcessReader processReader) {
    SshActivationProof proof;
    auto fail = [&](const std::string& reason) {
        proof.diagnostic = reason;
        proof.launches.clear();
        proof.services.clear();
        return proof;
    };
    if (platform.serviceUnits.empty() || platform.socketUnits.empty())
        return fail("SSH systemd activation topology is not declared");
    std::filesystem::path sshd, systemctl;
    std::string error;
    if (!executables.resolve(platform::ExecutableId::Sshd, sshd, error) ||
        !executables.resolve(platform::ExecutableId::Systemctl, systemctl, error))
        return fail("trusted SSH activation executables unavailable: " + error);
    if (!runner) runner = [](const std::string& exe, const std::vector<std::string>& args,
                             const ProcessOptions& options) {
        return VerifiedProcessExecutor::execute(exe, args, options);
    };
    if (!processReader) processReader = readProcess;
    struct stat trusted {};
    if (::stat(sshd.c_str(), &trusted) != 0) return fail("cannot stat trusted sshd");
    proof.trustedDevice = trusted.st_dev;
    proof.trustedInode = trusted.st_ino;
    const auto inspect = [&](const std::string& unit, Properties& props) {
        ProcessOptions options;
        options.clearEnvironment = true;
        const auto result = runner(systemctl.string(),
            {"show", "--property=Id", "--property=Names", "--property=LoadState",
             "--property=ActiveState", "--property=MainPID", "--property=ExecStart",
             "--property=Environment", "--property=EnvironmentFiles",
             "--property=UnsetEnvironment", "--property=RootDirectory",
             "--property=RootImage", "--property=BindPaths",
             "--property=BindReadOnlyPaths", "--property=TemporaryFileSystem",
             "--property=ExtensionImages", "--property=ExtensionDirectories",
             "--property=Type", "--property=ExecCondition",
             "--property=ExecStartPre", "--property=ExecStartPost",
             "--property=ExecReload", "--property=CanReload",
             "--property=ReloadResult", "--property=NotifyAccess",
             "--property=Triggers", "--property=Accept", unit}, options);
        if (!result.success() || !parseProperties(result.standardOutput, props)) {
            error = "cannot inspect systemd unit " + unit; return false;
        }
        return true;
    };
    std::set<std::string> socketTargets;
    for (const auto& socket : platform.socketUnits) {
        Properties props;
        if (!inspect(socket, props)) return fail(error);
        if (props["LoadState"] == "not-found") continue;
        if (props["LoadState"] != "loaded") return fail("SSH socket is not loaded: " + socket);
        if (props["ActiveState"] == "active" ||
            props["ActiveState"] == "inactive") {
            if (props["Accept"] != "no")
                return fail("SSH socket Accept setting is not proven safe: " + socket);
            std::istringstream targets(props["Triggers"]);
            std::string target, extra;
            if (!(targets >> target) || targets >> extra)
                return fail("SSH socket target is ambiguous: " + socket);
            socketTargets.insert(target);
        } else
            return fail("SSH socket state is unproven: " + socket);
    }
    std::set<std::string> checked;
    std::set<std::string> trustedNames;
    bool loaded = false;
    for (const auto& unit : platform.serviceUnits) {
        Properties props;
        if (!inspect(unit, props)) return fail(error);
        if (props["LoadState"] == "not-found") continue;
        if (props["LoadState"] != "loaded" || props["Id"].empty())
            return fail("SSH service is not demonstrably loaded: " + unit);
        loaded = true;
        trustedNames.insert(unit);
        trustedNames.insert(props["Id"]);
        std::istringstream names(props["Names"]);
        std::string name;
        while (names >> name) trustedNames.insert(name);
        if (!checked.insert(props["Id"]).second) continue;
        SshServiceLifecycleProof service;
        service.unit = props["Id"];
        if (!lifecycle(props, sshd, service, error)) return fail(error);
        for (const char* key : {"Environment", "EnvironmentFiles",
                                "UnsetEnvironment", "RootDirectory", "RootImage",
                                "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem",
                                "ExtensionImages", "ExtensionDirectories"})
            service.effectiveIdentity += std::string(key) + "=" + props[key] + "\n";
        proof.services.push_back(std::move(service));
        std::vector<std::string> argv;
        SshLaunchProof launch;
        launch.serviceUnit = props["Id"];
        if (props["ActiveState"] == "active") {
            unsigned int pid = 0;
            const auto& value = props["MainPID"];
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), pid);
            if (parsed.ec != std::errc() || parsed.ptr != value.data() + value.size() || pid == 0)
                return fail("active SSH service has no proven MainPID: " + unit);
            SshProcessSnapshot snapshot;
            if (!processReader(pid, snapshot, error)) return fail(error);
            if (snapshot.startTime.empty() || snapshot.arguments.empty())
                return fail("active SSH process identity is incomplete: " + unit);
            if (snapshot.device != static_cast<std::uint64_t>(trusted.st_dev) ||
                snapshot.inode != static_cast<std::uint64_t>(trusted.st_ino))
                return fail("active SSH process is not the trusted sshd: " + unit);
            argv = std::move(snapshot.arguments);
            launch.activeProcess = true;
            launch.mainPid = pid;
            launch.startTime = snapshot.startTime;
            Properties after;
            if (!inspect(unit, after) || after["MainPID"] != value ||
                after["ActiveState"] != "active")
                return fail("SSH service process changed during inspection: " + unit);
            SshProcessSnapshot confirmed;
            if (!processReader(pid, confirmed, error) ||
                confirmed.startTime != snapshot.startTime ||
                confirmed.device != snapshot.device ||
                confirmed.inode != snapshot.inode ||
                confirmed.arguments != argv)
                return fail("SSH process identity changed during inspection: " + unit);
        } else if (props["ActiveState"] == "inactive") {
            std::string executable;
            if (!expandedArgv(props, argv, executable, error)) return fail(error);
            if (executable != sshd.string())
                return fail("SSH service does not launch the trusted sshd: " + unit);
        } else return fail("SSH service state is unproven: " + unit);
        if (!launchArguments(argv, platform, launch, error)) return fail(error);
        proof.launches.push_back(std::move(launch));
        if (props["ActiveState"] == "active") {
            std::vector<std::string> futureArgv;
            std::string executable;
            if (!expandedArgv(props, futureArgv, executable, error)) return fail(error);
            if (executable != sshd.string())
                return fail("SSH service future launch is not the trusted sshd: " + unit);
            SshLaunchProof future;
            future.serviceUnit = props["Id"];
            if (!launchArguments(futureArgv, platform, future, error)) return fail(error);
            if (props["ExecStartPre"].find(sshd.string() + " ; argv[]=" +
                    sshd.string() + " -t") != std::string::npos &&
                !future.configurationArguments.empty())
                return fail("SSH validation hook does not use future launch configuration: " + unit);
            proof.launches.push_back(std::move(future));
        } else if (props["ExecStartPre"].find(sshd.string() + " ; argv[]=" +
                       sshd.string() + " -t") != std::string::npos &&
                   !proof.launches.back().configurationArguments.empty()) {
            return fail("SSH validation hook does not use future launch configuration: " + unit);
        }
    }
    if (!loaded) return fail("no declared SSH service unit is loaded");
    for (const auto& target : socketTargets)
        if (!trustedNames.count(target))
            return fail("SSH socket activates an untrusted service: " + target);
    proof.status = SshActivationStatus::Proven;
    proof.diagnostic = "declared SSH systemd activation paths are proven";
    return proof;
}

} // namespace fic::incident
