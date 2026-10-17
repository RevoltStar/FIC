#include "service/VerifiedConfigLaunchContract.h"
#include "service/VerifiedConfigMountSupport.h"
#include "platform/PlatformExecutableResolver.h"
#include "modules/net/ssh/SshConfigAudit.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "modules/net/ssh/SshInputAuthority.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/ProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <glob.h>
#include <iostream>
#include <set>
#include <sstream>
#include <unistd.h>

namespace d = fic::service::detail;
namespace fs = std::filesystem;
using Json = nlohmann::json;
using namespace fic::service;
Json result{{"checks", Json::array()}};
void record(const std::string& name, const std::string& status, const std::string& evidence, const std::string& method = "actual FIC helper") {
    result["checks"].push_back({{"name", name}, {"status", status}, {"evidence", evidence}, {"method", method}});
}
template<class F> void actual(const std::string& name, F operation) {
    try { record(name, "SUPPORTED", operation()); }
    catch (const d::Failure& e) { record(name, "UNSUPPORTED", e.what()); }
    catch (const std::exception& e) { record(name, "NOT_TESTED", e.what()); }
}
std::string text(const fs::path& path) { std::ifstream in(path); return {std::istreambuf_iterator<char>(in), {}}; }
std::map<std::string, std::string> properties(const fs::path& systemctl, const std::string& unit) {
    ProcessOptions options; options.timeout = std::chrono::seconds(10); options.maxOutputBytes = 256*1024;
    options.clearEnvironment = true; options.environment = {{"LANG", "C"}, {"LC_ALL", "C"}};
    // Read-only show; unit is a fixed profile candidate, never a command string.
    const auto response = ProcessExecutor::execute(systemctl, {"--system", "--no-pager", "show", "--all", "--", unit}, options);
    if (!response.success()) throw std::runtime_error("systemctl show unavailable");
    std::map<std::string, std::string> out; std::istringstream lines(response.standardOutput); std::string line;
    while (std::getline(lines, line)) { const auto equal = line.find('='); if (equal != std::string::npos) out.emplace(line.substr(0, equal), line.substr(equal+1)); }
    return out;
}
void rule(const std::map<std::string, std::string>& values, const std::string& key,
          const std::function<bool(const std::string&)>& accepts) {
    const auto it = values.find(key);
    if (it == values.end()) { record("unit." + key, "NOT_TESTED", "property absent from read-only show; typed reader is reported separately", "systemctl show + code-derived constraint"); return; }
    // Never serialize arbitrary environment/credential values.
    std::string evidence = it->second;
    if (evidence == "[unprintable]") { record("unit." + key, "NOT_TESTED", "systemctl intentionally hides value; see typed_properties if reader succeeded", "systemctl show"); return; }
    if (key.find("Credential") != std::string::npos) evidence = evidence.empty() ? "empty" : "nonempty (redacted)";
    record("unit." + key, accepts(it->second) ? "SUPPORTED" : "UNSUPPORTED", evidence.empty() ? "empty" : evidence, "systemctl show + code-derived constraint");
}
void includeGraph(const fs::path& path, const fs::path& base, std::set<std::string>& files,
                  Json& patterns, unsigned depth = 0) {
    if (depth > 16 || files.size() >= 256) throw std::runtime_error("Include audit limit exceeded");
    if (!files.insert(path.lexically_normal().string()).second) return;
    std::ifstream input(path); if (!input) throw std::runtime_error("unreadable Include input " + path.string());
    std::string line;
    while (std::getline(input, line)) {
        const auto parsed = parseSshConfigLine(line);
        if (!parsed.ok) throw std::runtime_error("Include syntax unavailable");
        if (!parsed.hasDirective || normalizeSshKeyword(parsed.directive.keyword) != "include") continue;
        for (const auto& argument : parsed.directive.arguments) {
            const fs::path pattern = (fs::path(argument).is_absolute() ? fs::path(argument) : base / argument).lexically_normal();
            patterns.push_back(pattern.string()); glob_t matches{};
            const int code = ::glob(pattern.c_str(), 0, nullptr, &matches);
            if (code == GLOB_NOMATCH) { ::globfree(&matches); continue; }
            if (code != 0) { ::globfree(&matches); throw std::runtime_error("Include glob failed"); }
            std::vector<std::string> names;
            for (std::size_t i = 0; i < matches.gl_pathc; ++i) names.emplace_back(matches.gl_pathv[i]);
            ::globfree(&matches);
            for (const auto& name : names) includeGraph(name, base, files, patterns, depth + 1);
        }
    }
}
int main() {
    try {
        std::string error; if (!fic::core::FicRuntimePaths::initializeProduction(error)) throw std::runtime_error(error);
        const auto profile = fic::platform::makeBuildPlatformProfile();
        fic::platform::PlatformExecutableResolver resolver(profile.executables);
        result["config"] = profile.ssh.configPath.string(); result["include_base"] = profile.ssh.includeBasePath.string();
        result["profile_services"] = profile.ssh.serviceUnits; result["profile_sockets"] = profile.ssh.socketUnits;
        result["profile_option_file"] = profile.ssh.optionFile.string(); result["profile_option_variable"] = profile.ssh.optionVariable;
        actual("privileges", [&] { if (::geteuid() != 0) throw d::Failure(ActivationStatus::UnsupportedConfiguration, "effective UID is not root");
            const auto status = text("/proc/self/status"); const auto at = status.find("CapEff:\t");
            if (at == std::string::npos || !(std::stoull(status.substr(at+8), nullptr, 16) & (1ULL<<21))) throw d::Failure(ActivationStatus::UnsupportedConfiguration, "effective CAP_SYS_ADMIN absent");
            return std::string("root; CAP_SYS_ADMIN present"); });
        actual("manager_namespace", [&] { const auto self = d::namespaceIdentity(::getpid()), manager = d::namespaceIdentity(1);
            result["namespaces"] = {{"diagnostic", self}, {"pid1", manager}, {"pid1_comm", text("/proc/1/comm")}};
            if (self != manager || text("/proc/1/comm") != "systemd\n") throw d::Failure(ActivationStatus::UnsupportedConfiguration, "different namespace or PID1 not systemd"); return self; });
        record("fic_daemon_namespace", "NOT_TESTED", "FIC daemon is not installed/running in this stock OpenSSH audit image");
        const auto enforcing = text("/sys/fs/selinux/enforce"); record("selinux", enforcing == "1" || enforcing == "1\n" ? "UNSUPPORTED" : "SUPPORTED", enforcing.empty() ? "enforce file absent; production check also treats it as non-enforcing" : enforcing);
        fs::path systemctl;
        if (!resolver.resolve(fic::platform::ExecutableId::Systemctl, systemctl, error)) throw std::runtime_error(error);
        const auto trust = fic::core::FicRuntimePaths::get().commandHashFile;
        result["trust_store_path"] = trust.string();
        if (!fs::exists(trust)) record("systemctl_trust", "NOT_TESTED", "FIC reference hash store not deployed; no enrollment attempted");
        else record("systemctl_trust", CommandHashStore::verifyHash(systemctl, error) ? "SUPPORTED" : "UNSUPPORTED", error.empty() ? "existing hash verified read-only" : error);
        fs::path sshd;
        record("sshd_platform_executable", resolver.resolve(fic::platform::ExecutableId::Sshd, sshd, error) ? "SUPPORTED" : "UNSUPPORTED", sshd.empty() ? error : sshd.string());
        std::map<std::string, std::string> values;
        std::string requested;
        for (const auto& candidate : profile.ssh.serviceUnits) {
            auto found = properties(systemctl, candidate);
            if (found["LoadState"] == "loaded") { requested = candidate; values = std::move(found); break; }
        }
        if (requested.empty()) throw std::runtime_error("no loaded platform service candidate");
        result["requested_unit"] = requested; result["canonical_unit"] = values["Id"];
        for (const auto& key : {"Id", "Names", "LoadState", "ActiveState", "SubState", "Type", "NotifyAccess", "MainPID", "InvocationID", "Job", "FragmentPath", "DropInPaths", "EnvironmentFiles", "TriggeredBy", "Triggers", "NeedDaemonReload", "UnitFileState", "PIDFile"})
            result["unit"][key] = values.count(key) ? Json(values.at(key)) : Json(nullptr);
        rule(values, "Id", [&](const auto& v) { return v == requested; });
        for (const auto& [key, expected] : std::map<std::string,std::string>{{"LoadState","loaded"},{"ActiveState","active"},{"SubState","running"},{"Type","notify"},{"NotifyAccess","main"},{"Job",""},{"NeedDaemonReload","no"},{"Transient","no"},{"ExitType","main"},{"RemainAfterExit","no"},{"FileDescriptorStoreMax","0"},{"NFileDescriptorStore","0"},{"StandardInput","null"},{"ProtectProc","default"},{"ProcSubset","all"}})
            rule(values, key, [&](const auto& v){return v == expected;});
        rule(values, "InvocationID", [](const auto& v){return v.size()==32 && v!=std::string(32,'0') && std::all_of(v.begin(),v.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');});});
        for (const auto& key : {"PrivateMounts","PrivateTmp","PrivateDevices","ProtectClock","ProtectKernelTunables","ProtectKernelModules","ProtectKernelLogs","ProtectControlGroups","ProtectHome","ProtectSystem","ProtectHostname","DynamicUser","PrivateUsers","PrivateNetwork","PrivateIPC","MountAPIVFS"})
            rule(values, key, [](const auto& v){return v=="no";});
        for (const auto& key : {"RootDirectory","RootImage","ReadWritePaths","ReadOnlyPaths","InaccessiblePaths","MountFlags","BindPaths","BindReadOnlyPaths","TemporaryFileSystem","SourcePath","TriggeredBy","PIDFile","EnvironmentFiles","LoadCredential","LoadCredentialEncrypted","SetCredential","SetCredentialEncrypted","ExtensionDirectories","ExtensionImages","PAMName","NetworkNamespacePath","IPCNamespacePath","LogNamespace"})
            rule(values, key, [](const auto& v){return v.empty();});
        for (const auto& key : {"StandardOutput","StandardError"}) rule(values,key,[](const auto& v){return v=="null"||v=="journal"||v=="inherit"||v=="kmsg";});
        if (values["MainPID"] != "0" && !values["MainPID"].empty()) actual("main_process_identity", [&] {
            const auto pid = std::stoul(values.at("MainPID")); const auto ns = d::namespaceIdentity(pid); result["namespaces"]["sshd"] = ns;
            struct stat a{}, b{}; const auto root = "/proc/" + std::to_string(pid) + "/root";
            if (::stat(root.c_str(), &a) || ::stat("/", &b) || a.st_dev != b.st_dev || a.st_ino != b.st_ino || ns != d::namespaceIdentity(::getpid()))
                throw d::Failure(ActivationStatus::UnsupportedConfiguration, "MainPID namespace/root differs"); return ns;
        }); else record("main_process_identity", "NOT_APPLICABLE", "MainPID=0; ActiveState/running gate already failed");
        actual("typed_launch_reader", [&] {
            const auto contract = d::readLaunchContract(values.at("Id"), std::chrono::steady_clock::now()+std::chrono::seconds(10));
            result["typed_property_count"] = contract.size();
            for (const auto& [key, encoded] : contract) {
                if (key.rfind("launch.file:", 0) == 0 || key == "launch.ManagerEnvironment") continue;
                const auto field = Json::parse(encoded); const auto& value = field.at("value");
                result["typed_properties"][key] = {{"signature", field.at("signature")}, {"empty", value.empty()}};
                if (key.find("Credential") != std::string::npos)
                    record("typed." + key, value.empty() ? "SUPPORTED" : "UNSUPPORTED", value.empty() ? "empty" : "nonempty (redacted)");
            }
            // Independent validator result must not suppress later path checks.
            actual("launch_validator", [&] { d::validateLaunchContract(contract); return std::string("all current launch constraints accepted"); });
            Json names = Json::array(); const auto environment = Json::parse(contract.at("launch.Environment")).at("value");
            for (const auto& item : environment) { const auto s=item.template get<std::string>(); names.push_back(s.substr(0,s.find('='))); }
            result["environment_names"] = names; return std::to_string(contract.size()) + " fields; values redacted";
        });
        actual("workspace_parent", [&] { d::requireSafePublicationParent(fic::core::FicRuntimePaths::get().runtimeDir / "verified-config-activator/prospective", true, ActivationStatus::UnsupportedConfiguration); return std::string("effective parent is non-shared; no directories created"); });
        ActivationRequest request; request.unit = values.at("Id");
        const fs::path config = profile.ssh.configPath, directory = profile.ssh.includeBasePath / "sshd_config.d";
        for (const auto& path : {config, directory}) {
            const auto name = path == config ? "config" : "dropins";
            if (!fs::exists(path) && path==directory) { record("tree."+std::string(name),"NOT_APPLICABLE","directory absent; no target invented"); continue; }
            actual("parent."+std::string(name), [&] { d::requireSafePublicationParent(path,false,ActivationStatus::UnsupportedConfiguration); return path.parent_path().string(); });
            actual("authority."+std::string(name), [&] { std::string why; if (!fic::ssh::trustedSshInput(path,path==directory,false,why)) throw d::Failure(ActivationStatus::UnsupportedConfiguration,why); return std::string("trustedSshInput accepted"); });
            actual("tree."+std::string(name), [&] {
                auto fd=d::openAbsolute(path,O_RDONLY); auto budget=request.maxSnapshotBytes; const auto kind=path==config?ControlledPathKind::File:ControlledPathKind::Directory;
                const auto tree=d::readTree(fd.get(),kind,budget); ControlledPath target{path,kind,"",{}};
                if (kind==ControlledPathKind::File) target.sha256=fic::core::ContentDigest::sha256Hex(tree.files.at(""));
                else for(const auto& [file,bytes]:tree.files)target.manifest[file]=fic::core::ContentDigest::sha256Hex(bytes);
                d::verifyTree(fd.get(),target,request.maxSnapshotBytes); request.paths.push_back(target);
                result["input_manifest"][path.string()]={{"mount_id",d::identity(fd.get()).mount},{"files",tree.files.size()},{"sha256",target.sha256},{"manifest",target.manifest}};
                return std::to_string(tree.files.size())+" files; actual RO descriptor/metadata/xattr/nested-mount checks";
            });
        }
        actual("request_shape", [&] { d::validateRequest(request); return std::string("observed file hashes form a legal request; this is not a trusted policy etalon"); });
        actual("mount_targets_and_residuals", [&] {
            for(const auto& mount:d::readMountInfo()) {
                if(mount.source.rfind("fic-vcsa.",0)==0)throw d::Failure(ActivationStatus::ResidualMounts,"residual activator mount");
                for(const auto& p:request.paths)if(mount.target==p.path ||(p.kind==ControlledPathKind::Directory&&d::below(mount.target,p.path.string())))throw d::Failure(ActivationStatus::UnsupportedConfiguration,"existing target/nested mount");
            } return std::string("no target/nested/residual mount found");
        });
        actual("ssh_include_authority", [&] { std::string identity, why; SshConfigAudit audit({config,profile.ssh.includeBasePath,16,256,true});
            if(!audit.sourceIdentity(identity,why))throw d::Failure(ActivationStatus::UnsupportedConfiguration,why); return identity; });
        actual("include_coverage", [&] {
            std::set<std::string> files; Json patterns=Json::array(); includeGraph(config,profile.ssh.includeBasePath,files,patterns);
            result["includes"]={{"files",files},{"patterns",patterns}};
            for(const auto& file:files)if(file!=config && !d::below(file,directory.string()))throw d::Failure(ActivationStatus::UnsupportedConfiguration,"Include outside proposed main+dropin targets: "+file);
            for(const auto& pattern:patterns)if(!d::below(pattern,directory.string()))throw d::Failure(ActivationStatus::UnsupportedConfiguration,"Include pattern outside proposed targets: "+pattern.get<std::string>());
            return std::string("current parsed Include graph confined to proposed existing targets; arbitrary future Include not guaranteed");
        });
        for(const auto& key:{"workspace_lock","tmpfs_creation_RO","publication_RO_identity","controlled_restart_READY","post_activation_cleanup"})
            record(key,"NOT_TESTED","requires state-changing operation; forbidden for stock SSH audit");
        std::cout << result.dump(2) << '\n'; return 0;
    } catch(const std::exception& e) { record("audit_infrastructure","NOT_TESTED",e.what()); std::cout<<result.dump(2)<<'\n'; return 1; }
}
