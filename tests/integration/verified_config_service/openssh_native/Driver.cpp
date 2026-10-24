#include "modules/net/ssh/policies/NET_ssh_port.h"
#include "modules/net/ssh/policies/NET_ssh_root_login.h"
#include "modules/net/ssh/policies/NET_ssh_use_pam.h"
#include "modules/net/ssh/policies/NET_ssh_pubkey_auth.h"
#include "modules/net/ssh/policies/NET_ssh_max_auth_tries.h"
#include "rollback/DaemonMutationJournal.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include <fic/core/config/ModuleConfigFileHandler.h>
#include "service/ssh/SshVerifiedActivationTestAccess.h"
// Test-only real OpenSSH adapter. Never installed or linked into FIC.
#include "service/VerifiedConfigServiceActivator.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include "service/VerifiedConfigSystemd.h"
#include "service/VerifiedConfigLaunchContract.h"
#include "modules/net/ssh/SshConfigAudit.h"
#include "platform/PlatformExecutableResolver.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/ProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <poll.h>
#include <sched.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
namespace fs = std::filesystem;
namespace d = fic::service::detail;
using namespace fic::service;
using J = nlohmann::json;
const std::string work = "/run/fic-openssh-work";
std::string text(const std::string& p) { std::ifstream f(p); return {std::istreambuf_iterator<char>(f), {}}; }
void check(bool b, const std::string& e) { if (!b) throw std::runtime_error(e); }
void write(const std::string& p, const std::string& s) { std::ofstream f(p); f << s; check(bool(f), "fixture write failed"); }
void guard() {
    const char* host = ::getenv("FIC_OPENSSH_HOST_MNT");
    const char* token = ::getenv("FIC_OPENSSH_DISPOSABLE");
    const char* hostRoot = ::getenv("FIC_OPENSSH_HOST_ROOT"); struct stat root{};
    check(::stat("/", &root) == 0 && hostRoot &&
          std::to_string(root.st_dev) + ":" + std::to_string(root.st_ino) != hostRoot,
          "refuse caller's root filesystem");
    check(::geteuid() == 0 && token && host &&
          fs::exists("/.dockerenv") && fs::exists(work + "/runner-marker") &&
          text(work + "/runner-marker") == token &&
          text("/proc/1/comm") == "systemd\n" && d::namespaceIdentity(1) == d::namespaceIdentity(::getpid()) &&
          d::namespaceIdentity(1) != host, "refuse non-disposable environment");
    unsigned interfaces = 0;
    for (const auto& e : fs::directory_iterator("/sys/class/net")) { check(e.path().filename() == "lo", "network must be loopback only"); ++interfaces; }
    check(interfaces == 1, "loopback network absent");
}
void ctl(const std::vector<std::string>& args) {
    ProcessOptions o; o.timeout = std::chrono::seconds(10); o.clearEnvironment = true;
    check(ProcessExecutor::execute("/usr/bin/systemctl", args, o).success(), "fixture systemctl failed");
}
std::vector<d::MountRecord> leftovers() {
    std::vector<d::MountRecord> out;
    for (const auto& m : d::readMountInfo()) if (m.source.rfind("fic-vcsa.", 0) == 0) out.push_back(m);
    return out;
}
template<class T> struct ModulePolicy : T {
    ModulePolicy(const fic::platform::SshPlatformConfig& config,
                 const fic::platform::PlatformExecutableResolver& resolver,
                 std::function<void()> beforeWrite) : T(config,resolver) {
        this->beforeWriteHook_=std::move(beforeWrite);
    }
};
int main(int argc, char** argv) {
    J output;
    try {
        guard(); check(argc >= 3, "action and request required");
        std::string error;
        auto paths = fic::core::FicProductPaths::production();
        paths.configDir = work + "/config"; paths.logDir = work + "/logs";
        paths.dataDir = work + "/state"; paths.commandHashFile = work + "/hashes";
        paths.runtimeDir = "/run/fic"; paths.lockDebugLogFile = work + "/logs/locks";
        fs::create_directories(paths.configDir); fs::create_directories(paths.logDir); fs::create_directories(paths.dataDir);
        check(fic::core::FicRuntimePaths::initialize(paths, error), error);
        auto profile = fic::platform::makeBuildPlatformProfile();
        fic::platform::PlatformExecutableResolver resolver(profile.executables); fs::path systemctl;
        check(resolver.resolve(fic::platform::ExecutableId::Systemctl, systemctl, error), error);
        // Explicit fixture provisioning, only after guard. Never production enrollment.
        check(CommandHashStore::saveHash(systemctl, error), error);
        fs::path sshd; check(resolver.resolve(fic::platform::ExecutableId::Sshd, sshd, error), error);
        check(CommandHashStore::saveHash(sshd, error), error);
        const auto input = J::parse(text(argv[2]));
        if (input.value("untrusted_sshd", false)) check(CommandHashStore::updateHashes({}, {sshd.string()}, error), error);
        ActivationRequest r; r.unit = "ssh.service";
        r.timeout = std::chrono::milliseconds(input.value("timeout_ms", 10000));
        for (const auto& p : input.at("paths")) {
            ControlledPath c; c.path = p.at("path").get<std::string>();
            c.kind = p.value("directory", false) ? ControlledPathKind::Directory : ControlledPathKind::File;
            c.sha256 = p.value("sha256", "");
            if (p.contains("manifest")) c.manifest = p.at("manifest").get<FileManifest>();
            r.paths.push_back(c);
        }
        const std::string action = argv[1];
        if(action=="module") {
            auto& journalOwner=fic::rollback::DaemonMutationJournal::instance();
            fs::create_directories(work+"/module-state");
            write(paths.configDir.string()+"/AUDIT.conf","log_level.status=ENABLE\nlog_level.value=ERROR\n");
            journalOwner.setOverridePath(work+"/module-state/journal.json");
            const auto observe=[&] {
                try { return d::SystemdActivation("ssh.service",std::chrono::steady_clock::now()+std::chrono::seconds(10),r.paths).current(); }
                catch(const d::Failure&) { d::ServiceState absent;absent.properties={{"MainPID","0"},{"InvocationID",""}};return absent; }
            };
            // Daemon normally initializes its journal before policy passes.
            // Initialize the isolated real journal, without fabricated ownership.
            check(journalOwner.tryGet(error)!=nullptr,error);
            bool journalFault=false;
            output["module"]=J::array();
            for(const auto& operation:input.at("operations")) {
                const auto beforeAction=operation.value("before","");
                if(beforeAction=="restart") ctl({"restart","ssh.service"});
                if(beforeAction=="main-comment") write("/etc/ssh/sshd_config",text("/etc/ssh/sshd_config")+"# administrative annotation\n");
                const auto id=operation.at("policy").get<std::string>();
                const auto desired=operation.at("value").get<std::string>();
                std::map<std::string,std::string> configured;
                for(const auto& planned:input.at("operations")) configured[planned.at("policy").get<std::string>()]=planned.at("value").get<std::string>();
                configured[id]=desired;std::string policyConfig;
                for(const auto& [name,value]:configured) policyConfig+=name+".status=ENABLE\n"+name+".value="+value+"\n";
                write(paths.configDir.string()+"/NET.conf",policyConfig);
                auto before=observe();
                const auto fault=operation.value("fault","");
                auto hook=[&] {
                    if(fault=="disable") ctl({"disable","ssh.service"});
                    else if(fault=="foreign-input") write("/etc/ssh/sshd_config.d/99-raced.conf","LogLevel VERBOSE\n");
                    else if(fault=="main-cas") write("/etc/ssh/sshd_config",text("/etc/ssh/sshd_config")+"# foreign CAS edit\n");
                };
                std::unique_ptr<Policy> policy;
#define MODULE_CASE(name, type) if(id==name) policy=std::make_unique<ModulePolicy<type>>(profile.ssh,resolver,hook)
                MODULE_CASE("ssh_port",NET_ssh_port);
                MODULE_CASE("ssh_root_login",NET_ssh_root_login);
                MODULE_CASE("ssh_use_pam",NET_ssh_use_pam);
                MODULE_CASE("ssh_pubkey_auth",NET_ssh_pubkey_auth);
                MODULE_CASE("ssh_max_auth_tries",NET_ssh_max_auth_tries);
#undef MODULE_CASE
                check(bool(policy),"unknown fixture policy");
                setSshSaveOutcomeHookForTests([&](FileHandler::FileSaveOutcome& saved) {
                    if(fault=="after-save-stop") ctl({"stop","ssh.service"});
                    else if(fault=="after-save-disable") ctl({"disable","ssh.service"});
                    else if(fault=="after-save-input") write("/etc/ssh/sshd_config.d/99-raced.conf","LogLevel VERBOSE\n");
                    else if(fault=="after-save-main") write("/etc/ssh/sshd_config",text("/etc/ssh/sshd_config")+"# foreign saved edit\n");
                    else if(fault=="durability") {saved.result=FileHandler::FileSaveResult::Failed; saved.durabilityConfirmed=false;}
                    else if(fault=="unknown-writer") throw std::runtime_error("fixture lost writer observation");
                    else if(fault=="journal-commit") {
                        journalFault=true;
                        AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& target){return target!=work+"/module-state/journal.json";});
                    }
                });
                const auto mainBefore=text("/etc/ssh/sshd_config");
                const auto journalBefore=text(work+"/module-state/journal.json");
                const bool applied=policy->apply();
                setSshSaveOutcomeHookForTests({});
                const auto after=observe();
                auto* journal=journalOwner.tryGet(error);check(journal||journalFault,error);
                J records=J::array();
                if(journal) for(const auto& record:journal->records())records.push_back({{"policy",record.policy.policyName},{"status",int(record.status)}});
                output["module"].push_back({{"policy",id},{"applied",applied},
                    {"before_pid",before.at("MainPID")},{"after_pid",after.at("MainPID")},
                    {"before_invocation",before.at("InvocationID")},{"after_invocation",after.at("InvocationID")},
                    {"main_unchanged",mainBefore==text("/etc/ssh/sshd_config")},{"records",records},
                    {"journal_unusable",journal==nullptr},{"journal_unchanged",journalBefore==text(work+"/module-state/journal.json")},{"journal_sha",fic::core::ContentDigest::sha256Hex(text(work+"/module-state/journal.json"))}});
            }
            AtomicFileWriter::setDirectoryFsyncHookForTests({});
            journalOwner.resetOverride();
        } else if (action == "cleanup") {
            // Explicit fixture administrator cleanup, never activator crash adoption.
            for (unsigned round = 0; round < 10 && !leftovers().empty(); ++round) {
                auto mounts = leftovers();
                for (auto it = mounts.rbegin(); it != mounts.rend(); ++it) {
                    check(it->target.rfind("/etc/ssh/", 0) == 0 || it->target == "/etc/default/ssh" ||
                          it->target.rfind("/run/fic/verified-config-activator/", 0) == 0, "unexpected residual target");
                    ::umount(it->target.c_str());
                }
            }
            check(leftovers().empty(), "fixture cleanup failed"); output["clean"] = true;
        } else if(action=="capture-reference") {
            output["reference_capture_succeeded"]=false;
            std::string expected;
            for(const auto& p:r.paths)if(p.path=="/etc/ssh/sshd_config")expected=p.sha256;
            const auto policies=input.value("policies",std::map<std::string,std::string>{{"ssh_root_login","no"},{"ssh_pubkey_auth","yes"},{"ssh_use_pam","yes"},{"ssh_max_auth_tries","3"},{"ssh_port","2222"}});
            const auto admitted=fic::service::ssh::SshVerifiedActivationAdapter::serviceAdmission();
            const auto request=fic::service::ssh::SshVerifiedActivationAdapter::captureReference(policies,expected);
            output["reference_capture_succeeded"]=true;output["reference"]=J{{"timeout_ms",request.reference.timeout.count()},{"paths",J::array()},{"policies",policies},{"observed_metadata",request.observedMetadata},{"expected_service",admitted}};
            for(const auto& p:request.reference.paths) {
                J target{{"path",p.path.string()}};
                if(p.kind==ControlledPathKind::Directory){target["directory"]=true;target["manifest"]=p.manifest;}
                else target["sha256"]=p.sha256;
                output["reference"]["paths"].push_back(target);
            }
        } else if (action == "preflight") {
            const auto launch = d::readLaunchContract(r.unit, std::chrono::steady_clock::now() + std::chrono::seconds(10));
            for (const auto& key : {"FragmentPath", "DropInPaths", "EnvironmentFiles", "ExecStartEx", "ExecStartPreEx", "ExecStartPostEx", "TriggeredBy"})
                output[key] = J::parse(launch.at("launch." + std::string(key)));
            d::SystemdActivation service(r.unit, std::chrono::steady_clock::now() + r.timeout, r.paths);
            auto state = service.preflight();
            output["status"] = "SUPPORTED";
            for (const auto& key : {"Type", "NotifyAccess", "MainPID", "InvocationID", "ActiveState", "SubState", "Job"}) output[key] = state.at(key);
            for (const auto& p : r.paths) {
                d::requireSafePublicationParent(p.path, false, ActivationStatus::UnsupportedConfiguration);
                auto fd = d::openAbsolute(p.path, O_RDONLY);
                char names[4096]; const auto count = ::flistxattr(fd.get(), names, sizeof names);
                J attrs = J::array();
                if (count > 0) for (ssize_t i = 0; i < count; ) { std::string name(names+i); attrs.push_back(name); i += name.size()+1; }
                output["input_metadata"].push_back({{"path", p.path.string()}, {"xattr_names", attrs},
                    {"xattr_size_query", ::flistxattr(fd.get(), nullptr, 0)}, {"xattr_list_count", count}});
                try { d::verifyTree(fd.get(), p, r.maxSnapshotBytes); }
                catch (const d::Failure& e) { throw d::Failure(e.status, p.path.string() + ": " + e.what()); }
            }
            d::requireSafePublicationParent("/run/fic/verified-config-activator/future", true, ActivationStatus::UnsupportedConfiguration);
            SshConfigAudit audit({"/etc/ssh/sshd_config", "/etc/ssh", 16, 256, true}); std::string identity;
            check(audit.sourceIdentity(identity, error), error); output["include_identity"] = identity;
        } else {
            const bool adapter = action.rfind("adapter", 0) == 0;
            d::LaunchContract launchBefore;
            try { launchBefore=d::readLaunchContract(r.unit,std::chrono::steady_clock::now()+std::chrono::seconds(10)); }
            catch(const d::Failure& e) {
                if(!adapter)throw;
                // Inactive units can be garbage-collected. Instrumentation
                // must not preempt the production adapter's own refusal.
                output["pre_launch_probe_error"]=e.what();
            }
            const std::string fault = action == "activate" || action == "adapter" ? "" : adapter ? action.substr(8) : action;
            pid_t stoppedService=-1;bool serviceTraced=false;
            const auto originalMain=text("/etc/ssh/sshd_config");
            if(fault.rfind("pending-",0)==0) {
                stoppedService=std::stoi(d::SystemdActivation(r.unit,std::chrono::steady_clock::now()+std::chrono::seconds(10),r.paths).current().at("MainPID"));
                // A plain SIGSTOP is not a barrier: systemd sends SIGCONT while
                // stopping a unit. Hold a real ptrace event-stop instead.
                check(stoppedService>1&&::ptrace(PTRACE_SEIZE,stoppedService,nullptr,nullptr)==0,"seize fixture-owned sshd");
                serviceTraced=true;
                check(::ptrace(PTRACE_INTERRUPT,stoppedService,nullptr,nullptr)==0,"interrupt fixture-owned sshd");
                const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
                int status=0;pid_t observed=0;
                while((observed=::waitpid(stoppedService,&status,__WALL|WNOHANG))==0) {
                    check(std::chrono::steady_clock::now()<deadline,"ptrace event-stop deadline");::sched_yield();
                }
                check(observed==stoppedService&&WIFSTOPPED(status),"ptrace event-stop barrier");
                ctl({"restart","--no-block","ssh.service"});
                while(d::SystemdActivation(r.unit,deadline,r.paths).current().at("ActiveState")!="deactivating") {
                    check(std::chrono::steady_clock::now()<deadline,"pending restart barrier deadline");::sched_yield();
                }
                if(fault=="pending-timeout")r.timeout=std::chrono::milliseconds(500);
            }
            d::Fd key(::open("/etc/ssh/ssh_host_ed25519_key", O_RDONLY|O_CLOEXEC));
            d::TestHooks hooks; d::Fd busy, original(::open("/etc/ssh/sshd_config", O_RDWR|O_CLOEXEC));
            const auto globDirectory = input.value("glob_dir", "/etc/ssh/sshd_config.d");
            d::Fd directory(::open(globDirectory.c_str(), O_RDONLY|O_DIRECTORY|O_CLOEXEC));
            pid_t blocked = -1; bool foreign = false; d::Fd fifoReady;
            output["checkpoints"] = J::array();
            hooks.checkpoint = [&](d::TestPhase phase, const std::string& snapshot) {
                if (phase == d::TestPhase::SnapshotReadOnly && fault == "inode") {
                    fs::rename("/etc/ssh/sshd_config", "/etc/ssh/.fic-native-old");
                    write("/etc/ssh/sshd_config", text("/etc/ssh/.fic-native-old"));
                }
                if (phase == d::TestPhase::Watching) {
                    J evidence = J::array();
                    for (const auto& p : r.paths) {
                        auto fd = d::openAbsolute(p.path, O_RDONLY); const auto id = d::identity(fd.get());
                        d::verifyTree(fd.get(), p, r.maxSnapshotBytes);
                        evidence.push_back({{"path", p.path.string()}, {"mount", id.mount}, {"inode", id.inode}});
                    }
                    output["published"] = evidence;
                    if (fault == "key-xattr") check(::fsetxattr(key.get(), "user.fic-test", "x", 1, 0)==0, "original key xattr");
                    if (fault == "key-mode") check(::fchmod(key.get(), 0644) == 0, "original private key mode");
                    if (fault == "config-mode") check(::fchmod(original.get(), 0600) == 0, "original config mode");
                    if (fault == "config-uid") check(::fchown(original.get(), 123, -1) == 0, "original config UID");
                    if (fault == "config-gid") check(::fchown(original.get(), -1, 123) == 0, "original config GID");
                    if (fault == "directory-mode") check(::fchmod(directory.get(), 0700) == 0, "original Include directory mode");
                    if (fault == "included-inode") {
                        check(::renameat(directory.get(), "10-inode.conf", directory.get(), "old.inc") == 0, "rename original Include child");
                        d::Fd old(::openat(directory.get(), "old.inc", O_RDONLY|O_CLOEXEC));
                        struct stat st{}; check(old && ::fstat(old.get(), &st) == 0, "old Include identity");
                        d::Fd replacement(::openat(directory.get(), "10-inode.conf", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, st.st_mode & 0777));
                        const std::string bytes = "# identical inode fixture\n";
                        check(replacement && ::write(replacement.get(), bytes.data(), bytes.size()) == ssize_t(bytes.size()) &&
                              ::fchown(replacement.get(), st.st_uid, st.st_gid) == 0, "replace Include inode");
                        struct stat now{}; check(::fstat(replacement.get(), &now)==0 && now.st_ino != st.st_ino, "new inode required");
                        check(::unlinkat(directory.get(), "old.inc", 0)==0, "remove displaced fixture");
                    }
                    if (fault == "original-write") {
                        const auto bytes = text(work + "/mutation.conf");
                        check(::ftruncate(original.get(), 0) == 0 && ::write(original.get(), bytes.data(), bytes.size()) == ssize_t(bytes.size()), "original FD write");
                    }
                    if (fault == "new-glob") {
                        d::Fd f(::openat(directory.get(), "00-new.conf", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0644));
                        const std::string bytes = "VersionAddendum GLOB\n";
                        check(f && ::write(f.get(), bytes.data(), bytes.size()) == ssize_t(bytes.size()), "original directory FD write");
                    }
                    if (fault == "ro-write") {
                        d::Fd f(::open("/etc/ssh/sshd_config", O_WRONLY|O_CLOEXEC));
                        check(!f && errno == EROFS, "RO write unexpectedly allowed"); output["write_errno"] = "EROFS";
                    }
                    if (fault == "aba") {
                        check(::mount((work + "/mutation.conf").c_str(), "/etc/ssh/sshd_config", nullptr, MS_BIND, nullptr) == 0, "mount ABA bind");
                        check(::umount("/etc/ssh/sshd_config") == 0, "mount ABA unmount");
                    }
                    if (fault == "contract-before") ctl({"set-environment", "FIC_OPENSSH_TEST_CHANGE=before"});
                    if (fault == "crash") ::kill(::getpid(), SIGKILL);
                    if (fault == "no-ready") {
                        int ready[2]; check(::pipe2(ready, O_CLOEXEC) == 0, "FIFO barrier pipe");
                        fifoReady = d::Fd(ready[0]); d::Fd notify(ready[1]);
                        blocked = ::fork(); check(blocked >= 0, "fork FIFO writer");
                        if (!blocked) {
                            d::Fd fifo(::open((work + "/blocked.conf").c_str(), O_WRONLY));
                            if (!fifo || ::write(notify.get(), "R", 1) != 1) ::_exit(91);
                            for (;;) ::pause();
                        }
                    }
                }
                if (phase == d::TestPhase::RestartQueued && fault == "no-ready") {
                    pollfd p{fifoReady.get(), POLLIN, 0}; char byte;
                    check(::poll(&p, 1, 3000) > 0 && ::read(fifoReady.get(), &byte, 1) == 1 && byte == 'R', "real sshd FIFO reader barrier");
                    output["fifo_reader_connected"] = true;
                    ProcessOptions opts; opts.timeout = std::chrono::seconds(3); opts.clearEnvironment = true;
                    auto state = ProcessExecutor::execute("/usr/bin/systemctl",
                        {"show", "ssh.service", "--property=MainPID,ActiveState,SubState,InvocationID"}, opts);
                    check(state.success(), "no-ready state collection"); output["blocked_service_state"] = state.standardOutput;
                }
                if (phase == d::TestPhase::RestartQueued && fault == "contract-after") ctl({"set-environment", "FIC_OPENSSH_TEST_CHANGE=after"});
                if (phase == d::TestPhase::BeforeCleanup) {
                    if(fault=="ready-stop") ctl({"stop","ssh.service"});
                    if(fault=="ready-disable") ctl({"disable","ssh.service"});
                    if(fault=="ready-foreign-restart") ctl({"restart","ssh.service"});
                    if (fault == "key-mode" || fault == "config-mode" || fault == "config-uid" || fault == "config-gid" ||
                        fault == "directory-mode" || fault == "included-inode" || fault == "key-xattr") {
                        ProcessOptions opts; opts.timeout = std::chrono::seconds(5); opts.clearEnvironment = true;
                        const auto probe = ProcessExecutor::execute("/usr/bin/ssh-keyscan", {"-T", "2", "-t", "ed25519", "-p", "2222", "127.0.0.1"}, opts);
                        check(probe.success() && (probe.standardError + probe.standardOutput).find("FIC_VERIFIED") != std::string::npos &&
                              !probe.standardOutput.empty(), "protected real SSH handshake");
                        output["protected_handshake_confirmed"] = true;
                    }
                    if (fault == "busy") busy = d::openAbsolute("/etc/ssh/sshd_config", O_RDONLY);
                    if (fault == "foreign") {
                        check(::mount((work + "/mutation.conf").c_str(), "/etc/ssh/sshd_config", nullptr, MS_BIND, nullptr) == 0, "foreign overlay"); foreign = true;
                    }
                }
            };
            output["activation_invoked"] = true;
            ActivationResult result;
            if (adapter) {
                namespace ssh = fic::service::ssh;
                ssh::SshVerifiedActivationRequest request;
                request.reference = r;
                request.observedMetadata=input.value("observed_metadata",std::map<std::string,std::string>{});
                request.expectedService=input.value("expected_service",std::map<std::string,std::string>{});
                request.policies = input.value("policies", std::map<std::string,std::string>{{"ssh_root_login","no"},{"ssh_pubkey_auth","yes"},{"ssh_use_pam","yes"},{"ssh_max_auth_tries","3"},{"ssh_port","2222"}});
                ssh::SshVerifiedActivationResult verified;
                if (action == "adapter") verified = ssh::SshVerifiedActivationAdapter::activate(request);
                else {
                    ssh::detail::AdapterTestHooks seam;
                    seam.beforeFinalConfirmation=[&] {
                        if(fault=="final-disable")ctl({"disable","ssh.service"});
                        if(fault=="final-restart")ctl({"restart","ssh.service"});
                    };
                    bool admissionObserved=false;
                    seam.admissionWait=[&] {
                        if(stoppedService>1&&!admissionObserved) {
                            admissionObserved=true;output["admission_wait_observed"]=true;
                            if(fault=="pending-failed")write("/etc/ssh/sshd_config","InvalidFicDirective yes\n");
                            if(fault!="pending-timeout") {
                                check(::ptrace(PTRACE_DETACH,stoppedService,nullptr,reinterpret_cast<void*>(static_cast<intptr_t>(SIGTERM)))==0,"release native admission barrier");
                                serviceTraced=false;
                            }
                        }
                    }; seam.activation = hooks;
                    seam.beforeActivation = [&] {
                        if (fault == "source-before") write("/etc/ssh/sshd_config", text(work + "/mutation.conf"));
                        if (fault == "source-inode-before") {
                            fs::rename("/etc/ssh/sshd_config", "/etc/ssh/.fic-native-old");
                            write("/etc/ssh/sshd_config", text("/etc/ssh/.fic-native-old"));
                        }
                        if (fault == "source-mode-before") check(::chmod("/etc/ssh/sshd_config", 0600) == 0, "source mode race");
                        if (fault == "glob-before") write(globDirectory + "/00-new.conf", "MaxAuthTries 1\n");
                        if (fault == "directory-before") {
                            check(fs::is_empty(globDirectory) && fs::remove(globDirectory), "replace empty original directory");
                            check(fs::create_directory(globDirectory), "create replacement directory");
                        }
                        if (fault == "contract-preflight") ctl({"set-environment", "FIC_OPENSSH_TEST_CHANGE=preflight"});
                    };
                    verified = ssh::detail::activateAdapterForTests(request, seam);
                }
                const auto proof = [](ssh::ProofState p) {
                    switch (p) { case ssh::ProofState::Proven: return "Proven"; case ssh::ProofState::NonCompliant: return "NonCompliant";
                        case ssh::ProofState::Unsupported: return "Unsupported"; default: return "NotProven"; }
                };
                output["adapter_success"] = verified.success(); output["adapter_status"] = int(verified.status);
                output["activation_invoked"] = verified.activationAttempted;
                output["A"] = proof(verified.inputs); output["C"] = proof(verified.semantics); output["P"] = proof(verified.persistent);
                output["adapter_diagnostic"] = verified.diagnostic;
                result = verified.activation;
            } else result = action == "activate" ? VerifiedConfigServiceActivator::activate(r) : d::activateForTests(r, hooks);
            if(stoppedService>1) {
                // Only fixture-owned process/job, after the product result.
                if(serviceTraced) {
                    check(::ptrace(PTRACE_DETACH,stoppedService,nullptr,reinterpret_cast<void*>(static_cast<intptr_t>(SIGTERM)))==0,"release timed-out fixture barrier");
                    serviceTraced=false;
                }
                if(fault!="pending-ready")ctl({"stop","ssh.service"});
                if(fault=="pending-failed")write("/etc/ssh/sshd_config",originalMain);
            }
            output["status"] = activationStatusName(result.status); output["primaryStatus"] = activationStatusName(result.primaryStatus);
            output["readinessConfirmed"] = result.readinessConfirmed; output["diagnostic"] = result.diagnostic;
            output["cleanupErrors"] = result.cleanupErrors; output["residualPaths"] = result.residualPaths;
            try {
                const auto launchAfter = d::readLaunchContract(r.unit, std::chrono::steady_clock::now() + std::chrono::seconds(10));
                output["launch_contract_stable"] = launchBefore == launchAfter;
            } catch (const d::Failure& e) { output["post_launch_probe_error"] = e.what(); }
            output["launch_contract_sha256"] = fic::core::ContentDigest::sha256Hex(J(launchBefore).dump());
            output["residual_count_before_admin_cleanup"] = leftovers().size();
            if (blocked > 0) { ::kill(blocked, SIGKILL); ::waitpid(blocked, nullptr, 0); }
            if (foreign) { output["foreign_preserved"] = text("/etc/ssh/sshd_config") == text(work + "/mutation.conf"); check(::umount("/etc/ssh/sshd_config") == 0, "fixture foreign cleanup"); }
            if (fault == "inode" || fault == "source-inode-before") fs::remove("/etc/ssh/.fic-native-old");
            // busy closes after result capture; explicit cleanup is a separate command.
        }
    } catch (const d::Failure& e) { output["status"] = activationStatusName(e.status); output["diagnostic"] = e.what(); }
      catch (const std::exception& e) { output["harness_error"] = e.what(); }
    std::cout << output.dump() << std::endl;
    return output.contains("harness_error") ? 1 : 0;
}
