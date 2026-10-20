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
#include <signal.h>
#include <poll.h>
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
        if (action == "cleanup") {
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
            const auto launchBefore = d::readLaunchContract(r.unit, std::chrono::steady_clock::now() + std::chrono::seconds(10));
            const bool adapter = action.rfind("adapter", 0) == 0;
            const std::string fault = action == "activate" || action == "adapter" ? "" : adapter ? action.substr(8) : action;
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
                request.policies = input.value("policies", std::map<std::string,std::string>{{"ssh_root_login","no"},{"ssh_pubkey_auth","yes"},{"ssh_use_pam","yes"},{"ssh_max_auth_tries","3"},{"ssh_port","2222"}});
                ssh::SshVerifiedActivationResult verified;
                if (action == "adapter") verified = ssh::SshVerifiedActivationAdapter::activate(request);
                else {
                    ssh::detail::AdapterTestHooks seam; seam.activation = hooks;
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
