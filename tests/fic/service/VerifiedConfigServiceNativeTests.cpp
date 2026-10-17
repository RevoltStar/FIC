#include "service/VerifiedConfigServiceActivator.h"
#include "service/VerifiedConfigMountSupport.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/ProcessExecutor.h>
#include <systemd/sd-daemon.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <functional>
#include <fcntl.h>
#include <linux/mount.h>
#include <poll.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sched.h>
#include <unistd.h>

using namespace fic::service;
namespace d = fic::service::detail;
namespace fs = std::filesystem;
const std::string root = "/etc/fic-vcsa-tests";
const std::string runRoot = "/run/fic-vcsa-tests";
const std::string unit = "fic-vcsa-test.service";
unsigned checks = 0, skips = 0;
void require(bool yes, const std::string& text) { if (!yes) throw std::runtime_error(text); }
void pass(const std::string& text) { ++checks; std::cout << "PASS " << text << std::endl; }
std::string read(const std::string& path) { std::ifstream f(path); require(bool(f), "read " + path); return {std::istreambuf_iterator<char>(f), {}}; }
void write(const std::string& path, const std::string& text) { std::ofstream f(path); require(bool(f), "write " + path); f << text; }
std::string digest(const std::string& text) { return fic::core::ContentDigest::sha256Hex(text); }
std::string configurationDigest() { return digest(read(root + "/one.conf") + "|" + read(root + "/dropins/a.conf") + "|" + read(root + "/dropins/sub/b.conf")); }
void waitFd(int fd, short events) { pollfd p{fd, events, 0}; require(::poll(&p, 1, 5000) > 0 && (p.revents & events), "native IPC barrier timeout"); }
void sendPacket(int fd, const std::string& text) { require(::send(fd, text.data(), text.size(), MSG_NOSIGNAL) == ssize_t(text.size()), "send barrier"); }
std::string receive(int fd) { waitFd(fd, POLLIN); char data[4096]; auto n = ::recv(fd, data, sizeof data, 0); require(n > 0, "receive barrier"); return {data, std::size_t(n)}; }
int serviceMain() {
    const auto mode = read(runRoot + "/mode");
    if (mode == "exit") return 23;
    d::Fd connection(::socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0));
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    const auto path = runRoot + "/control"; std::copy(path.begin(), path.end(), address.sun_path);
    const bool controlled = ::connect(connection.get(), reinterpret_cast<sockaddr*>(&address), sizeof address) == 0;
    if (controlled) { sendPacket(connection.get(), "BEFORE_READ"); require(receive(connection.get()) == "READ", "read barrier command"); }
    const auto seen = configurationDigest(); write(runRoot + "/seen", seen);
    if (controlled) { sendPacket(connection.get(), "READ_DONE:" + seen); require(receive(connection.get()) == "NOTIFY", "notify barrier command"); }
    if (mode != "silent") require(sd_notify(0, "READY=1") > 0, "sd_notify");
    while (true) ::pause();
}
struct Gate {
    d::Fd server, connection;
    std::string seen;
    Gate() : server(::socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0)) {
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        const auto path = runRoot + "/control"; ::unlink(path.c_str()); std::copy(path.begin(), path.end(), address.sun_path);
        require(::bind(server.get(), reinterpret_cast<sockaddr*>(&address), sizeof address) == 0 && ::listen(server.get(), 1) == 0, "create control socket");
    }
    ~Gate() { ::unlink((runRoot + "/control").c_str()); }
    void beforeRead() {
        waitFd(server.get(), POLLIN); connection = d::Fd(::accept4(server.get(), nullptr, nullptr, SOCK_CLOEXEC));
        require(receive(connection.get()) == "BEFORE_READ", "service entered read barrier");
    }
    void readNow() { sendPacket(connection.get(), "READ"); auto message = receive(connection.get()); require(message.rfind("READ_DONE:", 0) == 0, "read completion"); seen = message.substr(10); }
    void notify() { sendPacket(connection.get(), "NOTIFY"); }
};
ProcessResult ctl(const std::vector<std::string>& args) {
    const auto profile = fic::platform::makeBuildPlatformProfile();
    fic::platform::PlatformExecutableResolver resolver(profile.executables); fs::path path; std::string error;
    require(resolver.resolve(fic::platform::ExecutableId::Systemctl, path, error), error);
    ProcessOptions options; options.timeout = std::chrono::seconds(15);
    return ProcessExecutor::execute(path, args, options); // test setup ONLY
}
void mustCtl(const std::vector<std::string>& args) { auto r = ctl(args); require(r.success(), "test systemctl: " + r.error + r.standardError); }
void active() {
    ::unlink((runRoot + "/control").c_str()); write(runRoot + "/mode", "normal");
    mustCtl({"stop", unit}); ctl({"reset-failed", unit}); mustCtl({"start", unit});
}
ControlledPath one() { return {root + "/one.conf", ControlledPathKind::File, digest("one\n"), {}}; }
ControlledPath directory() { return {root + "/dropins", ControlledPathKind::Directory, "", {{"a.conf", digest("alpha\n")}, {"sub/b.conf", digest("beta\n")}}}; }
ActivationRequest request(std::vector<ControlledPath> paths = {one()}) { ActivationRequest r; r.paths = std::move(paths); r.unit = unit; r.timeout = std::chrono::seconds(10); return r; }
std::vector<d::MountRecord> leftovers() { std::vector<d::MountRecord> out; for (const auto& r : d::readMountInfo()) if (r.source.rfind("fic-vcsa.", 0) == 0) out.push_back(r); return out; }
void manualCleanup() {
    for (unsigned round = 0; round < 10; ++round) {
        auto mounts = leftovers(); if (mounts.empty()) return;
        std::reverse(mounts.begin(), mounts.end());
        for (const auto& m : mounts) ::umount2(m.target.c_str(), 0);
    }
    require(leftovers().empty(), "test admin cleanup left mounts");
}
ActivationResult activate(const ActivationRequest& r, const d::TestHooks& hooks = {}) {
    auto result = d::activateForTests(r, hooks);
    std::cout << "RESULT " << activationStatusName(result.status) << ": " << result.diagnostic << std::endl;
    for (const auto& e : result.cleanupErrors) std::cout << "CLEANUP " << e << std::endl;
    return result;
}
void clean(const std::string& expected) { require(leftovers().empty() && configurationDigest() == expected, "mount leak or permanent configuration mutation"); }
void basicCases() {
    const auto before = configurationDigest();
    for (const auto& paths : {std::vector<ControlledPath>{one()}, std::vector<ControlledPath>{directory()}, std::vector<ControlledPath>{one(), directory()}}) {
        const auto result = activate(request(paths));
        require(result.success() && result.readinessConfirmed && read(runRoot + "/seen") == before, "real notify activation/read failed");
        clean(before); pass("real notify file/directory activation and exact service read; ordinary cleanup");
    }
    require(activate(request()).success(), "repeat after cleanup"); clean(before); pass("repeat after successful cleanup");
    require(::chown((root + "/one.conf").c_str(), 12345, 23456) == 0 && ::chmod((root + "/one.conf").c_str(), 0640) == 0, "prepare source metadata");
    d::TestHooks metadata;
    metadata.checkpoint = [&](d::TestPhase phase, const std::string& path) {
        if (phase != d::TestPhase::SnapshotReadOnly) return;
        struct stat st{};
        require(::stat((path + "/0").c_str(), &st) == 0 && st.st_uid == 12345 && st.st_gid == 23456 && (st.st_mode & 07777) == 0640, "snapshot lost owner/group/mode");
    };
    require(activate(request(), metadata).success(), "metadata activation");
    require(::chown((root + "/one.conf").c_str(), 0, 0) == 0 && ::chmod((root + "/one.conf").c_str(), 0644) == 0, "restore fixture metadata");
    clean(before); pass("snapshot preserves owner/group/mode");
    require(::chmod((root + "/one.conf").c_str(), 04644) == 0, "prepare unsupported mode");
    require(activate(request()).status == ActivationStatus::UnsupportedConfiguration, "special mode silently stripped");
    require(::chmod((root + "/one.conf").c_str(), 0644) == 0, "restore special mode"); clean(before); pass("unsupported special permission bits refused before mount");
    auto r = request(); r.paths[0].sha256 = digest("wrong");
    require(activate(r).status == ActivationStatus::ChecksumMismatch, "wrong SHA accepted"); clean(before); pass("wrong checksum refused");
    r = request(); r.paths[0].path = root + "/absent";
    require(activate(r).status == ActivationStatus::ChecksumMismatch, "missing file accepted"); pass("missing file refused");
    write(root + "/dropins/extra", "extra");
    require(activate(request({directory()})).status == ActivationStatus::ChecksumMismatch, "extra file accepted"); fs::remove(root + "/dropins/extra"); pass("extra manifest file refused");
    fs::create_symlink(root + "/one.conf", root + "/link"); r = request(); r.paths[0].path = root + "/link";
    require(activate(r).status == ActivationStatus::UnsupportedConfiguration, "symlink accepted"); fs::remove(root + "/link"); pass("symlink refused");
    r = request({one(), directory()}); r.paths[1].path = root;
    require(activate(r).status == ActivationStatus::UnsupportedConfiguration, "overlap accepted"); pass("overlap refused");
    fs::create_directory(root + "/nested"); require(::mount("probe", (root + "/nested").c_str(), "tmpfs", 0, "size=65536") == 0, "native nested mount setup");
    r = request(); r.paths[0] = {root, ControlledPathKind::Directory, "", {}};
    require(activate(r).status == ActivationStatus::UnsupportedConfiguration, "nested mount accepted"); require(::umount2((root + "/nested").c_str(), 0) == 0, "remove nested probe"); fs::remove(root + "/nested"); pass("unexpected nested mount refused");
    for (const auto& operation : {std::string("tmpfs"), std::string("readonly"), std::string("bind")}) {
        d::TestHooks hooks; hooks.fault = [&](const std::string& action, std::size_t index) { return action == operation && (action != "bind" || index == 1) ? EIO : 0; };
        const auto result = activate(request({one(), directory()}), hooks);
        require(result.status == (operation == "bind" ? ActivationStatus::MountFailed : ActivationStatus::SnapshotFailed), "injected syscall failure reported success");
        clean(before); pass(operation + " failure and partial-mount cleanup");
    }
    d::TestHooks ro;
    ro.checkpoint = [&](d::TestPhase phase, const std::string& path) {
        if (phase == d::TestPhase::SnapshotReadOnly) {
            const int fd = ::open((path + "/0").c_str(), O_WRONLY); const int error = errno;
            if (fd >= 0) ::close(fd); require(fd < 0 && error == EROFS, "snapshot not superblock RO");
        }
    };
    require(activate(request(), ro).success(), "RO test activation"); clean(before); pass("actual write to snapshot fails EROFS");
    write(runRoot + "/mode", "exit");
    require(activate(request()).status == ActivationStatus::RestartFailed, "failed service restart accepted"); clean(before); pass("real restart failure"); active();
    write(runRoot + "/mode", "silent"); r = request(); r.timeout = std::chrono::milliseconds(1000);
    const auto timeout = activate(r); require(timeout.status == ActivationStatus::TimedOut && !timeout.readinessConfirmed, "silent notify service accepted"); clean(before); pass("readiness timeout is not success"); active();
    auto simple = read("/etc/systemd/system/" + unit); const auto at = simple.find("Type=notify"); simple.replace(at, 11, "Type=simple"); write("/etc/systemd/system/fic-vcsa-simple.service", simple);
    mustCtl({"daemon-reload"}); mustCtl({"start", "fic-vcsa-simple.service"});
    r = request(); r.unit = "fic-vcsa-simple.service";
    require(activate(r).status == ActivationStatus::UnsupportedConfiguration, "simple readiness falsely accepted"); mustCtl({"stop", "fic-vcsa-simple.service"}); pass("simple service rejected before mounting");
    mustCtl({"stop", unit}); require(activate(request()).status == ActivationStatus::UnsupportedConfiguration, "inactive service started"); pass("inactive service not started"); active(); clean(before);
}
void namespaceRaces() {
    const auto before = configurationDigest();
    for (const auto& action : {std::string("aba"), std::string("remount"), std::string("mount_setattr")}) {
        Gate gate; bool supported = true, observed = false;
        d::TestHooks hooks;
        hooks.checkpoint = [&](d::TestPhase phase, const std::string& path) {
            if (phase != d::TestPhase::RestartQueued) return;
            gate.beforeRead(); d::MountObserver probe;
            if (action == "aba") {
                require(::mount((root + "/alternate").c_str(), (root + "/one.conf").c_str(), nullptr, MS_BIND, nullptr) == 0, "ABA bind");
                require(::umount2((root + "/one.conf").c_str(), 0) == 0, "ABA umount");
            } else if (action == "remount") {
                require(::mount(nullptr, path.c_str(), nullptr, MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC, nullptr) == 0, "remount rw");
                require(::mount(nullptr, path.c_str(), nullptr, MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC, nullptr) == 0, "remount ro");
            } else {
#ifdef SYS_mount_setattr
                mount_attr attr{}; attr.attr_clr = MOUNT_ATTR_RDONLY;
                if (::syscall(SYS_mount_setattr, AT_FDCWD, (root + "/one.conf").c_str(), 0, &attr, sizeof attr) != 0) {
                    supported = false; std::cout << "SKIP mount_setattr: " << std::strerror(errno) << std::endl; ++skips;
                } else { attr = {}; attr.attr_set = MOUNT_ATTR_RDONLY; require(::syscall(SYS_mount_setattr, AT_FDCWD, (root + "/one.conf").c_str(), 0, &attr, sizeof attr) == 0, "restore mount attrs"); }
#else
                supported = false; ++skips; std::cout << "SKIP mount_setattr: headers unavailable" << std::endl;
#endif
            }
            observed = probe.changed(); if (observed) require(probe.changed(), "observer lost latched event after second poll");
            gate.readNow(); gate.notify();
        };
        const auto result = activate(request(), hooks);
        if (supported) {
            require(observed && result.primaryStatus == ActivationStatus::InterferenceDetected && !result.success(), "namespace race escaped observer");
            pass(action + " ABA detected; sticky poll survives intermediate polls");
        }
        clean(before); active();
    }
}
void crossNamespaceCases() {
    const auto before = configurationDigest();
    for (const auto& method : {std::string("other_namespace_remount"), std::string("fspick_fsconfig")})
    for (bool writeBytes : {false, true}) {
        Gate gate; bool supported = true, event = false;
        d::TestHooks hooks;
        hooks.checkpoint = [&](d::TestPhase phase, const std::string& path) {
            if (phase != d::TestPhase::RestartQueued) return;
            gate.beforeRead(); d::MountObserver observer;
            int pair[2]; require(::socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) == 0, "actor IPC");
            d::Fd parent(pair[0]), childEnd(pair[1]);
            const auto pid = ::fork(); require(pid >= 0, "namespace actor fork");
            if (pid == 0) {
                parent = d::Fd();
                bool writable = false;
                auto restoreRo = [&] { ::mount(nullptr, path.c_str(), nullptr, MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC, nullptr); };
                try {
                    auto unsupported = [&](const std::string& operation) {
                        const auto text = "SKIP " + operation + ": " + std::strerror(errno);
                        if (writable) restoreRo(); sendPacket(childEnd.get(), text); ::_exit(77);
                    };
                    if (::unshare(CLONE_NEWNS) || ::mount(nullptr, "/", nullptr, MS_REC|MS_PRIVATE, nullptr)) unsupported("alternate mount namespace");
                    if (method == "other_namespace_remount") {
                        if (::mount(nullptr, path.c_str(), nullptr, MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC, nullptr)) unsupported(method);
                        writable = true;
                    } else {
#if defined(SYS_fspick) && defined(SYS_fsconfig) && defined(SYS_mount_setattr)
                        d::Fd context(::syscall(SYS_fspick, AT_FDCWD, path.c_str(), FSPICK_CLOEXEC));
                        if (!context || ::syscall(SYS_fsconfig, context.get(), FSCONFIG_SET_FLAG, "rw", nullptr, 0) ||
                            ::syscall(SYS_fsconfig, context.get(), FSCONFIG_CMD_RECONFIGURE, nullptr, nullptr, 0)) unsupported(method);
                        writable = true;
                        mount_attr attr{}; attr.attr_clr = MOUNT_ATTR_RDONLY;
                        if (::syscall(SYS_mount_setattr, AT_FDCWD, path.c_str(), 0, &attr, sizeof attr)) unsupported("alternate mount_setattr");
#else
                        errno = ENOSYS; unsupported("fspick/fsconfig headers");
#endif
                    }
                    const auto original = read(path + "/0");
                    if (writeBytes) write(path + "/0", "evil\n");
                    sendPacket(childEnd.get(), "PREPARED"); require(receive(childEnd.get()) == "RESTORE", "actor restore barrier");
                    if (writeBytes) write(path + "/0", original);
                    if (method == "fspick_fsconfig") {
#if defined(SYS_fspick) && defined(SYS_fsconfig)
                        d::Fd context(::syscall(SYS_fspick, AT_FDCWD, path.c_str(), FSPICK_CLOEXEC));
                        require(bool(context) && ::syscall(SYS_fsconfig, context.get(), FSCONFIG_SET_FLAG, "ro", nullptr, 0) == 0 &&
                            ::syscall(SYS_fsconfig, context.get(), FSCONFIG_CMD_RECONFIGURE, nullptr, nullptr, 0) == 0, "fsconfig restore RO");
#endif
                    }
                    restoreRo(); sendPacket(childEnd.get(), "RESTORED"); ::_exit(0);
                } catch (const std::exception& e) {
                    restoreRo(); sendPacket(childEnd.get(), std::string("ERROR ") + e.what()); ::_exit(1);
                }
            }
            childEnd = d::Fd();
            const auto message = receive(parent.get());
            if (message.rfind("SKIP ", 0) == 0) {
                supported = false; ++skips; std::cout << message << std::endl;
                gate.readNow(); gate.notify();
            } else {
                require(message == "PREPARED", message);
                gate.readNow();
                require((gate.seen != before) == writeBytes, "service did not actually consume actor's snapshot bytes");
                sendPacket(parent.get(), "RESTORE"); require(receive(parent.get()) == "RESTORED", "actor failed restore");
                event = observer.changed(); if (event) require(observer.changed(), "cross-namespace event latch lost");
                gate.notify();
            }
            int status = 0; require(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == (supported ? 0 : 77), "namespace actor failed");
        };
        const auto result = activate(request(), hooks);
        if (supported) {
            std::cout << "OBSERVATION " << method << " writes=" << writeBytes << " poll=" << event << " result=" << activationStatusName(result.primaryStatus) << std::endl;
            if (writeBytes) require(!result.success() && result.primaryStatus == ActivationStatus::InterferenceDetected,
                                    "restored malicious snapshot bytes escaped identity/attribute proof");
            else if (event) require(!result.success(), "observed namespace intervention accepted");
            else require(result.success() || result.primaryStatus == ActivationStatus::InterferenceDetected, "unexpected cross-namespace outcome");
            pass(method + (writeBytes ? " transient writes rejected despite byte restoration" : " RO flip observation boundary measured (not claimed prevented)"));
        }
        clean(before); active();
    }
}

void cleanupCases() {
    const auto before = configurationDigest();
    d::Fd busy; d::TestHooks hook;
    hook.checkpoint = [&](d::TestPhase phase, const std::string&) {
        if (phase == d::TestPhase::BeforeCleanup) busy = d::openAbsolute(root + "/one.conf", O_RDONLY);
    };
    auto result = activate(request(), hook);
    require(result.status == ActivationStatus::CleanupFailed && result.primaryStatus == ActivationStatus::Success && !result.cleanupErrors.empty(), "busy cleanup converted to Success");
    const auto count = leftovers().size(); require(count > 0, "busy mount did not remain");
    require(activate(request()).status == ActivationStatus::ResidualMounts && leftovers().size() == count, "residual mounts adopted or altered");
    pass("real EBUSY cleanup error visible; primary preserved; residual repeat refused"); busy = d::Fd(); manualCleanup(); clean(before);
    d::TestHooks both;
    both.fault = [](const std::string& action, std::size_t index) { return action == "bind" && index == 1 ? EIO : action == "umount" ? EBUSY : 0; };
    result = activate(request({one(), directory()}), both);
    require(result.status == ActivationStatus::CleanupFailed && result.primaryStatus == ActivationStatus::MountFailed && !result.cleanupErrors.empty(), "cleanup hid primary mount failure");
    manualCleanup(); clean(before); pass("primary and cleanup failures both preserved");
    d::TestHooks foreign;
    foreign.checkpoint = [&](d::TestPhase phase, const std::string&) {
        if (phase == d::TestPhase::BeforeCleanup) require(::mount((root + "/alternate").c_str(), (root + "/one.conf").c_str(), nullptr, MS_BIND, nullptr) == 0, "foreign overmount");
    };
    result = activate(request(), foreign);
    require(result.status == ActivationStatus::CleanupFailed && read(root + "/one.conf") == "foreign\n", "component unmounted foreign overlay");
    require(::umount2((root + "/one.conf").c_str(), 0) == 0, "test admin remove foreign"); manualCleanup(); clean(before); pass("cleanup refuses foreign mount identity");
    const pid_t child = ::fork(); require(child >= 0, "fork crash actor");
    if (!child) {
        d::TestHooks kill;
        kill.checkpoint = [](d::TestPhase phase, const std::string&) { if (phase == d::TestPhase::Watching) ::kill(::getpid(), SIGKILL); };
        d::activateForTests(request(), kill); ::_exit(92);
    }
    int status = 0; require(::waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "crash actor was not killed");
    require(!leftovers().empty() && activate(request()).status == ActivationStatus::ResidualMounts, "SIGKILL mounts not detected");
    manualCleanup(); clean(before); pass("SIGKILL leaves detectable mounts; no automatic adoption/release");
}
int main(int argc, char** argv) {
    try {
        const bool container = fs::exists("/.dockerenv") || fs::exists("/run/.containerenv");
        if (argc == 2 && std::string(argv[1]) == "--service") { require(container, "test service only in container"); return serviceMain(); }
        if (!container || ::geteuid() != 0 || !std::getenv("FIC_ACTIVATOR_NATIVE")) { std::cout << "SKIP native: explicit disposable systemd container required\n"; return 77; }
        std::ifstream procStatus("/proc/self/status"); std::string statusLine; bool admin = false;
        while (std::getline(procStatus, statusLine)) if (statusLine.rfind("CapEff:\t", 0) == 0)
            admin = (std::stoull(statusLine.substr(8), nullptr, 16) & (1ULL << 21)) != 0;
        if (!admin || read("/proc/1/comm") != "systemd\n") { std::cout << "SKIP native: CAP_SYS_ADMIN and systemd PID 1 required\n"; return 77; }
        fs::create_directories(root + "/dropins/sub"); fs::create_directories(runRoot);
        write(root + "/one.conf", "one\n"); write(root + "/dropins/a.conf", "alpha\n"); write(root + "/dropins/sub/b.conf", "beta\n"); write(root + "/alternate", "foreign\n"); write(runRoot + "/mode", "normal");
        auto paths = fic::core::FicProductPaths::production();
        const fs::path state = "/var/lib/fic-vcsa-test";
        paths.configDir = state / "config"; paths.logDir = state / "logs"; paths.dataDir = state / "state"; paths.commandHashFile = state / "command-hashes"; paths.runtimeDir = "/run/fic"; paths.lockDebugLogFile = state / "logs/locks.txt";
        fs::create_directories(paths.configDir); fs::create_directories(paths.logDir); fs::create_directories(paths.dataDir);
        std::string error; require(fic::core::FicRuntimePaths::initialize(paths, error), error);
        const auto profile = fic::platform::makeBuildPlatformProfile(); fic::platform::PlatformExecutableResolver resolver(profile.executables); fs::path systemctl;
        require(resolver.resolve(fic::platform::ExecutableId::Systemctl, systemctl, error) && CommandHashStore::saveHash(systemctl, error), error);
        const auto binary = fs::canonical("/proc/self/exe").string();
        write("/etc/systemd/system/" + unit, "[Unit]\nDescription=Isolated verified-config fixture\nStartLimitIntervalSec=0\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=" + binary + " --service\nTimeoutStartSec=10s\nTimeoutStopSec=2s\n");
        mustCtl({"daemon-reload"}); active(); basicCases(); namespaceRaces(); crossNamespaceCases(); cleanupCases();
        mustCtl({"stop", unit});
        std::cout << "NATIVE verified-config: " << checks << " PASS, " << skips << " SKIP\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL native: " << e.what() << std::endl;
        return 1;
    }
}
