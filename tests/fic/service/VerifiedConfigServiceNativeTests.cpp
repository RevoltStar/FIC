#include "service/VerifiedConfigServiceActivator.h"
#include "service/VerifiedConfigMountSupport.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/process/ProcessExecutor.h>
#include <systemd/sd-daemon.h>
#include <nlohmann/json.hpp>
#include <linux/stat.h>
#include <fic/core/fs/AtomicFileWriter.h>
#include "service/VerifiedConfigLaunchContract.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
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
using Json = nlohmann::json;
const std::vector<std::string> configNames{"one.conf", "dropins/a.conf", "dropins/sub/b.conf"};
void require(bool yes, const std::string& text) { if (!yes) throw std::runtime_error(text); }
void pass(const std::string& text) { ++checks; std::cout << "PASS " << text << std::endl; }
std::string read(const std::string& path) { std::ifstream f(path); require(bool(f), "read " + path); return {std::istreambuf_iterator<char>(f), {}}; }
void write(const std::string& path, const std::string& text) { std::ofstream f(path); require(bool(f), "write " + path); f << text; }
std::string digest(const std::string& text) { return fic::core::ContentDigest::sha256Hex(text); }
std::string configurationDigest() { return digest(read(root + "/one.conf") + "|" + read(root + "/dropins/a.conf") + "|" + read(root + "/dropins/sub/b.conf")); }
void waitFd(int fd, short events) { pollfd p{fd, events, 0}; require(::poll(&p, 1, 5000) > 0 && (p.revents & events), "native IPC barrier timeout"); }
void sendPacket(int fd, const std::string& text) { require(::send(fd, text.data(), text.size(), MSG_NOSIGNAL) == ssize_t(text.size()), "send barrier"); }
std::string receive(int fd) { waitFd(fd, POLLIN); char data[4096]; auto n = ::recv(fd, data, sizeof data, 0); require(n > 0, "receive barrier"); return {data, std::size_t(n)}; }
Json readConfiguration(const std::string& mode, bool alternate) {
    std::string base = alternate ? root + "/alternate-source" : root;
    if (!alternate && std::getenv("FIC_VCSA_CONFIG_ROOT")) base = std::getenv("FIC_VCSA_CONFIG_ROOT");
    std::vector<std::string> originals;
    if (mode.rfind("original:", 0) == 0) {
        std::istringstream values(mode.substr(9)); std::string path;
        while (std::getline(values, path, ',')) originals.push_back(path);
        require(originals.size() == 3, "original FD fixture request");
    }
    Json report; report["files"] = Json::object(); std::string combined;
    std::vector<d::Fd> held;
    for (std::size_t i = 0; i < configNames.size(); ++i) {
        const auto path = originals.empty() ? base + "/" + configNames[i] : originals[i];
        held.emplace_back(::open(path.c_str(), O_RDONLY|O_CLOEXEC)); require(bool(held.back()), "fixture open actual config");
        struct statx st{};
        require(::syscall(SYS_statx, held.back().get(), "", AT_EMPTY_PATH, STATX_MNT_ID|STATX_INO, &st) == 0 &&
                (st.stx_mask & STATX_MNT_ID), "fixture statx actual FD");
        std::string content; char buffer[4096];
        while (true) { const auto n = ::read(held.back().get(), buffer, sizeof buffer); if (n < 0 && errno == EINTR) continue; require(n >= 0, "fixture read FD"); if (!n) break; content.append(buffer, n); }
        if (i) combined += '|'; combined += content;
        report["files"][configNames[i]] = {{"mount", st.stx_mnt_id}, {"inode", st.stx_ino}, {"sha256", digest(content)}};
    }
    report["digest"] = digest(combined);
    return report; // Close actual read descriptors BEFORE READY/ordinary cleanup.
}
using PublishedFiles = std::map<std::string, std::pair<std::uint64_t, std::string>>;
PublishedFiles publishedIds(const ActivationRequest& r, const std::string& base = root) {
    PublishedFiles expected;
    for (const auto& name : configNames) {
        const auto path = base + "/" + name;
        for (const auto& p : r.paths) if (p.path == path || (p.kind == ControlledPathKind::Directory && d::below(path, p.path.string()))) {
            d::Fd fd(::open(path.c_str(), O_RDONLY|O_CLOEXEC)); require(bool(fd), "capture published mount"); const auto sha = p.kind == ControlledPathKind::File ? p.sha256 : p.manifest.at(fs::path(path).lexically_relative(p.path).string());
            expected[name] = {d::identity(fd.get()).mount, sha};
        }
    }
    return expected;
}
bool matchesPublished(const Json& report, const PublishedFiles& expected) {
    if (expected.empty()) return false;
    for (const auto& [name, id] : expected) if (!report.at("files").contains(name) || report.at("files").at(name).at("mount") != id.first || report.at("files").at(name).at("sha256") != id.second) return false;
    return true;
}
int serviceMain(bool alternate = false) {
    const auto mode = read(runRoot + "/mode");
    if (mode == "exit") return 23;
    d::Fd connection(::socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0));
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    const auto path = runRoot + "/control"; std::copy(path.begin(), path.end(), address.sun_path);
    const bool controlled = ::connect(connection.get(), reinterpret_cast<sockaddr*>(&address), sizeof address) == 0;
    if (controlled) { sendPacket(connection.get(), "BEFORE_READ"); require(receive(connection.get()) == "READ", "read barrier command"); }
    const auto report = readConfiguration(mode, alternate); const auto seen = report.at("digest").get<std::string>();
    write(runRoot + "/seen", seen); write(runRoot + "/report", report.dump());
    if (controlled) { sendPacket(connection.get(), "READ_DONE:" + report.dump()); require(receive(connection.get()) == "NOTIFY", "notify barrier command"); }
    if (mode != "silent") require(sd_notify(0, "READY=1") > 0, "sd_notify");
    while (true) ::pause();
}
struct Gate {
    d::Fd server, connection;
    std::string seen;
    Json report;
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
    void readNow() { sendPacket(connection.get(), "READ"); auto message = receive(connection.get()); require(message.rfind("READ_DONE:", 0) == 0, "read completion"); report = Json::parse(message.substr(10)); seen = report.at("digest").get<std::string>(); }
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
        const auto r = request(paths); Gate gate; PublishedFiles expected;
        d::TestHooks hooks;
        hooks.checkpoint = [&](d::TestPhase phase, const std::string&) {
            if (phase == d::TestPhase::Watching) expected = publishedIds(r);
            if (phase == d::TestPhase::RestartQueued) { gate.beforeRead(); gate.readNow(); require(matchesPublished(gate.report, expected), "fixture read original mount instead of published snapshot"); gate.notify(); }
        };
        const auto result = activate(r, hooks);
        require(result.success() && result.readinessConfirmed && gate.seen == before, "real notify activation/read failed");
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

void originalReadNegativeCase() {
    const auto before = configurationDigest();
    std::vector<d::Fd> originals; std::string mode = "original:";
    for (const auto& name : configNames) {
        originals.emplace_back(::open((root + "/" + name).c_str(), O_RDONLY|O_CLOEXEC)); require(bool(originals.back()), "pin original fixture file");
        if (originals.size() > 1) mode += ',';
        mode += "/proc/" + std::to_string(::getpid()) + "/fd/" + std::to_string(originals.back().get());
    }
    write(runRoot + "/mode", mode);
    {
        Gate gate; PublishedFiles expected;
        d::TestHooks hooks; const auto r = request({one(), directory()});
        hooks.checkpoint = [&](d::TestPhase phase, const std::string&) {
            if (phase == d::TestPhase::Watching) expected = publishedIds(r);
            if (phase == d::TestPhase::RestartQueued) { gate.beforeRead(); gate.readNow(); gate.notify(); }
        };
        const auto result = activate(r, hooks);
        require(result.success() && gate.seen == before && !matchesPublished(gate.report, expected),
                "negative attestation did not distinguish identical original bytes from snapshot mounts");
        for (const auto& [name, id] : expected) require(gate.report.at("files").at(name).at("mount") != id.first, "original fixture accidentally read published object");
    }
    write(runRoot + "/mode", "normal"); active(); clean(before);
    pass("negative FD attestation rejects original mounts despite identical SHA and READY");
}
void launchCases() {
    const auto before = configurationDigest(); const auto file = "/etc/systemd/system/" + unit;
    const auto saved = read(file); const auto alternate = root + "/alternate-source";
    fs::create_directories(alternate + "/dropins/sub");
    for (const auto& name : configNames) write(alternate + "/" + name, "alternate\n");
    auto restore = [&] {
        fs::remove_all(file + ".d"); write(file, saved); mustCtl({"daemon-reload"}); active(); clean(before);
    };
    const auto loaded = d::readLaunchContract(unit, std::chrono::steady_clock::now() + std::chrono::seconds(10));
    d::validateLaunchContract(loaded);
    for (const auto& key : {"ExecStartEx", "ExecStartPreEx", "ExecConditionEx", "ExecStartPostEx", "Environment",
                           "EnvironmentFiles", "PassEnvironment", "UnsetEnvironment", "FragmentPath", "DropInPaths", "NeedDaemonReload", "ManagerEnvironment"}) {
        auto missing = loaded; missing.erase("launch." + std::string(key)); bool rejected = false;
        try { d::validateLaunchContract(missing); } catch (const d::Failure& e) { rejected = e.status == ActivationStatus::UnsupportedConfiguration; }
        require(rejected, std::string("missing required property accepted: ") + key);
    }
    pass("required typed launch properties absent => fail closed");
    const auto touch = fs::canonical("/bin/touch").string();
    write(file, saved + "ExecCondition=/bin/true\nExecStartPre=" + touch + " " + runRoot + "/pre\nExecStartPost=" + touch + " " + runRoot + "/post\n");
    mustCtl({"daemon-reload"}); active();
    require(activate(request()).success() && fs::exists(runRoot + "/pre") && fs::exists(runRoot + "/post"), "unchanged command lists/runtime metadata caused false rejection");
    pass("unchanged real ExecCondition/Pre/Post supported; runtime command status excluded"); restore();
    auto changedExec = saved; changedExec.replace(changedExec.find(" --service\n"), 11, " --service-alternate\n");
    for (const auto& kind : {std::string("ExecStart"), std::string("Environment"), std::string("drop-in"), std::string("before-READY")}) {
        const auto mutation = [&] {
            if (kind == "Environment") write(file, saved + "Environment=FIC_VCSA_CONFIG_ROOT=" + alternate + "\n");
            else if (kind == "drop-in") {
                fs::create_directory(file + ".d");
                write(file + ".d/hardening.conf", "[Service]\nExecStart=\nExecStart=" + fs::canonical("/proc/self/exe").string() + " --service-alternate\n");
            } else write(file, changedExec);
            mustCtl({"daemon-reload"});
        };
        ActivationResult result;
        if (kind == "before-READY") {
            Gate gate; d::TestHooks hooks;
            hooks.checkpoint = [&](d::TestPhase phase, const std::string&) {
                if (phase != d::TestPhase::RestartQueued) return;
                gate.beforeRead(); mutation(); gate.readNow(); gate.notify();
            };
            result = activate(request(), hooks);
        } else {
            d::TestHooks hooks;
            hooks.checkpoint = [&](d::TestPhase phase, const std::string&) { if (phase == d::TestPhase::Watching) mutation(); };
            result = activate(request(), hooks);
        }
        require(result.primaryStatus == ActivationStatus::InterferenceDetected && !result.success() && result.cleanupErrors.empty(), "changed launch contract returned success or leaked mounts");
        require(result.diagnostic.find("launch.") != std::string::npos, "launch regression was masked by another failure");
        // Actually launch the modified unit outside activate(). This is an isolated
        // fixture, proving systemd loaded and can execute the changed contract.
        mustCtl({"restart", unit}); require(read(runRoot + "/seen") != before, "changed unit was never really executed");
        pass(kind + " mutation with daemon-reload rejected; changed unit actually executes alternate config"); restore();
    }
    // NeedDaemonReload is a live disk-vs-loaded check, not a contract generation.
    write(file, saved + "Environment=UNCHANGED_FOR_SERVICE=yes\n");
    struct stat st{}; require(::stat(file.c_str(), &st) == 0, "unit stat");
    timespec times[2] = {st.st_atim, st.st_mtim}; times[1].tv_sec += 2;
    require(::utimensat(AT_FDCWD, file.c_str(), times, 0) == 0, "force distinct unit timestamp without sleep");
    const auto pending = ctl({"show", "--value", "--property=NeedDaemonReload", unit});
    require(pending.success() && pending.standardOutput == "yes\n", "fixture did not establish NeedDaemonReload=yes");
    require(activate(request()).status == ActivationStatus::UnsupportedConfiguration, "pending daemon reload accepted");
    clean(before); pass("NeedDaemonReload=yes rejected before mount"); restore();
    write(runRoot + "/environment", "FIC_VCSA_CONFIG_ROOT=" + root + "\n");
    write(file, saved + "EnvironmentFile=" + runRoot + "/environment\n"); mustCtl({"daemon-reload"}); active();
    require(activate(request()).status == ActivationStatus::UnsupportedConfiguration, "EnvironmentFile claimed supported");
    write(runRoot + "/environment", "FIC_VCSA_CONFIG_ROOT=" + alternate + "\n");
    require(ctl({"show", "--value", "--property=NeedDaemonReload", unit}).standardOutput == "no\n", "environment contents unexpectedly changed reload state");
    require(activate(request()).status == ActivationStatus::UnsupportedConfiguration, "changed environment file accepted");
    mustCtl({"restart", unit}); require(read(runRoot + "/seen") != before, "systemd did not consume changed EnvironmentFile");
    pass("EnvironmentFile/content rejected; unchanged loaded path/reload flag does not pin bytes"); restore();
    // Manager-provided values are outside the unit's Environment property.
    write(file, saved + "PassEnvironment=FIC_VCSA_CONFIG_ROOT\n"); mustCtl({"set-environment", "FIC_VCSA_CONFIG_ROOT=" + root}); mustCtl({"daemon-reload"}); active();
    d::TestHooks manager;
    manager.checkpoint = [&](d::TestPhase phase, const std::string&) {
        if (phase == d::TestPhase::Watching) mustCtl({"set-environment", "FIC_VCSA_CONFIG_ROOT=" + alternate});
    };
    const auto result = activate(request(), manager);
    require(result.primaryStatus == ActivationStatus::InterferenceDetected, "manager environment change accepted");
    mustCtl({"restart", unit}); require(read(runRoot + "/seen") != before, "manager environment not actually consumed");
    mustCtl({"unset-environment", "FIC_VCSA_CONFIG_ROOT"}); pass("manager Environment change detected with stable PassEnvironment"); restore();
}

struct PeerNamespace {
    d::Fd connection;
    pid_t pid = -1;
    PeerNamespace() {
        int pair[2]; require(::socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) == 0, "peer socket");
        pid = ::fork(); require(pid >= 0, "peer fork");
        if (!pid) {
            ::close(pair[0]);
            try {
                require(::unshare(CLONE_NEWNS) == 0, "peer namespace clone"); sendPacket(pair[1], "READY");
                while (receive(pair[1]) == "INSPECT") {
                    Json state; state["table"] = digest(read("/proc/self/mountinfo")); state["fic_mounts"] = leftovers().size();
                    sendPacket(pair[1], state.dump());
                }
                ::close(pair[1]); ::_exit(0);
            } catch (const std::exception& e) { sendPacket(pair[1], std::string("ERROR ") + e.what()); ::_exit(1); }
        }
        ::close(pair[1]); connection = d::Fd(pair[0]); require(receive(connection.get()) == "READY", "peer ready barrier");
    }
    Json inspect() { sendPacket(connection.get(), "INSPECT"); return Json::parse(receive(connection.get())); }
    void stop() {
        if (pid < 0) return;
        sendPacket(connection.get(), "EXIT"); int status = 0;
        require(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "peer exit"); pid = -1;
    }
    ~PeerNamespace() { if (pid > 0) { ::kill(pid, SIGKILL); ::waitpid(pid, nullptr, 0); } }
};
void topologyCases() {
    const auto saved = read("/etc/systemd/system/" + unit); const auto before = configurationDigest();
    const auto privateBase = root + "/private-area", master = root + "/master-area", slave = root + "/slave-area", sharedSlave = root + "/shared-slave-area";
    fs::create_directory(privateBase); fs::create_directory(master); fs::create_directory(slave); fs::create_directory(sharedSlave);
    // Only new, test-owned mounts are configured. /, /etc and /run propagation
    // are never changed, even inside this container. Boundaries precede peers.
    require(::mount(root.c_str(), root.c_str(), nullptr, MS_BIND, nullptr) == 0, "test parent boundary");
    require(::mount(privateBase.c_str(), privateBase.c_str(), nullptr, MS_BIND, nullptr) == 0 &&
            ::mount(nullptr, privateBase.c_str(), nullptr, MS_PRIVATE, nullptr) == 0, "test private boundary");
    require(::mount("test-topology-master", master.c_str(), "tmpfs", 0, "size=1048576,mode=0755") == 0, "test master tmpfs");
    for (const auto& base : {privateBase, master}) {
        fs::create_directories(base + "/dropins/sub");
        for (const auto& name : configNames) write(base + "/" + name, read(root + "/" + name));
    }
    require(::mount(nullptr, master.c_str(), nullptr, MS_SHARED, nullptr) == 0, "test shared master");
    for (const auto& base : {slave, sharedSlave}) {
        require(::mount(master.c_str(), base.c_str(), nullptr, MS_BIND, nullptr) == 0 &&
                ::mount(nullptr, base.c_str(), nullptr, MS_SLAVE, nullptr) == 0, "test slave boundary");
    }
    require(::mount(nullptr, sharedSlave.c_str(), nullptr, MS_SHARED, nullptr) == 0, "test shared-slave boundary");
    require(::mount(nullptr, root.c_str(), nullptr, MS_SHARED, nullptr) == 0, "test shared ancestor");
    fs::create_directories("/run/fic");
    require(::mount("/run/fic", "/run/fic", nullptr, MS_BIND, nullptr) == 0 &&
            ::mount(nullptr, "/run/fic", nullptr, MS_SHARED, nullptr) == 0, "test shared workspace ancestor");
    PeerNamespace peer; const auto baseline = peer.inspect();
    auto unchangedPeer = [&] { const auto state = peer.inspect(); require(state == baseline && state.at("fic_mounts") == 0, "temporary mounts escaped into peer namespace"); };
    auto pathsAt = [&](const std::string& base) {
        auto a = one(); auto b = directory(); a.path = base + "/one.conf"; b.path = base + "/dropins";
        return std::vector<ControlledPath>{a, b};
    };
    auto deniedWithoutMount = [&](const ActivationRequest& r) {
        unsigned attempts = 0; d::TestHooks hooks;
        hooks.fault = [&](const std::string& action, std::size_t) { if (action == "tmpfs" || action == "bind") ++attempts; return 0; };
        const auto table = read("/proc/self/mountinfo"); const auto result = activate(r, hooks);
        require(result.status == ActivationStatus::UnsupportedConfiguration && attempts == 0 &&
                read("/proc/self/mountinfo") == table, "unsafe topology changed namespace before refusal"); unchangedPeer();
    };
    deniedWithoutMount(request(pathsAt(privateBase))); pass("shared workspace parent refused before first mount; peer unchanged");
    // Preparing the boundary is test administration, not activator behavior.
    require(::mount(nullptr, "/run/fic", nullptr, MS_PRIVATE, nullptr) == 0, "test prepare private workspace boundary");
    deniedWithoutMount(request()); pass("shared target parent refused before first mount; peer unchanged");
    deniedWithoutMount(request(pathsAt(sharedSlave))); pass("shared-slave target parent refused before first mount; peer unchanged");
    for (const auto& base : {privateBase, slave}) {
        const auto both = pathsAt(base);
        for (const auto& paths : {std::vector<ControlledPath>{both[0]}, std::vector<ControlledPath>{both[1]}, both}) {
            AtomicWriteOptions options; options.rejectSymlink = true; std::string error;
            require(AtomicFileWriter::write(base + "/one.conf", "one\n", options, &error), "AtomicFileWriter before activation: " + error);
            write("/etc/systemd/system/" + unit, saved + "Environment=FIC_VCSA_CONFIG_ROOT=" + base + "\n"); mustCtl({"daemon-reload"}); active();
            Gate gate; const auto r = request(paths); PublishedFiles expected;
            d::TestHooks hooks;
            hooks.checkpoint = [&](d::TestPhase phase, const std::string&) {
                if (phase == d::TestPhase::SnapshotReadOnly || phase == d::TestPhase::Watching) unchangedPeer();
                if (phase == d::TestPhase::Watching) {
                    expected = publishedIds(r, base);
                    auto sibling = options; sibling.createIfMissing = true;
                    require(AtomicFileWriter::write(base + "/admin.conf", "admin\n", sibling, &error), "uncontrolled sibling atomic rename blocked: " + error);
                }
                if (phase == d::TestPhase::RestartQueued) { gate.beforeRead(); gate.readNow(); require(matchesPublished(gate.report, expected), "topology fixture read wrong mount"); unchangedPeer(); gate.notify(); }
            };
            const auto result = activate(r, hooks);
            require(result.success() && gate.seen == before, "safe boundary activation failed"); unchangedPeer();
            require(AtomicFileWriter::write(base + "/one.conf", "one\n", options, &error), "AtomicFileWriter after cleanup: " + error);
            pass(std::string(base == privateBase ? "private" : "non-shared slave") + " boundary under shared ancestor: published FD IDs, no peer mounts, atomic rename works");
        }
    }
    write("/etc/systemd/system/" + unit, saved); mustCtl({"daemon-reload"}); active();
    unchangedPeer(); peer.stop();
    for (const auto& path : {sharedSlave, slave, master, privateBase, root, std::string("/run/fic")})
        require(::umount2(path.c_str(), 0) == 0, "test topology cleanup " + path);
    clean(before);
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
        if (argc == 2 && (std::string(argv[1]) == "--service" || std::string(argv[1]) == "--service-alternate")) { require(container, "test service only in container"); return serviceMain(std::string(argv[1]) == "--service-alternate"); }
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
        mustCtl({"daemon-reload"}); active(); basicCases(); originalReadNegativeCase(); launchCases(); namespaceRaces(); crossNamespaceCases(); topologyCases(); cleanupCases();
        mustCtl({"stop", unit});
        std::cout << "NATIVE verified-config: " << checks << " PASS, " << skips << " SKIP\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL native: " << e.what() << std::endl;
        return 1;
    }
}
