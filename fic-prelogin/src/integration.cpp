#include "PreLoginPaths.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/fs/SecureStateFile.h>
#include <fic/core/process/ProcessExecutor.h>
#include <systemd/sd-bus.h>
#include <filesystem>
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;
using namespace fic::prelogin;
void require(bool condition, const std::string& error) { if (!condition) throw std::runtime_error(error); }
void safe(const fs::path& path, bool directory) {
    const auto canonical = fs::canonical(path);
    for (fs::path item = canonical; !item.empty(); item = item.parent_path()) {
        struct stat info{};
        require(::lstat(item.c_str(), &info) == 0 && info.st_uid == 0 && !(info.st_mode & 0022) &&
            (item == canonical && !directory ? S_ISREG(info.st_mode) : S_ISDIR(info.st_mode)), "unsafe prelogin integration path: " + item.string());
        if (item == item.root_path()) break;
    }
}
struct Manager {
    sd_bus* bus = nullptr;
    Manager() { require(sd_bus_open_system(&bus) >= 0, "systemd system bus unavailable; integration not changed"); sd_bus_set_method_call_timeout(bus, 5000000); }
    ~Manager() { sd_bus_unref(bus); }
    std::string load(const char* name) {
        sd_bus_message* reply = nullptr;
        if (sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "LoadUnit", nullptr, &reply, "s", name) < 0) return {};
        const char* path = nullptr;
        const bool ok = sd_bus_message_read(reply, "o", &path) > 0;
        const std::string result = ok ? path : ""; sd_bus_message_unref(reply); return result;
    }
    std::string text(const std::string& path, const char* key,
                     const char* interface = "org.freedesktop.systemd1.Unit") {
        char* result = nullptr;
        require(sd_bus_get_property_string(bus, "org.freedesktop.systemd1", path.c_str(), interface, key, nullptr, &result) >= 0, "cannot inspect effective systemd unit");
        std::string value = result; std::free(result); return value;
    }
    unsigned int pid(const std::string& path, const char* key) {
        unsigned int value = 0;
        require(sd_bus_get_property_trivial(bus, "org.freedesktop.systemd1", path.c_str(),
            "org.freedesktop.systemd1.Service", key, nullptr, 'u', &value) >= 0,
            "cannot prove prelogin process state");
        return value;
    }
    bool has(const std::string& path, const char* key, const std::string& expected) {
        char** values = nullptr;
        require(sd_bus_get_property_strv(bus, "org.freedesktop.systemd1", path.c_str(), "org.freedesktop.systemd1.Unit", key, nullptr, &values) >= 0, "cannot inspect effective systemd dependencies");
        bool found = false;
        if (values) { for (std::size_t i = 0; values[i]; ++i) { found |= expected == values[i]; std::free(values[i]); } std::free(values); }
        return found;
    }
    void reload() { require(sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Reload", nullptr, nullptr, "") >= 0, "systemd reload failed"); }
    bool processesEmpty(const char* name) {
        sd_bus_message* reply = nullptr;
        require(sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager", "GetUnitProcesses", nullptr, &reply, "s", name) >= 0,
            "cannot prove prelogin cgroup process state");
        const int entered = sd_bus_message_enter_container(reply, 'a', "(sus)");
        const bool empty = entered > 0 && sd_bus_message_at_end(reply, 0) > 0;
        sd_bus_message_unref(reply);
        return empty;
    }
};
ProcessResult execute(const fs::path& program, const std::vector<std::string>& args) {
    safe(program, false);
    ProcessOptions options; options.clearEnvironment = true;
    options.environment = {{"PATH", "/usr/sbin:/usr/bin:/sbin:/bin"}, {"LANG", "C.UTF-8"}};
    options.maxOutputBytes = 65536; options.timeout = std::chrono::seconds(15);
    return ProcessExecutor::execute(program.string(), args, options);
}
void proveGraph(Manager& manager) {
    const auto dm = manager.load("display-manager.service");
    const auto gate = manager.load("fic-prelogin.service");
    require(!dm.empty() && !gate.empty(), "selected DM or prelogin unit missing");
    const auto name = manager.text(dm, "Id");
    require(manager.text(gate, "Type", "org.freedesktop.systemd1.Service") == "oneshot" &&
        manager.text(gate, "KillMode", "org.freedesktop.systemd1.Service") == "control-group",
        "prelogin supervision was overridden; integration is unproven");
    int remains = 0;
    require(sd_bus_get_property_trivial(manager.bus, "org.freedesktop.systemd1", gate.c_str(),
        "org.freedesktop.systemd1.Service", "RemainAfterExit", nullptr, 'b', &remains) >= 0 && remains,
        "prelogin RemainAfterExit is not proven");
    require(manager.has(dm, "Requires", "fic-prelogin.service") && manager.has(dm, "After", "fic-prelogin.service") &&
        manager.has(gate, "Before", name) && !manager.has(gate, "After", name) && !manager.has(gate, "After", "fic.service") &&
        !manager.has(gate, "Requires", "fic.service"),
        "effective DM/prelogin ordering is not proven");
    const auto analyze = fs::exists("/usr/bin/systemd-analyze") ? "/usr/bin/systemd-analyze" : "/bin/systemd-analyze";
    const auto proof = execute(analyze, {"verify", "--man=no", paths::UNIT, "display-manager.service"});
    require(proof.success(), "unit graph verification failed: " + proof.standardError);
}
void stopGate(Manager& manager, const std::string& gate) {
    require(fs::canonical(manager.text(gate, "FragmentPath")) == fs::canonical(paths::UNIT) &&
        manager.text(gate, "KillMode", "org.freedesktop.systemd1.Service") == "control-group",
        "refusing to stop unproven prelogin supervision");
    const auto systemctl = fs::exists("/usr/bin/systemctl") ? "/usr/bin/systemctl" : "/bin/systemctl";
    require(execute(systemctl, {"stop", "fic-prelogin.service"}).success(), "prelogin cleanup job failed");
    const auto state = manager.text(gate, "ActiveState");
    require(manager.pid(gate, "MainPID") == 0 && manager.pid(gate, "ControlPID") == 0 &&
        (state == "inactive" || state == "failed") &&
        (manager.text(gate, "ControlGroup", "org.freedesktop.systemd1.Service").empty() ||
         manager.processesEmpty("fic-prelogin.service")),
        "prelogin cleanup is not proven");
}
}
int main(int argc, char** argv) {
    using namespace fic::core;
    if (argc != 2 || ::geteuid() != 0) return 2;
    const std::string action = argv[1];
    if (action != "activate" && action != "deactivate" && action != "verify") return 2;
    ::clearenv(); ::setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
    try {
        const fs::path file = paths::DROPIN;
        const fs::path payload = fs::path(paths::SHARE) / "50-fic-prelogin.conf";
        safe(payload, false);
        SecureStateFileExpectation expected;
        expected.owner = 0; expected.group = 0; expected.parentOwner = 0;
        expected.exactMode = 0644; expected.requireSingleLink = true;
        // Base fic package secures /opt/fic as root:fic with 0640 files.
        // The immutable template may therefore be 0640 or 0644, with either
        // root or fic group; neither group may write it. The installed /etc
        // drop-in still requires exactly root:root 0644 below.
        auto payloadExpected = expected;
        payloadExpected.group.reset(); payloadExpected.exactMode = 0;
        payloadExpected.forbiddenMode = 0022;
        const auto content = readSecureFileBounded(payload, payloadExpected, 4096);
        require(content.status == SecureStateReadStatus::Proven, "package-owned DM drop-in unproven");
        // Offline package removal has no running transaction or renderer.
        // Never use this path as fallback when the live manager is unavailable.
        if (action == "deactivate" && !fs::exists("/run/systemd/system")) {
            if (fs::exists(file.parent_path())) {
                safe(file.parent_path(), true);
                const auto before = readSecureFileBounded(file, expected, 4096);
                require(before.status == SecureStateReadStatus::Missing ||
                    (before.status == SecureStateReadStatus::Proven && before.content == content.content),
                    "refusing to remove foreign/drifted offline DM drop-in");
                std::string error;
                if (before.status == SecureStateReadStatus::Proven) {
                    AtomicRemoveResult removed;
                    require(AtomicFileWriter::removeIfCurrentState(file.string(), before.targetState, &error, &removed) &&
                        removed.durabilityConfirmed, error);
                }
                require(AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(file.string(), &error), error);
            }
            std::cout << "Offline prelogin integration removed; systemd will read units at next boot\n";
            return 0;
        }
        Manager manager;
        if (action == "activate") {
            const auto dm = manager.load("display-manager.service");
            if (dm.empty() || manager.text(dm, "LoadState") != "loaded") {
                require(!fs::exists(file), "stale integration with no selected DM");
                std::cout << "No selected DM; prelogin integration remains inactive\n"; return 0;
            }
            const auto id = manager.text(dm, "Id");
            require((id == "gdm.service" || id == "gdm3.service" || id == "sddm.service" || id == "lightdm.service") &&
                manager.has(dm, "Names", "display-manager.service"), "unsupported/missing selected DM alias");
            safe(manager.text(dm, "FragmentPath"), false);
            require(execute(fs::path(paths::BIN) / "fic", {"--maintenance", "incident-pam-verify"}).success(),
                "controlled DM PAM account paths are not proven; integration not activated");
            const auto directory = file.parent_path();
            safe(directory.parent_path(), true);
            if (!fs::exists(directory)) {
                fs::create_directory(directory); ::chmod(directory.c_str(), 0755);
                std::string error;
                require(AtomicFileWriter::fsyncParentDirectoryForPath(directory.string(), &error), error);
            }
            safe(directory, true);
            const auto before = readSecureFileBounded(file, expected, 4096);
            require(before.status == SecureStateReadStatus::Missing ||
                (before.status == SecureStateReadStatus::Proven && before.content == content.content), "refusing to overwrite foreign/drifted DM drop-in");
            AtomicTargetState installed;
            if (before.status == SecureStateReadStatus::Missing) {
                AtomicWriteOptions options; options.createIfMissing = true; options.exclusiveCreate = true;
                options.rejectSymlink = true; options.fileOwner = 0; options.fileGroup = 0; options.fileMode = 0644;
                AtomicWriteResult written; std::string error;
                require(AtomicFileWriter::writeWithResult(file.string(), content.content, options, &error, &written) && written.durabilityConfirmed, error);
                installed = *written.installedTargetState;
            } else {
                std::string error;
                require(AtomicFileWriter::ensureTargetDurableIfCurrentState(file.string(), before.targetState, &error), error);
                installed = before.targetState;
            }
            try { manager.reload(); proveGraph(manager); }
            catch (...) {
                if (before.status == SecureStateReadStatus::Missing) {
                    std::string error; AtomicRemoveResult removed;
                    require(AtomicFileWriter::removeIfCurrentState(file.string(), installed, &error, &removed) && removed.durabilityConfirmed,
                            "failed activation; drop-in cleanup unproven: " + error);
                    manager.reload();
                }
                throw;
            }
        } else if (action == "deactivate") {
            const auto gate = manager.load("fic-prelogin.service");
            bool stopped = false;
            if (fs::exists(file.parent_path())) {
                safe(file.parent_path(), true);
                const auto before = readSecureFileBounded(file, expected, 4096);
                require(before.status == SecureStateReadStatus::Missing ||
                    (before.status == SecureStateReadStatus::Proven && before.content == content.content), "refusing to remove foreign/drifted DM drop-in");
                // Stop a LIVE renderer before detaching ordering. Otherwise
                // daemon-reload could release an existing DM job while DRM is
                // still owned. An already exited gate is stopped only AFTER
                // removing Requires, so a running stock DM is not interrupted.
                if (!gate.empty() && manager.text(gate, "LoadState") == "loaded" &&
                    (manager.pid(gate, "MainPID") || manager.pid(gate, "ControlPID"))) {
                    stopGate(manager, gate); stopped = true;
                }
                if (before.status == SecureStateReadStatus::Proven) {
                    std::string error; AtomicRemoveResult removed;
                    require(AtomicFileWriter::removeIfCurrentState(file.string(), before.targetState, &error, &removed) && removed.durabilityConfirmed, error);
                }
                std::string error;
                require(AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(file.string(), &error), error);
            }
            manager.reload();
            const auto dm = manager.load("display-manager.service");
            if (!dm.empty() && manager.text(dm, "LoadState") == "loaded") {
                // Our still-installed unit's Before=DM produces an inverse
                // After=gate even after the managed drop-in is removed. An
                // ordering edge does not pull gate into a new transaction.
                for (const auto dependency : {"Requires", "Wants", "BindsTo", "Requisite", "Upholds"})
                    require(!manager.has(dm, dependency, "fic-prelogin.service"),
                        "administrator dependencies still pull prelogin; removal refused");
            }
            if (!stopped && !gate.empty() && manager.text(gate, "LoadState") == "loaded") stopGate(manager, gate);
        } else proveGraph(manager);
        return 0;
    } catch (const std::exception& e) { std::cerr << "FIC prelogin integration refused: " << e.what() << '\n'; return 1; }
}
