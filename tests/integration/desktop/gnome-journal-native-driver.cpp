// Explicit container-only native probe. Never registered as an ordinary CTest:
// it changes /etc/dconf inside a disposable Docker filesystem.
#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"
#include <fic/core/process/ProcessExecutor.h>
#include <filesystem>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
bool GlobalDesktopConfigKey::operator<(const GlobalDesktopConfigKey& other) const {
    return setting < other.setting;
}
static void require(bool condition, const std::string& error) {
    if (!condition) throw std::runtime_error(error);
}
static std::string read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), {}};
}
static void write(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text; output.close();
    require(output.good(), "native fixture write failed");
    require(::chmod(path.c_str(), 0644) == 0, "native fixture chmod failed");
}
int main() {
    const char* enabled = std::getenv("FIC_NATIVE_GNOME_PROBE");
    if (!enabled || std::string(enabled) != "container-only" || ::geteuid() != 0 || !fs::exists("/.dockerenv")) {
        std::cerr << "native GNOME probe requires explicitly enabled disposable Docker root environment\n";
        return 77;
    }
    try {
        require(!fs::exists("/etc/dconf/db/fic") && !fs::exists("/etc/dconf/db/fic.d") &&
                !fs::exists("/etc/dconf/profile/user"), "native fixture refuses existing fic/profile state");
        const fs::path source = "/etc/dconf/db/fic.d/99-fic.conf";
        const fs::path locks = "/etc/dconf/db/fic.d/locks/99-fic";
        const fs::path site = "/etc/dconf/db/fic.d/20-site.conf";
        const std::string originalSource = "# administrator\r\n[org/gnome/desktop/session]\r\n"
            "idle-delay=uint32 600\r\n[org/gnome/desktop/screensaver]\r\nlock-enabled=false\r\n"
            "lock-delay=uint32 10\r\n[org/gnome/desktop/lockdown]\r\ndisable-lock-screen=true\r\n";
        const std::string originalLocks = "# administrator lock\r\n/org/gnome/desktop/session/idle-delay\r\n";
        const std::string originalProfile = "# administrator profile\nuser-db:user\nsystem-db:fic\n";
        write(source, originalSource); write(locks, originalLocks);
        write("/etc/dconf/profile/user", originalProfile);
        write(site, "[org/gnome/desktop/interface]\nclock-show-date=true\n");
        write("/etc/dconf/db/fic.d/locks/10-foreign", "/org/gnome/desktop/screensaver/lock-enabled\n");
        fs::create_directories("/run/fic");
        for (const auto* directory : {"/etc/dconf", "/etc/dconf/db", "/etc/dconf/db/fic.d",
                                     "/etc/dconf/db/fic.d/locks", "/etc/dconf/profile", "/run/fic"})
            require(::chmod(directory, 0755) == 0, "native fixture directory chmod failed");
        ProcessOptions process; process.clearEnvironment = true;
        process.environment = {{"LC_ALL", "C"}, {"LANG", "C"}}; process.childUmask = 0022;
        const auto compiled = ProcessExecutor::execute("/usr/bin/dconf",
            {"compile", "/etc/dconf/db/fic", "/etc/dconf/db/fic.d"}, process);
        require(compiled.success(), "native initial dconf compilation: " + compiled.standardError);
        require(::chmod("/etc/dconf/db/fic", 0644) == 0, "native compiled mode failed");
        write("/etc/dconf/db/site.d/10-site.conf", "[site]\nvalue='old'\n");
        const auto siteCompiled = ProcessExecutor::execute("/usr/bin/dconf",
            {"compile", "/etc/dconf/db/site", "/etc/dconf/db/site.d"}, process);
        require(siteCompiled.success(), "native foreign database fixture failed");
        const auto foreignCache = read("/etc/dconf/db/site");
        write("/etc/dconf/db/site.d/10-site.conf", "[site]\nvalue='new'\n");
        fs::last_write_time("/etc/dconf/db/site.d",
            fs::last_write_time("/etc/dconf/db/site") + std::chrono::seconds(2));
        GnomeSystemBackendOptions backendOptions;
        backendOptions.lockPath = "/run/fic/desktop-config.lock";
        GnomeSystemBackend backend({
            [](fic::platform::ExecutableId id, fs::path& executable, std::string& error) {
                executable = id == fic::platform::ExecutableId::Dconf ? "/usr/bin/dconf" : "/usr/bin/gsettings";
                error.clear(); return fs::exists(executable);
            },
            [](const fs::path& executable, const std::vector<std::string>& arguments, const ProcessOptions& options) {
                return ProcessExecutor::execute(executable.string(), arguments, options);
            }}, backendOptions);
        fic::rollback::MutationJournal journal("/tmp/fic-native-gnome-journal.json");
        std::string error; require(journal.initializeOrLoad(error), error);
        const std::set<PolicyRef> owners{{"OSS", "DesktopEnvironment", "screenlock_timeout"},
            {"OSS", "DesktopEnvironment", "disable_kde_lock_screen_media_controls"}};
        DesktopGlobalConfigRequirements wanted{
            {{"/org/gnome/desktop/session/idle-delay"}, {"uint32 300", owners}},
            {{"/org/gnome/desktop/screensaver/lock-enabled"}, {"true", owners}},
            {{"/org/gnome/desktop/screensaver/lock-delay"}, {"uint32 0", owners}},
            {{"/org/gnome/desktop/lockdown/disable-lock-screen"}, {"false", owners}}};
        require(backend.preflightJournaled(wanted, journal, error), error);
        require(backend.reconcileJournaled(wanted, journal, error), error);
        require(journal.records().size() == 4, "native apply did not record four key/lock pairs");
        require(backend.reconcileJournaled(wanted, journal, error), error);
        const auto retainedSource = read(source);
        const auto retainedLocks = read(locks);
        require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "screenlock_timeout"}, journal, error), error);
        require(read(source) == retainedSource && read(locks) == retainedLocks,
                "native primary-owner release removed a still-required scalar");
        const std::string changedSite = "[org/gnome/desktop/interface]\nclock-show-date=false\n";
        write(site, changedSite);
        fic::rollback::MutationJournal restarted("/tmp/fic-native-gnome-journal.json");
        require(restarted.initializeOrLoad(error), error);
        require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "disable_kde_lock_screen_media_controls"},
                restarted, error), error);
        require(read(source) == originalSource && read(locks) == originalLocks &&
                read("/etc/dconf/profile/user") == originalProfile && read(site) == changedSite,
                "native release changed foreign text, lock, profile or source state");
        require(read("/etc/dconf/db/site") == foreignCache,
                "native FIC update regenerated an unrelated system database");
        for (const auto& record : restarted.records()) require(!record.isActive(), "native release left an active scalar");
        process.environment.push_back({"DCONF_PROFILE", "/etc/dconf/profile/user"});
        process.environment.push_back({"XDG_CONFIG_HOME", "/nonexistent"});
        process.environment.push_back({"XDG_RUNTIME_DIR", "/nonexistent"});
        const auto value = ProcessExecutor::execute("/usr/bin/gsettings",
            {"get", "org.gnome.desktop.session", "idle-delay"}, process);
        require(value.success() && value.standardOutput == "uint32 600\n", "native original scalar was not effective");
        const auto writable = ProcessExecutor::execute("/usr/bin/gsettings",
            {"writable", "org.gnome.desktop.screensaver", "lock-enabled"}, process);
        require(writable.success() && writable.standardOutput == "false\n", "native release removed a foreign lock");
        require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "screenlock_timeout"}, restarted, error), error);
        // Discard only this disposable harness's preceding fixture, then
        // exercise genuinely missing GNOME policy containers.
        fs::remove_all("/etc/dconf/db/fic.d"); fs::remove("/etc/dconf/db/fic"); fs::remove("/etc/dconf/profile/user");
        fs::remove("/etc/dconf/db/site"); fs::remove_all("/etc/dconf/db/site.d");
        require(fs::is_empty("/etc/dconf/db") && fs::is_empty("/etc/dconf/profile"),
                "native harness refuses unexpected foreign parent contents");
        fs::remove("/etc/dconf/db"); fs::remove("/etc/dconf/profile");
        require(fs::is_empty("/etc/dconf"), "native harness refuses unexpected dconf root contents");
        fs::remove("/etc/dconf");
        fic::rollback::MutationJournal virgin("/tmp/fic-native-gnome-creation.json");
        require(virgin.initializeOrLoad(error), error);
        require(backend.preflightJournaled(wanted, virgin, error), error);
        require(!fs::exists(source) && !fs::exists("/etc/dconf/profile/user") && virgin.records().empty(),
                "native creation preflight mutated protected state");
        require(backend.reconcileJournaled(wanted, virgin, error), error);
        fic::rollback::MutationJournal creationRestart("/tmp/fic-native-gnome-creation.json");
        require(creationRestart.initializeOrLoad(error), error);
        require(backend.reconcileJournaled({}, creationRestart, error), error);
        require(!fs::exists("/etc/dconf"), "native created containers/parents not released");
        std::cout << "PASS: native GNOME existing/created containers, shared owners, restart and release\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: native GNOME probe: " << error.what() << '\n'; return 1;
    }
}
