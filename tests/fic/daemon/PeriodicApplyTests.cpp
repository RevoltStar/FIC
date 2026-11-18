#include "daemon/PeriodicApplySchedule.h"
#include "modules/global/system_settings/PeriodicApplySettings.h"
#include "modules/global/system_settings/policies/GLOBAL_periodic_apply_settings.h"
#include "policy/registry/PolicyRegistryInitialization.h"
#include "policy/registry/PolicyRegistryJson.h"
#include "policy/registry/PolicyRegistryMutation.h"
#include <fic/core/config/ConfigSchemaManager.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/fs/AtomicFileWriter.h>
#include <algorithm>
#include <vector>
#include <cstddef>
#include <cerrno>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using namespace fic::daemon;
using namespace std::chrono;
namespace fs = std::filesystem;
void require(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}
void write(const fs::path& file, const std::string& content) {
    std::ofstream out(file); out << content; out.close();
    require(!out.fail(), "fixture write failed");
    require(::chmod(file.c_str(), 0640) == 0, "fixture chmod failed");
}
std::string read(const fs::path& file) {
    std::ifstream in(file); return {std::istreambuf_iterator<char>(in), {}};
}
void scheduleTests() {
    const PeriodicApplySchedule::Time zero{};
    PeriodicApplySchedule defaults(zero, seconds(1800), seconds(30));
    require(!defaults.due(zero + seconds(1799)) && defaults.due(zero + seconds(1800)),
            "default first deadline incorrect");
    for (const int duration : {10, 30, 50, 90, 180}) {
        PeriodicApplySchedule schedule(zero, seconds(60), seconds(30));
        require(!schedule.due(zero + seconds(59)), "startup apply incorrectly counted");
        const auto start = zero + seconds(60);
        require(schedule.due(start), "first interval lost");
        schedule.attempted(start);
        schedule.finished(start + seconds(duration));
        const auto next = start + seconds(std::max(60, duration + 30));
        require(!schedule.due(next - milliseconds(1)), "pass admitted too soon");
        require(schedule.due(next), "max(start+interval,finish+pause) incorrect");
        schedule.attempted(next); // Never replay missed periods.
        require(!schedule.due(next), "missed passes accumulated");
    }
    // A 45s admitted preflight must not consume the 60s apply interval.
    PeriodicApplySchedule admitted(zero, seconds(60), seconds(30));
    const auto attempt = zero + seconds(60);
    const auto actualStart = attempt + seconds(45);
    require(admitted.due(attempt), "preflight attempt not due");
    admitted.attempted(actualStart);
    admitted.finished(actualStart + seconds(1));
    require(!admitted.due(actualStart + seconds(31)) &&
            !admitted.due(actualStart + seconds(60) - milliseconds(1)) &&
            admitted.due(actualStart + seconds(60)), "preflight shortened actual apply interval");
    // A refused, slow preflight retains attempt+I and the previous completion.
    for (const int preflightDuration : {45, 90}) {
        PeriodicApplySchedule denied(zero, seconds(60), seconds(30));
        denied.finished(zero + seconds(20));
        require(denied.due(attempt), "refused attempt not due");
        const auto preflightEnd = attempt + seconds(preflightDuration);
        denied.attempted(attempt); // no actual apply, no finished(preflightEnd)
        require(!denied.due(attempt + seconds(60) - milliseconds(1)) &&
                denied.due(std::max(attempt + seconds(60), preflightEnd)),
                "refused preflight changed finish or moved deadline from preflight end");
    }
    PeriodicApplySchedule noPause(zero, seconds(60), seconds(0));
    noPause.attempted(zero + seconds(60));
    noPause.finished(zero + seconds(240));
    require(noPause.due(zero + seconds(240)), "P=0 changed overrun behavior");
    PeriodicApplySchedule failed(zero, seconds(60), seconds(30));
    failed.attempted(zero + seconds(60));
    failed.finished(zero + seconds(150)); // same completion path for failed apply
    require(!failed.due(zero + seconds(179)) && failed.due(zero + seconds(180)),
            "unsuccessful pass lost its pause");
    // Refused preflight moves only the primary deadline; no finish timestamp.
    PeriodicApplySchedule refused(zero, seconds(60), seconds(600));
    refused.attempted(zero + seconds(60));
    require(refused.due(zero + seconds(120)), "preflight invented a completion");
    refused.finished(zero + seconds(150));
    refused.attempted(zero + seconds(750));
    require(refused.due(zero + seconds(810)), "refusal replaced previous finish");
}
// Restrict only this child: kernel-enforced denial of write opens, without
// changing canonical config metadata or requiring root/mount privileges.
void denyWriteOpens() {
    constexpr unsigned mask = O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND;
    const sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, mask, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
#ifdef SYS_open
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, mask, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
                       const_cast<sock_filter*>(filter)};
    require(::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
            ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0,
            "could not install test-only write denial");
}
void readOnlyStartupTests(const fs::path& root) {
    const auto defaults = root / "startup-defaults";
    const auto working = root / "startup-config";
    fs::create_directories(defaults); fs::create_directories(working);
    require(::chmod(working.c_str(), 02750) == 0, "fixture directory chmod failed");
    const char* names[] = {"AUDIT", "DAC", "DC", "GLOBAL", "IDENTITY_ACCESS",
                           "FIREWALL", "NET", "OSS", "SYSCTL"};
    const std::string old = "_schema_version=1\n# preserved old config\n";
    for (const auto* name : names) {
        write(defaults / (std::string(name) + ".conf"), old);
        write(working / (std::string(name) + ".conf"), old);
    }
    const auto identity = fic::core::ConfigAuthorityIdentity{::geteuid(), ::getegid()};
    const auto global = working / "GLOBAL.conf";
    const pid_t child = ::fork();
    require(child >= 0, "fork failed");
    if (child == 0) {
        try {
            denyWriteOpens();
            const int fd = ::open(global.c_str(), O_WRONLY);
            if (fd >= 0) ::close(fd);
            require(fd == -1 && errno == EACCES, "write denial not effective");
            std::string error;
            auto startup = [&] {
                ModuleConfigFileHandler config(working, "GLOBAL");
                PeriodicApplySettings settings;
                return fic::core::ConfigSchemaManager::verifyConfigs(working, error, identity) &&
                    readPeriodicApplySettings(config, std::nullopt, settings, error) &&
                    settings.intervalSeconds == 1800 && settings.minPauseSeconds == 30;
            };
            require(startup(), "old read-only config prevented startup load: " + error);
            require(!fic::core::ConfigSchemaManager::ensureConfigs(defaults, working, error, false, identity),
                    "package ensure-config hid denied write");
            require(startup() && read(global) == old, "failed package write changed startup load");
            ::_exit(0);
        } catch (const std::exception& ex) {
            std::cerr << ex.what() << '\n'; ::_exit(1);
        }
    }
    int status = 0;
    require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "read-only startup child failed");
    for (const auto* name : names)
        require(read(working / (std::string(name) + ".conf")) == old, "startup modified config");
    std::string error;
    require(fic::core::ConfigSchemaManager::ensureConfigs(defaults, working, error, false, identity),
            "package ensure-config did not upgrade old config: " + error);
    const auto upgraded = read(global);
    require(upgraded.find("periodic_apply_min_pause.status=ENABLE\n") != std::string::npos &&
            upgraded.find("check_interval.value=1800\n") != std::string::npos, "package defaults missing");
    require(fic::core::ConfigSchemaManager::ensureConfigs(defaults, working, error, false, identity) &&
            read(global) == upgraded, "package ensure-config not idempotent");
    const std::string disabled = "_schema_version=1\ncheck_interval.status=DISABLE\ncheck_interval.value=777\n"
        "periodic_apply_min_pause.status=DISABLE\nperiodic_apply_min_pause.value=45\n";
    write(global, disabled);
    require(fic::core::ConfigSchemaManager::ensureConfigs(defaults, working, error, false, identity) &&
            read(global) == disabled, "package ensure-config overwrote saved values or DISABLE");
    write(global, "_schema_version=0\n");
    require(!fic::core::ConfigSchemaManager::verifyConfigs(working, error, identity),
            "startup accepted corrupt config schema");
    write(global, old);
    require(::chmod(global.c_str(), 0666) == 0, "fixture chmod failed");
    require(!fic::core::ConfigSchemaManager::verifyConfigs(working, error, identity),
            "startup accepted untrusted metadata");
}
void configTests(const fs::path& root) {
    const auto file = root / "config/GLOBAL.conf";
    ModuleConfigFileHandler config(root / "config", "GLOBAL");
    std::string error;
    PeriodicApplySettings settings;
    auto load = [&](std::optional<int> cli = std::nullopt) {
        return readPeriodicApplySettings(config, cli, settings, error);
    };
    write(file, "_schema_version=1\nlang.value=en\n");
    require(load() && settings.intervalSeconds == 1800 && settings.minPauseSeconds == 30,
            "missing keys did not use startup defaults");
    const auto identity = fic::core::ConfigAuthorityIdentity{::geteuid(), ::getegid()};
    auto upgrade = [&] {
        return fic::core::ConfigSchemaManager::ensurePeriodicApplyDefaults(root / "config", error, identity);
    };
    require(upgrade(), "old config additive upgrade failed: " + error);
    const std::string upgraded = read(file);
    require(upgraded.find("lang.value=en\n") != std::string::npos, "upgrade changed user field");
    require(upgrade() && read(file) == upgraded, "upgrade is not idempotent");
    PolicyList policies;
    policies.push_back(std::make_unique<GLOBAL_check_interval>());
    policies.push_back(std::make_unique<GLOBAL_periodic_apply_min_pause>());
    PolicyRegistry registry;
    require(buildPolicyRegistry(std::move(policies), registry, error), "registration failed");
    auto& interval = *registry.at("GLOBAL").submodules.at("system_settings").at("check_interval");
    auto& pause = *registry.at("GLOBAL").submodules.at("system_settings").at("periodic_apply_min_pause");
    for (auto* policy : {&interval, &pause}) {
        const bool isInterval = policy == &interval;
        const auto json = policyToJson("GLOBAL", "system_settings", policy->policyRef().policyName, *policy);
        require(json.at("enabled") == true && json.at("set") == true && json.at("value_valid") == true,
                "upgraded metadata shows disabled/unset");
        require(json.at("editor") == "spinbox" && json.at("min") == (isInterval ? 60 : 0) &&
                json.at("max") == (isInterval ? 86400 : 600) &&
                json.at("default_value") == (isInterval ? "1800" : "30"), "incorrect numeric metadata");
        require(policy->dependencies().empty(), "unnecessary dependencies added");
        require(policy->apply(), "default config apply failed");
        for (const auto* bad : {"-1", "1.5", "60.5", "30seconds", "abc", "", " 60", "60 ", "999999999999999999999"})
            require(!policy->validate(bad), "invalid input accepted: " + std::string(bad));
    }
    for (const auto* good : {"60", "1800", "86400"}) require(interval.validate(good), "interval bound rejected");
    for (const auto* bad : {"0", "59", "86401"}) require(!interval.validate(bad), "interval bound accepted");
    for (const auto* good : {"0", "30", "600"}) require(pause.validate(good), "pause bound rejected");
    require(!pause.validate("601"), "pause overflow accepted");
    require(load(), "default settings not loadable");
    const auto runningSnapshot = settings;
    PeriodicApplySchedule runningSchedule(PeriodicApplySchedule::Time{},
        seconds(runningSnapshot.intervalSeconds), seconds(runningSnapshot.minPauseSeconds));
    require(setPolicyValue(registry, "GLOBAL", "check_interval", "60", error) &&
            setPolicyValue(registry, "GLOBAL", "periodic_apply_min_pause", "600", error), "policy save failed");
    require(interval.apply() && pause.apply(), "saved values apply failed");
    require(runningSnapshot.intervalSeconds == 1800 && runningSnapshot.minPauseSeconds == 30,
            "settings snapshot changed during running process");
    require(!runningSchedule.due(PeriodicApplySchedule::Time{} + seconds(60)),
            "saved configuration changed the running schedule");
    require(load() && settings.intervalSeconds == 60 && settings.minPauseSeconds == 600,
            "new process settings did not pick up saved values");
    PeriodicApplySchedule restartedSchedule(PeriodicApplySchedule::Time{},
        seconds(settings.intervalSeconds), seconds(settings.minPauseSeconds));
    require(restartedSchedule.due(PeriodicApplySchedule::Time{} + seconds(60)),
            "restarted schedule missed the saved interval");
    require(load(7) && settings.intervalSeconds == 7, "CLI override lost historical positive range");
    require(!setPolicyValue(registry, "GLOBAL", "check_interval", "60.5", error), "fraction saved");
    require(config.loadConfig() && config.disablePolicy("check_interval") &&
            config.disablePolicy("periodic_apply_min_pause") && config.saveConfig(), "disable save failed");
    const auto disabledBytes = read(file);
    require(upgrade() && read(file) == disabledBytes, "upgrade overwrote explicit DISABLE");
    require(load() && settings.intervalSeconds == 1800 && settings.minPauseSeconds == 0,
            "DISABLE does not differ from absent pause");
    require(interval.apply() && pause.apply() && read(file) == disabledBytes,
            "apply changed stored state");
    require(config.loadConfig() && config.enablePolicy("periodic_apply_min_pause") &&
            config.setPolicyValue("periodic_apply_min_pause", "0") && config.saveConfig(), "zero save failed");
    require(load() && settings.minPauseSeconds == 0, "enabled zero pause not respected");
    for (const auto* bad : {"-1", "601", "3.5", "abc"}) {
        write(file, std::string("_schema_version=1\nperiodic_apply_min_pause.status=ENABLE\nperiodic_apply_min_pause.value=") + bad + "\n");
        require(!load() && !pause.apply(), "invalid stored pause accepted");
    }
    write(file, "_schema_version=1\ncheck_interval.status=ENABLE\ncheck_interval.value=59\n");
    require(!load() && !interval.apply(), "invalid stored interval accepted");
    require(load(42) && settings.intervalSeconds == 42, "CLI priority over policy incorrect");
    write(file, "_schema_version=1\nperiodic_apply_min_pause.status=BROKEN\nperiodic_apply_min_pause.value=30\n");
    require(!load() && !pause.apply(), "corrupt status silently disabled");

    write(file, "_schema_version=1\n# comment unchanged\nperiodic_apply_min_pause.status=DISABLE");
    require(upgrade() && load() && settings.minPauseSeconds == 0, "partial old config disabled state lost");
    const auto partial = read(file);
    require(partial.rfind("_schema_version=1\n# comment unchanged\nperiodic_apply_min_pause.status=DISABLE", 0) == 0,
            "upgrade rewrote original bytes");
    struct stat info{}; require(::stat(file.c_str(), &info) == 0 && (info.st_mode & 07777) == 0640,
                               "upgrade changed metadata");
    write(file, "_schema_version=1\n check_interval.status = DISABLE\ncheck_interval.value=777\nperiodic_apply_min_pause.value=45\n");
    require(upgrade() && load() && settings.intervalSeconds == 1800 && settings.minPauseSeconds == 45,
            "upgrade ignored normalized status key or overwrote saved value");
    require(read(file).find("check_interval.status=ENABLE") == std::string::npos,
            "upgrade duplicated an existing status under normalized key");
    fs::rename(file, file.string() + ".saved");
    fs::create_symlink(file.string() + ".saved", file);
    require(!upgrade(), "unsafe symlink config upgraded");
    fs::remove(file); fs::rename(file.string() + ".saved", file);
    require(::chmod(file.c_str(), 0666) == 0, "chmod failed");
    require(!upgrade(), "unsafe metadata upgraded");
    require(::chmod(file.c_str(), 0640) == 0, "chmod failed");
    write(file, "_schema_version=1\n");
    AtomicFileWriter::setDirectoryFsyncHookForTests([](const std::string&) { return false; });
    require(!upgrade(), "upgrade hid durability failure");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    fs::remove(file);
    require(!load() && !upgrade() && !fs::exists(file), "missing GLOBAL.conf silently bootstrapped");
}
void cliTests() {
    auto parse = [](std::initializer_list<const char*> values) {
        std::vector<char*> argv;
        for (auto value : values) argv.push_back(const_cast<char*>(value));
        return periodicIntervalOverride(static_cast<int>(argv.size()), argv.data());
    };
    require(!parse({"fic"}) && !parse({"fic", "--interval"}), "absent override changed");
    for (const auto* invalid : {"0", "-1", "abc", "999999999999999999999"})
        require(parse({"fic", "--interval", invalid}) == 1800, "legacy CLI fallback changed");
    require(parse({"fic", "--interval", "1"}) == 1 &&
            parse({"fic", "--interval", "90000"}) == 90000 &&
            parse({"fic", "--interval", "60tail"}) == 60, "legacy CLI parsing changed");
}
}
int main() {
    const fs::path root = fs::temp_directory_path() / ("fic-periodic-test-" + std::to_string(::getpid()));
    try {
        fs::create_directories(root / "config");
        ::chmod(root.c_str(), 02750); ::chmod((root / "config").c_str(), 02750);
        auto paths = fic::core::FicProductPaths::production();
        paths.configDir = root / "config"; paths.logDir = root;
        std::string error;
        require(fic::core::FicRuntimePaths::initialize(paths, error), error);
        scheduleTests(); cliTests(); readOnlyStartupTests(root); configTests(root);
        fs::remove_all(root);
        std::cout << "PASS periodic settings, migration, policy metadata and model-time scheduling\n";
        return 0;
    } catch (const std::exception& ex) {
        fs::remove_all(root); std::cerr << ex.what() << '\n'; return 1;
    }
}
