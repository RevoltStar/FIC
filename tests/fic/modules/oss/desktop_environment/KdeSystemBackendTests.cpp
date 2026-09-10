#include "modules/oss/desktop_environment/backends/KdeSystemBackend.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

bool GlobalDesktopConfigKey::operator<(
    const GlobalDesktopConfigKey& other) const {
    return setting < other.setting;
}

namespace {

void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

std::string read(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), {}};
}

void write(const fs::path& path, const std::string& value) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << value;
}

DesktopManagedSettings requirements(unsigned minutes = 5) {
    return {
        {{"kscreenlockerrc/Daemon/Autolock"}, "true"},
        {{"kscreenlockerrc/Daemon/Timeout"}, std::to_string(minutes)},
        {{"kscreenlockerrc/Daemon/Lock"}, "true"},
        {{"kscreenlockerrc/Daemon/LockGrace"}, "0"},
        {{"kscreenlockerrc/Daemon/RequirePassword"}, "true"},
    };
}

std::string environmentValue(const ProcessOptions& options,
                             const std::string& name) {
    const auto found = std::find_if(
        options.environment.begin(), options.environment.end(),
        [&name](const auto& item) { return item.first == name; });
    return found == options.environment.end() ? "" : found->second;
}

std::string configValue(const std::string& content, const std::string& key,
                        bool immutableOnly) {
    bool daemon = false;
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        if (line == "[Daemon]") {
            daemon = true;
            continue;
        }
        if (!line.empty() && line.front() == '[') {
            daemon = false;
            continue;
        }
        if (!daemon) continue;
        const std::string prefix = key + (immutableOnly ? "[$i]=" : "=");
        if (line.rfind(prefix, 0) == 0) return line.substr(prefix.size());
    }
    return "";
}

struct FakeCommands {
    bool resolve = true;
    bool executeOk = true;
    bool honorImmutability = true;
    fs::path systemConfig;
    int executions = 0;
    std::vector<ProcessOptions> options;

    KdeSystemBackendDependencies dependencies() {
        return {
            [this](fic::platform::ExecutableId id, fs::path& path,
                   std::string& error) {
                require(id == fic::platform::ExecutableId::Kreadconfig,
                        "backend resolved an unexpected executable");
                if (!resolve) {
                    error = "not installed";
                    return false;
                }
                path = "/fake/kreadconfig6";
                error.clear();
                return true;
            },
            [this](const fs::path&, const std::vector<std::string>& arguments,
                   const ProcessOptions& processOptions) {
                ++executions;
                options.push_back(processOptions);
                ProcessResult result;
                result.started = true;
                result.exitCode = executeOk ? 0 : 1;
                if (!executeOk) {
                    result.standardError = "reader failed";
                    return result;
                }
                const std::string key = arguments.at(5);
                std::string value;
                if (honorImmutability) {
                    value = configValue(read(systemConfig), key, true);
                }
                if (value.empty()) {
                    const fs::path user = environmentValue(
                        processOptions, "XDG_CONFIG_HOME");
                    value = configValue(read(user / "kscreenlockerrc"),
                                        key, false);
                }
                result.standardOutput = value + "\n";
                return result;
            }
        };
    }
};

struct Fixture {
    fs::path root;
    KdeSystemBackendOptions options;
    FakeCommands commands;

    Fixture() {
        static unsigned sequence = 0;
        root = fs::temp_directory_path() /
            ("fic-kde-system-test-" + std::to_string(::getpid()) + "-" +
             std::to_string(sequence++));
        fs::create_directories(root);
        ::chmod(root.c_str(), 0755);
        options.trustedRoot = root;
        options.configPath = root / "xdg/kscreenlockerrc";
        options.temporaryRoot = root;
        options.trustedOwner = ::geteuid();
        options.trustedGroup = ::getegid();
        commands.systemConfig = options.configPath;
    }
    ~Fixture() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }
    KdeSystemBackend backend() {
        return KdeSystemBackend(commands.dependencies(), options);
    }
};

mode_t fileMode(const fs::path& path) {
    struct stat info {};
    require(::stat(path.c_str(), &info) == 0, "stat failed");
    return info.st_mode & 0777;
}

class ScopedUmask {
public:
    explicit ScopedUmask(mode_t value) : previous_(::umask(value)) {}
    ~ScopedUmask() { ::umask(previous_); }
    ScopedUmask(const ScopedUmask&) = delete;
    ScopedUmask& operator=(const ScopedUmask&) = delete;
private:
    mode_t previous_;
};

void requireFiveImmutableKeys(const std::string& content) {
    for (const auto& [physical, value] : requirements()) {
        const std::string key =
            physical.setting.substr(physical.setting.rfind('/') + 1);
        require(content.find(key + "[$i]=" + value + "\n") !=
                    std::string::npos,
                "missing immutable KDE setting: " + key);
    }
}

void testInitialCreationAndEffectiveVerification() {
    ScopedUmask umask(0027);
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.desktop() == DesktopEnvironmentKind::Kde &&
                backend.backendName() == "kde",
            "KDE backend identity is wrong");
    require(backend.ensureManagedSettings(requirements(), error), error);
    requireFiveImmutableKeys(read(fixture.options.configPath));
    require(fileMode(fixture.root / "xdg") == 0755,
            "FIC-created KDE config directory is not 0755");
    require(fileMode(fixture.options.configPath) == 0644,
            "KDE system config is not 0644");
    require(fixture.commands.executions == 5,
            "effective verification did not read all five keys");
    for (const auto& options : fixture.commands.options) {
        require(options.clearEnvironment &&
                    !environmentValue(options, "HOME").empty() &&
                    !environmentValue(options, "XDG_CONFIG_HOME").empty() &&
                    environmentValue(options, "XDG_CONFIG_DIRS") ==
                        (fixture.root / "xdg").string() &&
                    environmentValue(options, "LC_ALL") == "C" &&
                    environmentValue(options, "LANG") == "C",
                "KDE verification environment is not isolated");
    }
}

void testMergePreservationReplacementAndIdempotence() {
    Fixture fixture;
    write(fixture.options.configPath,
          "# admin comment\n\n[Other]\nForeign=kept\n\n[Daemon]\n"
          "AdminOnly=kept\nAutolock=false\nTimeout=999\n");
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    const std::string once = read(fixture.options.configPath);
    require(once.find("# admin comment\n\n") != std::string::npos &&
                once.find("[Other]\nForeign=kept") != std::string::npos &&
                once.find("AdminOnly=kept") != std::string::npos &&
                once.find("Autolock=false") == std::string::npos &&
                once.find("Timeout=999") == std::string::npos,
            "KDE merge lost admin state or retained conflicting active values");
    requireFiveImmutableKeys(once);
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(read(fixture.options.configPath) == once,
            "KDE ensure is not idempotent");

    DesktopManagedSettings subset = {
        {{"kscreenlockerrc/Daemon/Autolock"}, "true"}};
    require(backend.ensureManagedSettings(subset, error), error);
    require(read(fixture.options.configPath).find("Timeout[$i]=5") !=
                std::string::npos,
            "missing requirement deleted stale managed state");
}

void testUnsafeSymlinkAndUnknownSettingFailBeforeMutation() {
    {
        Fixture fixture;
        write(fixture.root / "target", "foreign");
        fs::create_directories(fixture.root / "xdg");
        fs::create_symlink(fixture.root / "target", fixture.options.configPath);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "KDE system config symlink was accepted");
    }
    {
        Fixture fixture;
        const DesktopManagedSettings unknown = {
            {{"kscreenlockerrc/Daemon/Unknown"}, "true"}};
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(unknown, error),
                "unknown KDE physical setting was accepted");
        require(!fs::exists(fixture.root / "xdg"),
                "unknown KDE setting mutated filesystem state");
        require(fixture.commands.executions == 0,
                "unknown KDE setting executed a command");
    }
}

void testForeignAncestorModes() {
    {
        Fixture fixture;
        fs::create_directories(fixture.root / "xdg");
        ::chmod((fixture.root / "xdg").c_str(), 0750);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                    error.find("not traversable") != std::string::npos,
                "0750 foreign KDE ancestor was accepted");
        require(fileMode(fixture.root / "xdg") == 0750,
                "0750 foreign KDE ancestor was chmod'ed");
        require(!fs::exists(fixture.options.configPath),
                "state was written below inaccessible KDE ancestor");
    }
    {
        Fixture fixture;
        fs::create_directories(fixture.root / "xdg");
        ::chmod((fixture.root / "xdg").c_str(), 0751);
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
        require(fileMode(fixture.root / "xdg") == 0751,
                "0751 foreign KDE ancestor was re-permissioned");
    }
}

void testUnreadableAndMissingReaderFailVerification() {
    Fixture fixture;
    {
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
    }
    ::chmod(fixture.options.configPath.c_str(), 0640);
    auto backend = fixture.backend();
    std::string error;
    require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("not readable") != std::string::npos,
            "0640 KDE system config passed verification");

    Fixture missing;
    missing.commands.resolve = false;
    auto missingBackend = missing.backend();
    require(!missingBackend.ensureManagedSettings(requirements(), error) &&
                error.find("cannot resolve kreadconfig") != std::string::npos,
            "missing kreadconfig did not fail relevant backend");
    require(!fs::exists(missing.root / "xdg"),
            "missing kreadconfig caused filesystem mutation");
}

void testConflictingUserAndMissingImmutabilityFail() {
    {
        Fixture fixture;
        fixture.commands.honorImmutability = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                    error.find("overrides system setting") != std::string::npos,
                "conflicting user config did not fail effective verification");
    }
    {
        Fixture fixture;
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
        std::string content = read(fixture.options.configPath);
        const std::string immutable = "Lock[$i]=true";
        const auto position = content.find(immutable);
        require(position != std::string::npos, "Lock immutable entry missing");
        content.replace(position, immutable.size(), "Lock=true");
        write(fixture.options.configPath, content);
        require(!backend.verifyManagedSettings(requirements(), error),
                "managed KDE key without [$i] passed verification");
    }
}

void testEmptyRequirementsDoNothing() {
    Fixture fixture;
    fixture.commands.resolve = false;
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings({}, error), error);
    require(!fs::exists(fixture.root / "xdg"),
            "empty KDE requirements created state");
}

} // namespace

int main() {
    try {
        testInitialCreationAndEffectiveVerification();
        testMergePreservationReplacementAndIdempotence();
        testUnsafeSymlinkAndUnknownSettingFailBeforeMutation();
        testForeignAncestorModes();
        testUnreadableAndMissingReaderFailVerification();
        testConflictingUserAndMissingImmutabilityFail();
        testEmptyRequirementsDoNothing();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
