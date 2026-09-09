#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
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

DesktopManagedSettings requirements(unsigned seconds = 300) {
    return {
        {{"/org/gnome/desktop/session/idle-delay"},
         "uint32 " + std::to_string(seconds)},
        {{"/org/gnome/desktop/screensaver/lock-enabled"}, "true"},
        {{"/org/gnome/desktop/screensaver/lock-delay"}, "uint32 0"},
    };
}

struct FakeCommands {
    bool resolveDconf = true;
    bool resolveGsettings = true;
    bool updateOk = true;
    int updates = 0;
    std::map<std::string, std::string> values;
    std::map<std::string, bool> writable;
    bool repairOnUpdate = false;
    std::vector<ProcessOptions> options;

    static std::string physical(const std::string& schema,
                                const std::string& key) {
        std::string group = schema;
        for (char& character : group)
            if (character == '.') character = '/';
        return "/" + group + "/" + key;
    }

    GnomeSystemBackendDependencies dependencies() {
        return {
            [this](fic::platform::ExecutableId id, fs::path& path,
                   std::string& error) {
                const bool available = id == fic::platform::ExecutableId::Dconf
                    ? resolveDconf : resolveGsettings;
                if (!available) { error = "not installed"; return false; }
                path = id == fic::platform::ExecutableId::Dconf
                    ? "/fake/dconf" : "/fake/gsettings";
                error.clear();
                return true;
            },
            [this](const fs::path& executable,
                   const std::vector<std::string>& arguments,
                   const ProcessOptions& processOptions) {
                options.push_back(processOptions);
                ProcessResult result;
                result.started = true;
                result.exitCode = 0;
                if (executable.filename() == "dconf") {
                    ++updates;
                    if (!updateOk) {
                        result.exitCode = 1;
                        result.standardError = "compile failed";
                    } else if (repairOnUpdate) {
                        for (const auto& [key, value] : requirements()) {
                            values[key.setting] = value;
                            writable[key.setting] = false;
                        }
                    }
                    return result;
                }
                const std::string path = physical(arguments.at(1), arguments.at(2));
                if (arguments.at(0) == "get")
                    result.standardOutput = values[path] + "\n";
                else
                    result.standardOutput = writable[path] ? "true\n" : "false\n";
                return result;
            }
        };
    }
};

struct Fixture {
    fs::path root;
    GnomeSystemBackendOptions options;
    FakeCommands commands;

    Fixture() {
        static unsigned sequence = 0;
        root = fs::temp_directory_path() /
            ("fic-gnome-system-test-" + std::to_string(::getpid()) + "-" +
             std::to_string(sequence++));
        fs::create_directories(root);
        fs::permissions(root, fs::perms::owner_all);
        options.trustedRoot = root;
        options.profilePath = root / "dconf/profile/user";
        options.databaseRoot = root / "dconf/db";
        options.trustedOwner = ::geteuid();
        options.trustedGroup = ::getegid();
        for (const auto& [key, value] : requirements()) {
            commands.values[key.setting] = value;
            commands.writable[key.setting] = false;
        }
    }
    ~Fixture() { std::error_code ignored; fs::remove_all(root, ignored); }
    fs::path keyfile() const { return options.databaseRoot / "fic.d/99-fic.conf"; }
    fs::path lockfile() const { return options.databaseRoot / "fic.d/locks/99-fic"; }
    GnomeSystemBackend backend() {
        return GnomeSystemBackend(commands.dependencies(), options);
    }
};

void testInitialCreationAndVerification() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.desktop() == DesktopEnvironmentKind::Gnome &&
            backend.backendName() == "gnome", "typed backend identity is wrong");
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(read(fixture.options.profilePath) ==
                "user-db:user\nsystem-db:fic\n",
            "initial profile is wrong");
    const std::string keyfile = read(fixture.keyfile());
    require(keyfile.find("idle-delay=uint32 300") != std::string::npos &&
            keyfile.find("lock-enabled=true") != std::string::npos &&
            keyfile.find("lock-delay=uint32 0") != std::string::npos,
            "initial keyfile lacks required values");
    const std::string locks = read(fixture.lockfile());
    for (const auto& [key, ignored] : requirements())
        require(locks.find(key.setting + "\n") != std::string::npos,
                "initial lock file is incomplete");
    require(fixture.commands.updates == 1, "dconf update was not called once");
    require(backend.verifyManagedSettings(requirements(), error), error);
    const ProcessOptions& verification = fixture.commands.options.back();
    const auto hasEnvironment = [&](const std::string& name,
                                    const std::string& value) {
        return std::find(verification.environment.begin(),
                         verification.environment.end(),
                         std::pair<std::string, std::string>{name, value}) !=
            verification.environment.end();
    };
    require(verification.clearEnvironment &&
            hasEnvironment("DCONF_PROFILE", fixture.options.profilePath.string()) &&
            hasEnvironment("XDG_CONFIG_HOME", "/nonexistent") &&
            hasEnvironment("XDG_RUNTIME_DIR", "/nonexistent"),
            "verification did not select an explicit clean profile context");
}

void testProfileAndMergePreservation() {
    Fixture fixture;
    fixture.commands.values["/org/gnome/desktop/session/idle-delay"] =
        "uint32 600";
    write(fixture.options.profilePath,
          "# admin comment\nuser-db:user\nservice-db:keyfile/cache\n"
          "system-db:local\n\nsystem-db:site\n");
    write(fixture.keyfile(),
          "[org/example]\nold-setting='kept'\n\n"
          "[org/gnome/desktop/session]\nidle-delay=uint32 120\n");
    write(fixture.lockfile(), "/org/example/old-setting\n");
    write(fixture.options.databaseRoot / "site.d/admin", "foreign=true\n");
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(600), error), error);
    const std::string profile = read(fixture.options.profilePath);
    require(profile.find("# admin comment\nuser-db:user\nsystem-db:fic\n"
                         "service-db:keyfile/cache\nsystem-db:local\n\n"
                         "system-db:site\n") != std::string::npos,
            "administrator profile was not preserved around FIC insertion");
    const std::string keyfile = read(fixture.keyfile());
    require(keyfile.find("old-setting='kept'") != std::string::npos &&
            keyfile.find("idle-delay=uint32 600") != std::string::npos,
            "merge lost an old setting or failed to update active value");
    require(read(fixture.lockfile()).find("/org/example/old-setting") !=
                std::string::npos,
            "merge removed an old FIC lock");
    require(read(fixture.options.databaseRoot / "site.d/admin") ==
                "foreign=true\n", "foreign database was modified");
}

void testIdempotenceAndStaleRecovery() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    write(fixture.options.databaseRoot / "fic", "compiled");
    const auto keyTime = fs::last_write_time(fixture.keyfile());
    fixture.commands.updates = 0;
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(fixture.commands.updates == 0 &&
            fs::last_write_time(fixture.keyfile()) == keyTime,
            "idempotent pass rewrote or recompiled correct state");

    fixture.commands.values["/org/gnome/desktop/session/idle-delay"] =
        "uint32 1";
    fixture.commands.repairOnUpdate = true;
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(fixture.commands.updates == 1,
            "stale compiled state did not trigger one recompilation");
}

void testMalformedInputsAndSymlinkAreRejected() {
    {
        Fixture fixture;
        write(fixture.keyfile(), "[broken\nvalue=x\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                fixture.commands.updates == 0,
                "malformed keyfile reached mutation");
    }
    {
        Fixture fixture;
        write(fixture.lockfile(), "not/an/absolute/key\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "malformed lock file was accepted");
    }
    {
        Fixture fixture;
        write(fixture.root / "outside", "untouched\n");
        fs::create_directories(fixture.options.profilePath.parent_path());
        fs::create_symlink(fixture.root / "outside", fixture.options.profilePath);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                read(fixture.root / "outside") == "untouched\n",
                "profile symlink attack was not rejected safely");
    }
    {
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:fic\nsystem-db:fic\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "duplicate FIC profile entry was accepted");
    }
}

void testCommandAndEffectiveFailures() {
    {
        Fixture fixture;
        fixture.commands.updateOk = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                error.find("dconf update") != std::string::npos,
                "dconf update failure was hidden");
    }
    {
        Fixture fixture;
        fixture.commands.resolveDconf = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                error.find("cannot resolve dconf") != std::string::npos,
                "missing dconf was not diagnosed");
    }
    {
        Fixture fixture;
        fixture.commands.resolveGsettings = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                error.find("cannot resolve gsettings") != std::string::npos,
                "missing gsettings was not diagnosed before mutation");
    }
    {
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:fic\n");
        fixture.commands.values["/org/gnome/desktop/session/idle-delay"] =
            "uint32 1";
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("effective value mismatch") != std::string::npos,
                "wrong effective value was verified");
    }
    {
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:fic\n");
        fixture.commands.writable[
            "/org/gnome/desktop/screensaver/lock-enabled"] = true;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("remains writable") != std::string::npos,
                "missing effective lock was verified");
    }
}

void testUnknownKeyFailsBeforeMutation() {
    Fixture fixture;
    DesktopManagedSettings invalid = {{{"/org/example/unknown"}, "true"}};
    auto backend = fixture.backend();
    std::string error;
    require(!backend.ensureManagedSettings(invalid, error) &&
            !fs::exists(fixture.options.profilePath) &&
            fixture.commands.updates == 0,
            "unknown key mutated system state");
}

void testEmptyRequirementsDoNothing() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings({}, error) &&
            fixture.commands.updates == 0 &&
            !fs::exists(fixture.options.profilePath),
            "empty requirements performed cleanup or setup");
}

} // namespace

int main() {
    try {
        testInitialCreationAndVerification();
        testProfileAndMergePreservation();
        testIdempotenceAndStaleRecovery();
        testMalformedInputsAndSymlinkAreRejected();
        testCommandAndEffectiveFailures();
        testUnknownKeyFailsBeforeMutation();
        testEmptyRequirementsDoNothing();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
