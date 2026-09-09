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
        {{"/org/gnome/desktop/lockdown/disable-lock-screen"}, "false"},
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
    // Test hook standing in for the real dconf compiler: a successful update
    // materialises the compiled database with a controllable mode.
    fs::path compiledPath;
    mode_t compiledMode = 0644;
    bool createCompiledOnUpdate = true;

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
                    } else {
                        if (createCompiledOnUpdate && !compiledPath.empty()) {
                            std::ofstream(compiledPath, std::ios::binary)
                                << "compiled";
                            ::chmod(compiledPath.c_str(), compiledMode);
                        }
                        if (repairOnUpdate) {
                            for (const auto& [key, value] : requirements()) {
                                values[key.setting] = value;
                                writable[key.setting] = false;
                            }
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
        // Plays the role of the production trusted root (/etc): traversable
        // and readable by ordinary users, but never group/world writable
        // (validateDirectoryFd rejects that). The mode is forced explicitly
        // because fs::create_directories honours the process umask; under the
        // umask=0027 regression scenario an inherited 0750 root would mask the
        // bug this suite must detect.
        fs::permissions(root,
                        fs::perms{fs::perms::owner_all | fs::perms::group_read |
                                  fs::perms::group_exec | fs::perms::others_read |
                                  fs::perms::others_exec},
                        fs::perm_options::replace);
        options.trustedRoot = root;
        options.profilePath = root / "dconf/profile/user";
        options.databaseRoot = root / "dconf/db";
        options.trustedOwner = ::geteuid();
        options.trustedGroup = ::getegid();
        commands.compiledPath = options.databaseRoot / "fic";
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

// Restores the process umask even when a require() throws.
class ScopedUmask {
public:
    explicit ScopedUmask(mode_t value) : previous_(::umask(value)) {}
    ~ScopedUmask() { ::umask(previous_); }
    ScopedUmask(const ScopedUmask&) = delete;
    ScopedUmask& operator=(const ScopedUmask&) = delete;
private:
    mode_t previous_;
};

mode_t fileMode(const fs::path& path) {
    struct stat info {};
    require(::stat(path.c_str(), &info) == 0, "stat failed for mode probe");
    return info.st_mode & 0777;
}

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
            keyfile.find("lock-delay=uint32 0") != std::string::npos &&
            keyfile.find("disable-lock-screen=false") != std::string::npos &&
            keyfile.find("[org/gnome/desktop/lockdown]") != std::string::npos,
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
        write(fixture.commands.compiledPath, "compiled");
        fixture.commands.createCompiledOnUpdate = false;
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
        write(fixture.commands.compiledPath, "compiled");
        fixture.commands.createCompiledOnUpdate = false;
        fixture.commands.writable[
            "/org/gnome/desktop/screensaver/lock-enabled"] = true;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("remains writable") != std::string::npos,
                "missing effective lock was verified");
    }
    {
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:fic\n");
        write(fixture.commands.compiledPath, "compiled");
        fixture.commands.createCompiledOnUpdate = false;
        fixture.commands.values[
            "/org/gnome/desktop/lockdown/disable-lock-screen"] = "true";
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("effective value mismatch") != std::string::npos,
                "disable-lock-screen=true was verified as effective lock state");
    }
    {
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:fic\n");
        write(fixture.commands.compiledPath, "compiled");
        fixture.commands.createCompiledOnUpdate = false;
        fixture.commands.writable[
            "/org/gnome/desktop/lockdown/disable-lock-screen"] = true;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("remains writable") != std::string::npos,
                "writable disable-lock-screen was verified as locked");
    }
    {
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:fic\n");
        write(fixture.commands.compiledPath, "compiled");
        fixture.commands.createCompiledOnUpdate = false;
        auto backend = fixture.backend();
        std::string error;
        require(backend.verifyManagedSettings(requirements(), error), error);
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

void testProfileCompatibility() {
    {
        // file-db распознаётся как read-only источник и сохраняется.
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nfile-db:/etc/example.db\nsystem-db:local\n");
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
        require(read(fixture.options.profilePath) ==
                    "user-db:user\nsystem-db:fic\n"
                    "file-db:/etc/example.db\nsystem-db:local\n",
                "file-db profile was not accepted with FIC priority");
    }
    {
        // Ведущие пробелы — валидный dconf profile syntax.
        Fixture fixture;
        write(fixture.options.profilePath,
              "   user-db:user\n   system-db:local\n");
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
        require(read(fixture.options.profilePath) ==
                    "   user-db:user\nsystem-db:fic\n   system-db:local\n",
                "whitespace profile was rewritten beyond FIC insertion");
    }
    {
        // Inline '#'-комментарии сохраняются в чужих строках.
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user   # writable\nsystem-db:local   # admin defaults\n");
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
        require(read(fixture.options.profilePath) ==
                    "user-db:user   # writable\nsystem-db:fic\n"
                    "system-db:local   # admin defaults\n",
                "inline comments were not preserved");
    }
    {
        // Реальный administrator-подобный профиль: комментарии, пустые строки,
        // whitespace, inline comments и file-db сохраняются byte-for-byte.
        Fixture fixture;
        const std::string admin =
            "# managed by administrator\n"
            "\n"
            " user-db:user    # writable\n"
            "\n"
            " system-db:local   # defaults\n"
            " file-db:/etc/company.db\n";
        write(fixture.options.profilePath, admin);
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
        require(read(fixture.options.profilePath) ==
                    "# managed by administrator\n"
                    "\n"
                    " user-db:user    # writable\n"
                    "system-db:fic\n"
                    "\n"
                    " system-db:local   # defaults\n"
                    " file-db:/etc/company.db\n",
                "administrator profile was normalised instead of preserved");
    }
    {
        // FIC line в неправильной позиции перемещается, чужие строки не
        // переупорядочиваются.
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:local\nsystem-db:fic\n");
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
        require(read(fixture.options.profilePath) ==
                    "user-db:user\nsystem-db:fic\nsystem-db:local\n",
                "misplaced FIC line was not relocated without reordering");
    }
    {
        // Дубликат system-db:fic распознаётся даже с whitespace/comments.
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsystem-db:fic\n system-db:fic # duplicate\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "duplicated FIC entry with formatting was accepted");
    }
    {
        // Первый источник file-db — профиль non-writable.
        Fixture fixture;
        write(fixture.options.profilePath,
              "file-db:/etc/foo\nuser-db:user\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "file-db-first profile was accepted as writable");
    }
    {
        // Первый источник system-db — профиль non-writable.
        Fixture fixture;
        write(fixture.options.profilePath,
              "system-db:local\nuser-db:user\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "system-db-first profile was accepted as writable");
    }
    {
        // Неизвестный тип источника остаётся fail-closed.
        Fixture fixture;
        write(fixture.options.profilePath,
              "user-db:user\nsomething-db:test\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "unknown dconf profile source was accepted");
    }
}

void testUmaskCreatesTraversableFicDirectories() {
    // Production condition: fic.service runs with UMask=0027. FIC-created
    // public dconf directories must still end up user-traversable (0755).
    ScopedUmask guard(0027);
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(::umask(0) == 0027, "test umask was not restored by the guard probe");
    const fs::path dconf = fixture.root / "dconf";
    require(fileMode(dconf) == 0755,
            "FIC-created dconf directory lost ordinary-user bits to umask");
    require(fileMode(dconf / "profile") == 0755,
            "FIC-created profile directory lost ordinary-user bits to umask");
    require(fileMode(fixture.options.databaseRoot) == 0755,
            "FIC-created db directory lost ordinary-user bits to umask");
    require(fileMode(fixture.options.databaseRoot / "fic.d") == 0755,
            "FIC-created fic.d directory lost ordinary-user bits to umask");
    require(fileMode(fixture.options.databaseRoot / "fic.d/locks") == 0755,
            "FIC-created locks directory lost ordinary-user bits to umask");
    require(fileMode(fixture.options.profilePath) == 0644,
            "FIC-written profile file is not 0644 under restrictive umask");
    require(fileMode(fixture.commands.compiledPath) == 0644,
            "compiled database created without ordinary-user read bit");
}

void testForeignParentInaccessibleFailsClosed() {
    // Existing foreign parent 0750: ordinary users cannot traverse to the
    // compiled database. FIC must fail closed and must not chmod the
    // foreign directory.
    Fixture fixture;
    fs::create_directories(fixture.options.databaseRoot);
    fs::permissions(fixture.options.databaseRoot,
                    fs::perms{fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec});
    const fs::path keyfileDir = fixture.options.databaseRoot / "fic.d";
    fs::create_directories(keyfileDir);
    fs::permissions(keyfileDir,
                    fs::perms{fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec | fs::perms::others_read |
                              fs::perms::others_exec});
    auto backend = fixture.backend();
    std::string error;
    require(!backend.ensureManagedSettings(requirements(), error) &&
                error.find("not traversable by ordinary users") !=
                    std::string::npos,
            "inaccessible foreign dconf parent did not fail closed");
    require(fileMode(fixture.options.databaseRoot) == 0750,
            "FIC re-permissioned an existing foreign parent directory");
    require(!fs::exists(fixture.keyfile()),
            "FIC wrote managed state under an inaccessible foreign parent");
}

void testForeignParentTraversableAccepted() {
    // 0751 is acceptable: other-execute is sufficient traversal.
    Fixture fixture;
    fs::create_directories(fixture.options.databaseRoot);
    fs::permissions(fixture.options.databaseRoot,
                    fs::perms{fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec | fs::perms::others_exec});
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(fileMode(fixture.options.databaseRoot) == 0751,
            "FIC re-permissioned an existing traversable foreign parent");
}

void testCompiledDatabaseUnreadableFailsVerification() {
    {
        Fixture fixture;
        write(fixture.options.profilePath, "user-db:user\nsystem-db:fic\n");
        write(fixture.commands.compiledPath, "compiled");
        ::chmod(fixture.commands.compiledPath.c_str(), 0640);
        fixture.commands.createCompiledOnUpdate = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error) &&
                    error.find("not readable by ordinary users") !=
                        std::string::npos,
                "compiled database 0640 passed ordinary-user verification");
    }
    {
        Fixture fixture;
        write(fixture.options.profilePath, "user-db:user\nsystem-db:fic\n");
        write(fixture.commands.compiledPath, "compiled");
        ::chmod(fixture.commands.compiledPath.c_str(), 0600);
        fixture.commands.createCompiledOnUpdate = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error),
                "compiled database 0600 passed ordinary-user verification");
    }
}

void testProfileUnreadableFailsVerification() {
    Fixture fixture;
    {
        auto backend = fixture.backend();
        std::string error;
        require(backend.ensureManagedSettings(requirements(), error), error);
    }
    ::chmod(fixture.options.profilePath.c_str(), 0640);
    auto backend = fixture.backend();
    std::string error;
    require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("not readable by ordinary users") != std::string::npos,
            "unreadable profile passed ordinary-user verification");
    require(fileMode(fixture.options.profilePath) == 0640,
            "verify re-permissioned the managed profile file");
}

void testDconfUpdateUsesChildUmask() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(!fixture.commands.options.empty(), "no commands were recorded");
    const ProcessOptions updateOptions = fixture.commands.options.front();
    require(updateOptions.childUmask.has_value() &&
                updateOptions.childUmask.value() == 0022,
            "dconf update did not receive an isolated child umask 0022");
    require(fixture.commands.options.back().childUmask.has_value() == false,
            "gsettings verification must not set a child umask");
}

void testFileDbPathCharsetCompatibility() {
    // Upstream dconf accepts arbitrary non-empty paths after file-db:.
    Fixture fixture;
    write(fixture.options.profilePath,
          "user-db:user\nfile-db:/etc/site+db@company=v2/profile.db\n");
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(read(fixture.options.profilePath) ==
                "user-db:user\nsystem-db:fic\n"
                "file-db:/etc/site+db@company=v2/profile.db\n",
            "valid file-db path with ordinary filename characters was rejected");
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
        testProfileCompatibility();
        testUmaskCreatesTraversableFicDirectories();
        testForeignParentInaccessibleFailsClosed();
        testForeignParentTraversableAccepted();
        testCompiledDatabaseUnreadableFailsVerification();
        testProfileUnreadableFailsVerification();
        testDconfUpdateUsesChildUmask();
        testFileDbPathCharsetCompatibility();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
