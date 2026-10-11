#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>
#include <nlohmann/json.hpp>

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
#include <sys/wait.h>
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
    int failUpdateNumber = 0;
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
    bool nativeModel = true;
    bool compileOk = true;
    std::string rejectedNativeSource;
    bool disagreeWithCompile = false;
    bool effectiveOk = true;
    std::string schemaRangeOverride;
    int compiles = 0;

    static std::string nativeBytes(const fs::path& source) {
        std::map<std::string, std::string> files;
        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            if (!entry.is_regular_file()) continue;
            std::istringstream lines(read(entry.path()));
            std::string line, body;
            while (std::getline(lines, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty() && (line.front() == '#' || line.front() == ';')) continue;
                body += line + "\n";
            }
            files[entry.path().lexically_relative(source).string()] = body;
        }
        std::string result = "native-fixture\n";
        for (const auto& [name, body] : files) result += name + "\n" + body;
        return result;
    }

    void inspectSources() {
        values.clear(); writable.clear();
        const auto source = compiledPath.parent_path() / "fic.d";
        if (!fs::exists(source)) return;
        std::map<std::string, fs::path> keyfiles;
        for (const auto& entry : fs::directory_iterator(source))
            if (entry.is_regular_file()) keyfiles[entry.path().filename().string()] = entry.path();
        for (const auto& [name, file] : keyfiles) {
            (void)name;
            std::istringstream lines(read(file)); std::string group, line;
            while (std::getline(lines, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line.front() == '#' || line.front() == ';') continue;
                if (line.front() == '[') group = line.substr(1, line.size() - 2);
                else if (line.find('=') != std::string::npos)
                    values["/" + group + "/" + line.substr(0, line.find('='))] = line.substr(line.find('=') + 1);
            }
        }
        if (fs::exists(source / "locks")) for (const auto& entry : fs::directory_iterator(source / "locks")) {
            std::istringstream lines(read(entry.path())); std::string line;
            while (std::getline(lines, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty() && line.front() == '/') writable[line] = false;
            }
        }
        for (const auto& [key, value] : requirements()) {
            if (!values.count(key.setting)) values[key.setting] = value;
            if (!writable.count(key.setting)) writable[key.setting] = true;
        }
    }

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
                    if (arguments.at(0) == "compile") {
                        ++compiles;
                        if (!compileOk || (!rejectedNativeSource.empty() &&
                            nativeBytes(arguments.at(2)).find(rejectedNativeSource) != std::string::npos)) {
                            result.exitCode = 1; result.standardError = "invalid source";
                        }
                        else write(arguments.at(1), nativeBytes(arguments.at(2)));
                        return result;
                    }
                    ++updates;
                    if (!updateOk || updates == failUpdateNumber) {
                        result.exitCode = 1;
                        result.standardError = "compile failed";
                    } else {
                        if (nativeModel && arguments.size() == 2) {
                            const fs::path isolated = arguments.at(1);
                            write(isolated / "fic", nativeBytes(isolated / "fic.d") +
                                (disagreeWithCompile ? "unexpected native update output" : ""));
                            ::chmod((isolated / "fic").c_str(), compiledMode);
                            inspectSources();
                            return result;
                        }
                        if (createCompiledOnUpdate && !compiledPath.empty()) {
                            std::ofstream(compiledPath, std::ios::binary)
                                << (nativeModel ? nativeBytes(compiledPath.parent_path() / "fic.d") : "compiled");
                            ::chmod(compiledPath.c_str(), compiledMode);
                        }
                        if (repairOnUpdate) {
                            for (const auto& [key, value] : requirements()) {
                                values[key.setting] = value;
                                writable[key.setting] = false;
                            }
                        }
                        if (nativeModel) inspectSources();
                    }
                    return result;
                }
                const std::string path = physical(arguments.at(1), arguments.at(2));
                if (arguments.at(0) == "range") {
                    result.standardOutput = schemaRangeOverride.empty() ?
                        (arguments.at(2) == "idle-delay" || arguments.at(2) == "lock-delay" ? "type u\n" : "type b\n") : schemaRangeOverride;
                    return result;
                }
                if (!effectiveOk) { result.exitCode = 1; result.standardError = "effective inspection failed"; return result; }
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
        options.lockPath = root / "desktop-config.lock";
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

void prepareJournalFixture(Fixture& fixture) {
    write(fixture.options.profilePath, "# admin profile\nuser-db:user\nsystem-db:fic\n");
    write(fixture.keyfile(), "# admin source\r\n[org/gnome/desktop/session]\r\n"
          "idle-delay=uint32 600\r\nforeign-key='keep'\r\n"
          "[org/gnome/desktop/screensaver]\r\nlock-enabled=false\r\nlock-delay=uint32 10\r\n"
          "[org/gnome/desktop/lockdown]\r\ndisable-lock-screen=true\r\n");
    write(fixture.lockfile(), "# admin lock\r\n/org/gnome/desktop/session/idle-delay\r\n");
    write(fixture.options.databaseRoot / "fic.d/locks/10-foreign", "/org/gnome/desktop/screensaver/lock-enabled\n");
    for (const auto& entry : fs::recursive_directory_iterator(fixture.root))
        ::chmod(entry.path().c_str(), entry.is_directory() ? 0755 : 0644);
    fixture.commands.nativeModel = true;
    write(fixture.commands.compiledPath, FakeCommands::nativeBytes(fixture.keyfile().parent_path()));
    fixture.commands.inspectSources();
}

void testEmptyRequirementsDoNothing() {
    Fixture fixture; prepareJournalFixture(fixture);
    auto backend = fixture.backend();
    const auto before = read(fixture.keyfile());
    std::string error;
    require(backend.ensureManagedSettings({}, error) && read(fixture.keyfile()) == before && fixture.commands.updates == 0,
            "empty ordinary ensure acquired implicit release authority");
}

DesktopGlobalConfigRequirements journalRequirements(bool shared = false) {
    DesktopGlobalConfigRequirements result;
    for (const auto& [key, value] : requirements()) {
        std::set<PolicyRef> owners{{"OSS", "DesktopEnvironment", "screenlock_timeout"}};
        if (shared) owners.insert({"OSS", "DesktopEnvironment", "disable_kde_lock_screen_media_controls"});
        result.emplace(key, GlobalDesktopConfigValue{value, owners});
    }
    return result;
}

std::size_t activeGnomeCount(const fic::rollback::MutationJournal& journal) {
    return static_cast<std::size_t>(std::count_if(journal.records().begin(), journal.records().end(),
        [](const auto& record) { return record.isActive() && record.undo.backend == fic::rollback::MutationBackend::Desktop; }));
}

void testJournaledKeysLocksForeignStateAndOwners() {
    Fixture fixture; prepareJournalFixture(fixture);
    const auto sourceBefore = read(fixture.keyfile());
    const auto locksBefore = read(fixture.lockfile());
    const auto profileBefore = read(fixture.options.profilePath);
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    require(backend.preflightJournaled(journalRequirements(true), journal, error), error);
    require(journal.records().empty() && read(fixture.keyfile()) == sourceBefore && fixture.commands.updates == 1,
            "GNOME preflight mutated protected state");
    require(backend.reconcileJournaled(journalRequirements(true), journal, error), error);
    require(activeGnomeCount(journal) == 4, "GNOME did not persist separate physical key/lock records");
    require(read(fixture.root / "mutations.json").find("foreign-key") == std::string::npos,
            "GNOME journal stored a whole foreign source snapshot");
    require(!backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "unknown"}, journal, error),
            "unknown GNOME policy acquired release authority");
    require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "screenlock_timeout"}, journal, error), error);
    for (const auto& record : journal.records())
        if (record.isActive()) require(std::get<fic::rollback::UndoRestoreDesktopScalar>(record.undo.payload).owners.size() == 1,
            "shared owner removal did not retain the last owner");
    std::string source = read(fixture.keyfile());
    source.replace(source.find("foreign-key='keep'"), std::string("foreign-key='keep'").size(), "foreign-key='changed'");
    write(fixture.keyfile(), source);
    fic::rollback::MutationJournal restarted(fixture.root / "mutations.json");
    require(restarted.initializeOrLoad(error), error);
    require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "disable_kde_lock_screen_media_controls"},
            restarted, error), error);
    std::string expected = sourceBefore;
    expected.replace(expected.find("foreign-key='keep'"), std::string("foreign-key='keep'").size(), "foreign-key='changed'");
    require(read(fixture.keyfile()) == expected && read(fixture.lockfile()) == locksBefore &&
            read(fixture.options.profilePath) == profileBefore && activeGnomeCount(restarted) == 0,
            "GNOME release overwrote foreign bytes/locks/profile or lost original CRLF");
    require(read(fixture.commands.compiledPath) == FakeCommands::nativeBytes(fixture.keyfile().parent_path()),
            "GNOME release left a stale compiled database");
    require(!fixture.commands.writable["/org/gnome/desktop/screensaver/lock-enabled"],
            "GNOME release removed a foreign lock from a different fragment");
    require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "screenlock_timeout"}, restarted, error), error);
}

void testJournaledPartialNativeFailureAndRetry() {
    Fixture fixture; prepareJournalFixture(fixture);
    const auto originalSource = read(fixture.keyfile());
    const auto originalLocks = read(fixture.lockfile());
    const auto path = fixture.root / "mutations.json";
    fic::rollback::MutationJournal journal(path);
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    fixture.commands.failUpdateNumber = fixture.commands.updates + 2;
    require(!backend.reconcileJournaled(journalRequirements(), journal, error),
            "dconf update failure reported success");
    require(activeGnomeCount(journal) == 4 && read(fixture.keyfile()).find("# FIC-DE ") != std::string::npos,
            "native failure lost physical ownership provenance");
    fic::rollback::MutationJournal restarted(path); require(restarted.initializeOrLoad(error), error);
    fixture.commands.updateOk = true;
    require(backend.reconcileJournaled(journalRequirements(), restarted, error), error);
    fixture.commands.effectiveOk = false;
    require(!backend.reconcileJournaled({}, restarted, error), "failed effective release inspection reported success");
    require(read(fixture.keyfile()) == originalSource && read(fixture.lockfile()) == originalLocks &&
            activeGnomeCount(restarted) == 4, "release failure reconstructed settings or discarded provenance");
    fixture.commands.effectiveOk = true;
    fic::rollback::MutationJournal afterRelease(path); require(afterRelease.initializeOrLoad(error), error);
    require(backend.reconcileJournaled({}, afterRelease, error), error);
    require(read(fixture.keyfile()) == originalSource && activeGnomeCount(afterRelease) == 0,
            "release retry reconstructed removed owned values");
}

void testJournaledCasForeignCacheAndOrphans() {
    Fixture fixture; prepareJournalFixture(fixture);
    const auto originalSource = read(fixture.keyfile());
    const auto originalLocks = read(fixture.lockfile());
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    write(fixture.commands.compiledPath, "unrepresented foreign cache");
    require(!backend.preflightJournaled(journalRequirements(), journal, error) && journal.records().empty() &&
            read(fixture.keyfile()) == originalSource && read(fixture.commands.compiledPath) == "unrepresented foreign cache",
            "GNOME adopted an unrepresented foreign compiled database");
    write(fixture.commands.compiledPath, FakeCommands::nativeBytes(fixture.keyfile().parent_path()));
    AtomicFileWriter::setPreInstallHookForTests([&](const std::string& path) {
        if (path == fixture.lockfile().string()) write(path, originalLocks + "# concurrent admin\n");
    });
    struct Reset { ~Reset() { AtomicFileWriter::setPreInstallHookForTests(nullptr); } } reset;
    require(!backend.reconcileJournaled(journalRequirements(), journal, error) && activeGnomeCount(journal) == 4,
            "multi-file CAS conflict did not retain all Prepared records");
    require(read(fixture.lockfile()) == originalLocks + "# concurrent admin\n",
            "GNOME lock CAS overwrote the competing writer");
    AtomicFileWriter::setPreInstallHookForTests(nullptr);
    require(backend.reconcileJournaled(journalRequirements(), journal, error), error);
    const auto installed = read(fixture.keyfile());
    std::string tampered = installed;
    tampered.replace(tampered.find("idle-delay=uint32 300"), std::string("idle-delay=uint32 300").size(), "idle-delay=uint32 900");
    write(fixture.keyfile(), tampered);
    require(!backend.reconcileJournaled({}, journal, error) && read(fixture.keyfile()) == tampered,
            "GNOME release overwrote a foreign owned-scalar edit");
    write(fixture.keyfile(), installed);
    require(backend.reconcileJournaled({}, journal, error), error);
    write(fixture.keyfile(), installed);
    require(!backend.reconcileJournaled({}, journal, error), "GNOME resolved records adopted an orphan marker");
}

void testJournaledPreflightMissingCreationAndBadMetadata() {
    Fixture fixture;
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    require(backend.preflightJournaled(journalRequirements(), journal, error) &&
            !fs::exists(fixture.keyfile()) && journal.records().empty(),
            "container creation preflight mutated the system");
    prepareJournalFixture(fixture);
    require(backend.reconcileJournaled(journalRequirements(), journal, error), error);
    auto record = journal.records().front();
    std::get<fic::rollback::UndoRestoreDesktopScalar>(record.undo.payload).originalLockLine = "/different/key\n";
    fic::rollback::MutationId id = 0;
    require(!journal.prepareMutation(record, id, error), "foreign lock path admitted by scalar validator");
    auto doc = nlohmann::json::parse(read(fixture.root / "mutations.json"));
    doc["records"][0]["undo"]["compiled_target_digest"] = "wrong";
    write(fixture.root / "mutations.json", doc.dump()); ::chmod((fixture.root / "mutations.json").c_str(), 0600);
    fic::rollback::MutationJournal malformed(fixture.root / "mutations.json");
    require(!malformed.initializeOrLoad(error), "invalid native cache authority loaded");
}

void testJournaledSourceAndJournalDurabilityRecovery() {
    Fixture fixture; prepareJournalFixture(fixture);
    const auto originalSource = read(fixture.keyfile());
    const auto originalLocks = read(fixture.lockfile());
    const auto path = fixture.root / "mutations.json";
    fic::rollback::MutationJournal journal(path);
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    struct Reset {
        ~Reset() { AtomicFileWriter::setPreInstallHookForTests(nullptr); AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr); }
    } reset;
    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& target) {
        return target != fixture.keyfile().string();
    });
    require(!backend.reconcileJournaled(journalRequirements(), journal, error),
            "source rename without durability reported success");
    require(read(fixture.keyfile()).find("# FIC-DE ") != std::string::npos && read(fixture.lockfile()) == originalLocks,
            "source durability fault did not bracket a partial multi-file write");
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    fic::rollback::MutationJournal restarted(path); require(restarted.initializeOrLoad(error), error);
    require(backend.reconcileJournaled(journalRequirements(), restarted, error), error);
    AtomicFileWriter::setPreInstallHookForTests([&](const std::string& target) {
        if (target == fixture.commands.compiledPath.string())
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& actual) {
                return actual != path.string();
            });
    });
    require(!backend.reconcileJournaled({}, restarted, error),
            "journal commit durability fault reported successful release");
    require(read(fixture.keyfile()) == originalSource && read(fixture.lockfile()) == originalLocks && !restarted.usable(),
            "commit failure reconstructed released state or kept poisoned journal usable");
    AtomicFileWriter::setPreInstallHookForTests(nullptr);
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    fic::rollback::MutationJournal afterCommitFailure(path); require(afterCommitFailure.initializeOrLoad(error), error);
    require(backend.reconcileJournaled({}, afterCommitFailure, error), error);
    require(read(fixture.keyfile()) == originalSource && activeGnomeCount(afterCommitFailure) == 0,
            "restart did not complete physical release without reconstruction");
}

void testJournaledAbsentKeyRefreshAndReleaseReenrollment() {
    Fixture fixture; prepareJournalFixture(fixture);
    std::string original = read(fixture.keyfile());
    original.erase(original.find("lock-delay=uint32 10\r\n"), std::string("lock-delay=uint32 10\r\n").size());
    write(fixture.keyfile(), original);
    write(fixture.commands.compiledPath, FakeCommands::nativeBytes(fixture.keyfile().parent_path()));
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    require(backend.reconcileJournaled(journalRequirements(), journal, error), error);
    auto refreshed = journalRequirements();
    refreshed.at({"/org/gnome/desktop/session/idle-delay"}).value = "uint32 900";
    require(backend.reconcileJournaled(refreshed, journal, error), error);
    require(fixture.commands.values["/org/gnome/desktop/session/idle-delay"] == "uint32 900",
            "GNOME value refresh did not change effective state");
    fixture.commands.effectiveOk = false;
    require(!backend.reconcileJournaled({}, journal, error), "release readback failure accepted");
    require(read(fixture.keyfile()) == original, "absent original GNOME key was not removed exactly");
    fixture.commands.effectiveOk = true;
    require(backend.reconcileJournaled(journalRequirements(), journal, error), error);
    for (const auto& record : journal.records()) if (record.isActive())
        require(record.id > 4, "re-enrollment reused a released mutation ID");
    require(backend.reconcileJournaled({}, journal, error), error);
    require(read(fixture.keyfile()) == original, "re-enrollment replaced the original inverse delta");
}

void testJournaledPreflightRejectsTargetBeforeEnrollment() {
    Fixture fixture; prepareJournalFixture(fixture);
    const auto source = read(fixture.keyfile());
    const auto locks = read(fixture.lockfile());
    const auto cache = read(fixture.commands.compiledPath);
    const auto profile = read(fixture.options.profilePath);
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    fixture.commands.rejectedNativeSource = "idle-delay=uint32 300";
    require(!backend.preflightJournaled(journalRequirements(), journal, error),
            "preflight accepted a target rejected by the native compiler");
    require(fixture.commands.compiles == 2 && journal.records().empty() &&
            read(fixture.keyfile()) == source && read(fixture.lockfile()) == locks &&
            read(fixture.commands.compiledPath) == cache && read(fixture.options.profilePath) == profile,
            "target preflight failed after protected mutation or enrollment");
    fixture.commands.rejectedNativeSource.clear();
    fixture.commands.schemaRangeOverride = "type s\n";
    require(!backend.preflightJournaled(journalRequirements(), journal, error) && journal.records().empty() &&
            read(fixture.keyfile()) == source && read(fixture.commands.compiledPath) == cache,
            "native-incompatible schema was found after protected mutation");
    fixture.commands.schemaRangeOverride.clear();
    fixture.commands.updateOk = false;
    require(!backend.preflightJournaled(journalRequirements(), journal, error),
            "preflight accepted a target rejected by isolated native update");
    require(journal.records().empty() && read(fixture.keyfile()) == source &&
            read(fixture.lockfile()) == locks && read(fixture.commands.compiledPath) == cache,
            "failed native update in preflight mutated protected state");
    fixture.commands.updateOk = true;
    fixture.commands.disagreeWithCompile = true;
    require(!backend.preflightJournaled(journalRequirements(), journal, error) &&
            error.find("disagrees") != std::string::npos && journal.records().empty(),
            "preflight accepted inconsistent native target outputs");
    fixture.commands.disagreeWithCompile = false;
    require(backend.reconcileJournaled(journalRequirements(), journal, error), error);
    const auto appliedSource = read(fixture.keyfile());
    const auto appliedLocks = read(fixture.lockfile());
    const auto appliedCache = read(fixture.commands.compiledPath);
    const auto appliedJournal = read(fixture.root / "mutations.json");
    fixture.commands.rejectedNativeSource = "idle-delay=uint32 600";
    require(!backend.preflightJournaled({}, journal, error),
            "release preflight accepted a native-rejected inverse target");
    require(read(fixture.keyfile()) == appliedSource && read(fixture.lockfile()) == appliedLocks &&
            read(fixture.commands.compiledPath) == appliedCache &&
            read(fixture.root / "mutations.json") == appliedJournal,
            "release preflight changed physical state or durable ownership");
}

void testJournaledVirginCreationAndContainerCleanup() {
    ScopedUmask restrictive(0077);
    Fixture fixture;
    fixture.commands.nativeModel = true;
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error; require(journal.initializeOrLoad(error), error);
    auto backend = fixture.backend();
    require(backend.preflightJournaled(journalRequirements(), journal, error), error);
    require(!fs::exists(fixture.keyfile()) && !fs::exists(fixture.options.profilePath) && journal.records().empty(),
            "virgin GNOME preflight created protected resources");
    require(backend.reconcileJournaled(journalRequirements(), journal, error), error);
    require(fileMode(fixture.keyfile()) == 0644 && fileMode(fixture.keyfile().parent_path()) == 0755 &&
            fileMode(fixture.options.profilePath.parent_path()) == 0755,
            "GNOME creation inherited restrictive daemon umask");
    require(fs::exists(fixture.keyfile().parent_path() / ".fic-de-owner") &&
            read(fixture.options.profilePath).find("system-db:fic") != std::string::npos,
            "GNOME creation provenance not materialized");
    fic::rollback::MutationJournal restarted(fixture.root / "mutations.json");
    require(restarted.initializeOrLoad(error), error);
    require(backend.reconcileJournaled({}, restarted, error), error);
    require(!fs::exists(fixture.keyfile().parent_path()) && !fs::exists(fixture.commands.compiledPath) &&
            !fs::exists(fixture.options.profilePath), "last-owner release retained an empty created GNOME container");
    for (const auto& record : restarted.records()) require(!record.isActive(), "creation provenance still active after release");
    require(backend.reconcileJournaled(journalRequirements(), restarted, error), error);
    const std::string foreignGroup = "[org/gnome/desktop/interface]\nclock-show-seconds=true\n";
    write(fixture.keyfile(), read(fixture.keyfile()) + foreignGroup);
    write(fixture.keyfile().parent_path() / "20-admin", "[org/gnome/desktop/interface]\nclock-show-date=true\n");
    ::chmod((fixture.keyfile().parent_path() / "20-admin").c_str(), 0644);
    require(backend.reconcileJournaled({}, restarted, error), error);
    require(read(fixture.keyfile().parent_path() / "20-admin").find("clock-show-date=true") != std::string::npos &&
            read(fixture.options.profilePath).find("system-db:fic") != std::string::npos &&
            fs::exists(fixture.commands.compiledPath), "foreign data lost with created GNOME container");
    require(read(fixture.keyfile()) == foreignGroup, "empty created group retained or foreign group altered during release");
    require(!fs::exists(fixture.keyfile().parent_path() / "00-fic-ownership") &&
            read(fixture.options.profilePath).find("# FIC-DE-ARTIFACT") == std::string::npos,
            "foreign container retained FIC creation ownership instead of detaching");
}

void testJournaledSecurityPreflight() {
    for (const std::string fault : {"hidden-root", "hidden-parent", "unsafe-source", "cache-mode", "symlink", "duplicate-group", "profile-priority", "orphan-artifact"}) {
        Fixture fixture; prepareJournalFixture(fixture);
        fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
        std::string error; require(journal.initializeOrLoad(error), error);
        if (fault == "hidden-root") ::chmod(fixture.root.c_str(), 0750);
        if (fault == "hidden-parent") ::chmod((fixture.root / "dconf").c_str(), 0750);
        if (fault == "unsafe-source") ::chmod(fixture.keyfile().c_str(), 0666);
        if (fault == "cache-mode") ::chmod(fixture.commands.compiledPath.c_str(), 0640);
        if (fault == "symlink") { fs::remove(fixture.keyfile()); fs::create_symlink(fixture.commands.compiledPath, fixture.keyfile()); }
        if (fault == "duplicate-group") write(fixture.keyfile(), read(fixture.keyfile()) + "[org/gnome/desktop/session]\n");
        if (fault == "profile-priority") write(fixture.options.profilePath, "user-db:user\nsystem-db:site\nsystem-db:fic\n");
        if (fault == "orphan-artifact") write(fixture.keyfile(), "# FIC-DE-ARTIFACT 999 keyfile\n" + read(fixture.keyfile()));
        const auto before = read(fixture.keyfile());
        auto backend = fixture.backend();
        require(!backend.preflightJournaled(journalRequirements(), journal, error) &&
                journal.records().empty() && read(fixture.keyfile()) == before,
                "GNOME security preflight mutated/adopted unsafe state: " + fault);
        ::chmod(fixture.root.c_str(), 0755); ::chmod((fixture.root / "dconf").c_str(), 0755);
    }
}

void testJournaledUnpublishedDirectoryCrashRecovery() {
    for (const bool nested : {false, true}) for (const bool resume : {true, false}) {
        Fixture fixture;
        const auto path = fixture.root / "mutations.json";
        fic::rollback::MutationJournal initial(path);
        std::string error; require(initial.initializeOrLoad(error), error);
        const pid_t child = ::fork(); require(child >= 0, "fork failed");
        if (!child) {
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& target) {
                const fs::path path(target);
                const auto parent = nested ? fixture.keyfile().parent_path() : fixture.root;
                if (path.filename() == ".fic-de-owner" && path.parent_path().filename().string().find(".fic-de-stage.") == 0 &&
                    path.parent_path().parent_path() == parent)
                    ::_exit(91); // Abrupt exit: no C++ cleanup before directory publication.
                return true;
            });
            fic::rollback::MutationJournal journal(path);
            if (!journal.initializeOrLoad(error)) ::_exit(92);
            auto backend = fixture.backend();
            (void)backend.reconcileJournaled(journalRequirements(), journal, error);
            ::_exit(93);
        }
        int status = 0; require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 91,
            "creation crash seam not reached");
        require(nested ? !fs::exists(fixture.lockfile().parent_path()) : !fs::exists(fixture.root / "dconf"),
                "directory published before crash seam");
        fic::rollback::MutationJournal restarted(path); require(restarted.initializeOrLoad(error), error);
        auto backend = fixture.backend();
        if (resume) require(backend.reconcileJournaled(journalRequirements(), restarted, error), error);
        require(backend.reconcileJournaled({}, restarted, error), error);
        require(!fs::exists(fixture.root / "dconf"), "crash recovery left created policy parents");
        for (const auto& entry : fs::directory_iterator(fixture.root))
            require(entry.path().filename().string().find(".fic-de-stage.") != 0, "proven creation stage leaked after release");
        for (const auto& record : restarted.records()) require(!record.isActive(), "unpublished creation provenance abandoned");
    }
}

} // namespace

int main() {
    try {
        testEmptyRequirementsDoNothing();
        testJournaledKeysLocksForeignStateAndOwners();
        testJournaledPartialNativeFailureAndRetry();
        testJournaledCasForeignCacheAndOrphans();
        testJournaledPreflightMissingCreationAndBadMetadata();
        testJournaledSourceAndJournalDurabilityRecovery();
        testJournaledAbsentKeyRefreshAndReleaseReenrollment();
        testJournaledPreflightRejectsTargetBeforeEnrollment();
        testJournaledVirginCreationAndContainerCleanup();
        testJournaledSecurityPreflight();
        testJournaledUnpublishedDirectoryCrashRecovery();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
