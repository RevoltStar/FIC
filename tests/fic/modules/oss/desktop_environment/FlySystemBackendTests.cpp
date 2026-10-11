#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

bool GlobalDesktopConfigKey::operator<(
    const GlobalDesktopConfigKey& other) const {
    return setting < other.setting;
}

namespace {
void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

void write(const fs::path& path, const std::string& content) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
    output.close();
    ::chmod(path.c_str(), 0644);
}

std::string read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

DesktopManagedSettings requirements(int seconds = 300) {
    return {
        {{"themerc/Variables/ScreenSaverDelay"}, std::to_string(seconds)},
    };
}

struct Fixture {
    fs::path root = fs::temp_directory_path() /
        ("fic-fly-system-test-" + std::to_string(::getpid()) + "-" +
         std::to_string(sequence++));
    FlySystemBackendOptions options;

    explicit Fixture(bool createThemeMaster = true) {
        fs::create_directories(root);
        ::chmod(root.c_str(), 0755);
        options.trustedRoot = root;
        options.configPath =
            root / "usr/share/fly-wm/theme.master/themerc";
        options.trustedOwner = ::getuid();
        options.trustedGroup = ::getgid();
        options.lockPath = root / "desktop-config.lock";
        fic::rollback::DaemonMutationJournal::instance().setOverridePath(root / "mutations.json");
        if (createThemeMaster) {
            fs::create_directories(options.configPath.parent_path());
            for (fs::path current = root / "usr"; current != root;
                 current = current.parent_path()) {
                ::chmod(current.c_str(), 0755);
                if (current == root / "usr") break;
            }
        } else {
            fs::create_directories(root / "usr/share/fly-wm");
            ::chmod((root / "usr").c_str(), 0755);
            ::chmod((root / "usr/share").c_str(), 0755);
            ::chmod((root / "usr/share/fly-wm").c_str(), 0755);
        }
    }
    ~Fixture() {
        fic::rollback::DaemonMutationJournal::instance().resetOverride();
        std::error_code ignored; fs::remove_all(root, ignored);
    }
    FlySystemBackend backend() { return FlySystemBackend(options); }
    inline static unsigned long sequence = 0;
};

void testInstalledFileAndVerification() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.desktop() == DesktopEnvironmentKind::Fly &&
            backend.backendName() == "fly", "typed backend identity is wrong");
    require(!backend.ensureManagedSettings(requirements(), error) &&
            !fs::exists(fixture.options.configPath),
            "missing installed FLY master was fabricated");
    write(fixture.options.configPath, "[Variables]\nScreenSaverDelay=999\n");
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(read(fixture.options.configPath).find("ScreenSaverDelay=300\n") != std::string::npos &&
            read(fixture.options.configPath).find("# FIC-DE ") != std::string::npos,
            "production ensure did not install journal-backed ownership");
    write(fixture.root / "home/user/.fly/theme/current.themerc",
          "[Variables]\nScreenSaver=evil\nScreenSaverDBUS=false\n"
          "ScreenSaverDelay=99999\n");
    require(backend.verifyManagedSettings(requirements(), error), error);
}

void testPreserveCrLfAndIdempotence() {
    Fixture fixture;
    write(fixture.options.configPath,
          "# admin\r\n[Variables]\r\nForeignSetting=keep\r\n"
          "ScreenSaver=internal fly-modern-locker\r\n"
          "ScreenSaverDBUS=false\r\nScreenSaverDelay=999\r\n\r\n"
          "[Other]\r\nFoo=Bar\r\n");
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    const std::string merged = read(fixture.options.configPath);
    require(merged.find("# admin\r\n") != std::string::npos &&
            merged.find("ForeignSetting=keep\r\n") != std::string::npos &&
            merged.find("ScreenSaver=internal fly-modern-locker\r\n") !=
                std::string::npos &&
            merged.find("ScreenSaverDBUS=false\r\n") != std::string::npos &&
            merged.find("ScreenSaverDelay=300\n") != std::string::npos &&
            merged.find("[Other]\r\nFoo=Bar\r\n") != std::string::npos,
            "FLY apply rewrote foreign line endings or lost data");
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(read(fixture.options.configPath) == merged,
            "idempotent ensure rewrote FLY master state");
}

void testMalformedAndUnknownFailBeforeMutation() {
    {
        Fixture fixture;
        write(fixture.options.configPath,
              "[Variables]\nScreenSaverDelay=60\nScreenSaverDelay=120\n");
        const std::string before = read(fixture.options.configPath);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                read(fixture.options.configPath) == before,
                "duplicate active FLY key was mutated");
    }
    {
        Fixture fixture;
        write(fixture.options.configPath, "[Variables]\nForeign=keep\n");
        DesktopManagedSettings unknown{
            {{"themerc/Variables/ScreenSaver"}, "internal"}};
        const std::string before = read(fixture.options.configPath);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(unknown, error) &&
                read(fixture.options.configPath) == before,
                "unknown FLY requirement reached mutation");
    }
    {
        Fixture fixture;
        write(fixture.options.configPath,
              "[Variables]\nScreenSaver=wrong\n[Variables]\nX=y\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "duplicate [Variables] group was accepted");
    }
    {
        Fixture fixture;
        write(fixture.options.configPath,
              "[Variables]\nScreenSaverDelay malformed\nForeign=keep\n");
        const std::string before = read(fixture.options.configPath);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                read(fixture.options.configPath) == before,
                "malformed active FLY state reached mutation");
    }
}

void testSymlinkAndUnsafeAncestorAreRejected() {
    {
        Fixture fixture;
        const fs::path target = fixture.root / "outside";
        write(target, "untouched\n");
        fs::create_symlink(target, fixture.options.configPath);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                read(target) == "untouched\n",
                "FLY themerc symlink attack was not rejected");
    }
    {
        Fixture fixture;
        const fs::path unsafe = fixture.root / "usr/share";
        ::chmod(unsafe.c_str(), 0777);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "unsafe FLY ancestor was accepted");
        struct stat info {};
        require(::stat(unsafe.c_str(), &info) == 0 &&
                (info.st_mode & 0777) == 0777,
                "unsafe foreign ancestor was chmoded");
        require(!fs::exists(fixture.options.configPath),
                "unsafe ancestor allowed file creation");
    }
}

void testMissingDirectoryAndVerificationFailures() {
    {
        Fixture fixture(false);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                !fs::exists(fixture.options.configPath.parent_path()),
                "missing theme.master directory was created");
    }
    {
        Fixture fixture;
        write(fixture.options.configPath,
              "[Variables]\nScreenSaver=internal fly-modern-locker\n"
              "ScreenSaverDBUS=false\nScreenSaverDelay=5\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.verifyManagedSettings(requirements(), error),
                "wrong FLY master value was verified");
        write(fixture.options.configPath,
              "[Variables]\nScreenSaver=internal fly-modern-locker\n"
              "ScreenSaverDBUS=false\n");
        require(!backend.verifyManagedSettings(requirements(), error),
                "missing FLY master value was verified");
    }
}

void testEmptyRequirementsDoNotTouchFilesystem() {
    Fixture fixture(false);
    fixture.options.configPath = fixture.root / "missing/tree/themerc";
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings({}, error) &&
            backend.verifyManagedSettings({}, error) &&
            !fs::exists(fixture.root / "missing"),
            "empty FLY requirements touched the filesystem");
}

DesktopGlobalConfigRequirements ownedRequirements(int seconds = 300, bool shared = false) {
    std::set<PolicyRef> owners{{"OSS", "DesktopEnvironment", "screenlock_timeout"}};
    if (shared) owners.insert({"OSS", "DesktopEnvironment", "disable_kde_lock_screen_media_controls"});
    return {{{"themerc/Variables/ScreenSaverDelay"}, {std::to_string(seconds), owners}}};
}

fic::rollback::MutationRecord activeFly(const fic::rollback::MutationJournal& journal) {
    for (const auto& record : journal.records())
        if (record.isActive() && record.undo.backend == fic::rollback::MutationBackend::Desktop)
            return record;
    throw std::runtime_error("active FLY record missing");
}

void testJournaledExactDeltaAndSharedOwners() {
    Fixture fixture;
    const std::string original = "# admin\r\n[Variables]\r\nForeign=keep\r\n"
        "  ScreenSaverDelay = 99999\r\n[Other]\r\nTail=no-newline";
    write(fixture.options.configPath, original);
    auto backend = fixture.backend();
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error;
    require(journal.initializeOrLoad(error), error);
    require(backend.preflightJournaled(ownedRequirements(300, true), journal, error), error);
    require(read(fixture.options.configPath) == original && journal.records().empty(),
            "preflight touched the shared config or ownership journal");
    require(backend.reconcileJournaled(ownedRequirements(300, true), journal, error), error);
    const auto applied = activeFly(journal);
    const auto& scalar = std::get<fic::rollback::UndoRestoreDesktopScalar>(applied.undo.payload);
    require(scalar.originalLine == "  ScreenSaverDelay = 99999\r\n" &&
            scalar.owners.size() == 2 && scalar.hadApplied,
            "scalar journal lost original bytes or shared ownership");
    require(read(fixture.root / "mutations.json").find("Foreign=keep") == std::string::npos,
            "journal captured a whole foreign file");
    const std::string once = read(fixture.options.configPath);
    require(backend.reconcileJournaled(ownedRequirements(300), journal, error), error);
    require(read(fixture.options.configPath) == once &&
            std::get<fic::rollback::UndoRestoreDesktopScalar>(activeFly(journal).undo.payload).owners.size() == 1,
            "removal of one owner released a still-required physical key");
    require(backend.reconcileJournaled(ownedRequirements(600), journal, error), error);
    require(activeFly(journal).id == applied.id,
            "value refresh lost the active physical mutation identity");
    const std::string refreshed = read(fixture.options.configPath);
    require(!backend.releaseJournaled(applied, journal, error) &&
            read(fixture.options.configPath) == refreshed,
            "stale release request removed a refreshed requirement with the same mutation ID");
    // A foreign edit to another parameter is deliberately preserved.
    std::string edited = read(fixture.options.configPath);
    edited.replace(edited.find("Foreign=keep"), std::string("Foreign=keep").size(), "Foreign=changed");
    write(fixture.options.configPath, edited);
    require(backend.reconcileJournaled({}, journal, error), error);
    std::string expected = original;
    expected.replace(expected.find("Foreign=keep"), std::string("Foreign=keep").size(), "Foreign=changed");
    require(read(fixture.options.configPath) == expected,
            "rollback did not restore exact scalar bytes or overwrote foreign data");
    require(backend.reconcileJournaled({}, journal, error), error);
}

void testJournaledPolicyOwnerReleaseAfterRestart() {
    Fixture fixture;
    const std::string original = "[Variables]\r\nScreenSaverDelay=999\r\nForeign=keep\r\n";
    write(fixture.options.configPath, original);
    auto backend = fixture.backend();
    const auto path = fixture.root / "mutations.json";
    fic::rollback::MutationJournal journal(path);
    std::string error; require(journal.initializeOrLoad(error), error);
    require(backend.reconcileJournaled(ownedRequirements(300, true), journal, error), error);
    const auto before = read(fixture.options.configPath);
    const auto id = activeFly(journal).id;
    require(!backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "unknown"}, journal, error) &&
            read(fixture.options.configPath) == before, "unknown FLY owner acquired release authority");
    require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "screenlock_timeout"}, journal, error), error);
    const auto retained = activeFly(journal);
    const auto& scalar = std::get<fic::rollback::UndoRestoreDesktopScalar>(retained.undo.payload);
    require(activeFly(journal).id == id && scalar.owners ==
            std::vector<PolicyRef>{{"OSS", "DesktopEnvironment", "disable_kde_lock_screen_media_controls"}} &&
            read(fixture.options.configPath) == before,
            "primary policy release discarded shared FLY ownership");
    fic::rollback::MutationJournal restarted(path); require(restarted.initializeOrLoad(error), error);
    require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "disable_kde_lock_screen_media_controls"},
            restarted, error), error);
    require(read(fixture.options.configPath) == original, "last-owner FLY release lost exact inverse after restart");
    require(backend.releaseOwnerJournaled({"OSS", "DesktopEnvironment", "screenlock_timeout"}, restarted, error), error);
    require(read(fixture.options.configPath) == original, "repeated FLY policy release reconstructed state");
}

void testJournaledInsertionAndOwnershipConflicts() {
    Fixture fixture;
    const std::string original = "[Variables]\nForeign=keep\n[Other]\nTail=keep\n";
    write(fixture.options.configPath, original);
    auto backend = fixture.backend();
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error;
    require(journal.initializeOrLoad(error), error);
    require(backend.reconcileJournaled(ownedRequirements(), journal, error), error);
    const std::string installed = read(fixture.options.configPath);
    const auto mutation = activeFly(journal);
    std::string foreign = installed;
    foreign.replace(foreign.find("ScreenSaverDelay=300"),
                    std::string("ScreenSaverDelay=300").size(), "ScreenSaverDelay=600");
    write(fixture.options.configPath, foreign);
    require(!backend.reconcileJournaled({}, journal, error) && read(fixture.options.configPath) == foreign,
            "rollback overwrote a foreign applied-scalar modification");
    std::string aba = installed;
    const auto idOffset = aba.find("# FIC-DE ") + std::string("# FIC-DE ").size();
    aba.replace(idOffset, std::to_string(mutation.id).size(), std::to_string(mutation.id + 1));
    write(fixture.options.configPath, aba);
    require(!backend.preflightJournaled({}, journal, error), "mutation ID ABA accepted");
    write(fixture.options.configPath, original);
    require(!backend.preflightJournaled(ownedRequirements(), journal, error),
            "missing Applied marker silently adopted the baseline");
    write(fixture.options.configPath, installed);
    require(backend.reconcileJournaled({}, journal, error), error);
    require(read(fixture.options.configPath) == original, "inserted scalar was not removed exactly");
    write(fixture.options.configPath, installed);
    require(!backend.preflightJournaled({}, journal, error), "resolved journal adopted an orphan block");
}

void testJournaledCrashRecovery() {
    Fixture fixture;
    const std::string original = "[Variables]\nScreenSaverDelay=999\nForeign=keep\n";
    write(fixture.options.configPath, original);
    auto backend = fixture.backend();
    const fs::path journalPath = fixture.root / "mutations.json";
    fic::rollback::MutationJournal journal(journalPath);
    std::string error;
    require(journal.initializeOrLoad(error), error);
    struct ResetHooks {
        ~ResetHooks() {
            AtomicFileWriter::setPreInstallHookForTests(nullptr);
            AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
        }
    } reset;
    AtomicFileWriter::setPreInstallHookForTests([&](const std::string& path) {
        if (path == fixture.options.configPath.string()) {
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& target) {
                return target != journalPath.string();
            });
        }
    });
    require(!backend.reconcileJournaled(ownedRequirements(), journal, error),
            "post-install journal durability failure reported success");
    require(read(fixture.options.configPath).find("ScreenSaverDelay=300") != std::string::npos &&
            !journal.usable(), "fault did not leave the physical change and unresolved journal");
    AtomicFileWriter::setPreInstallHookForTests(nullptr);
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    fic::rollback::MutationJournal restarted(journalPath);
    require(restarted.initializeOrLoad(error), error);
    require(backend.reconcileJournaled(ownedRequirements(), restarted, error), error);
    require(std::get<fic::rollback::UndoRestoreDesktopScalar>(activeFly(restarted).undo.payload).originalLine ==
            "ScreenSaverDelay=999\n", "restart replaced the inverse delta with the already applied value");
    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& target) {
        return target != fixture.options.configPath.string();
    });
    require(!backend.reconcileJournaled({}, restarted, error),
            "release rename without durability reported success");
    require(read(fixture.options.configPath) == original && activeFly(restarted).isActive(),
            "release failure lost the original/provenance");
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    fic::rollback::MutationJournal afterRelease(journalPath);
    require(afterRelease.initializeOrLoad(error), error);
    require(backend.reconcileJournaled({}, afterRelease, error), error);
    require(read(fixture.options.configPath) == original,
            "release retry reconstructed the removed FIC setting");
}

void testJournaledCasAndMalformedProvenance() {
    Fixture fixture;
    const std::string original = "[Variables]\nScreenSaverDelay=999\nForeign=keep\n";
    write(fixture.options.configPath, original);
    auto backend = fixture.backend();
    fic::rollback::MutationJournal journal(fixture.root / "mutations.json");
    std::string error;
    require(journal.initializeOrLoad(error), error);
    AtomicFileWriter::setPreInstallHookForTests([&](const std::string& path) {
        if (path == fixture.options.configPath.string()) write(path, original + "# concurrent admin\n");
    });
    struct Reset { ~Reset() { AtomicFileWriter::setPreInstallHookForTests(nullptr); } } reset;
    require(!backend.reconcileJournaled(ownedRequirements(), journal, error),
            "CAS overwrote a concurrent file change");
    require(read(fixture.options.configPath) == original + "# concurrent admin\n",
            "CAS rejection did not preserve the concurrent writer");
    AtomicFileWriter::setPreInstallHookForTests(nullptr);
    require(backend.reconcileJournaled(ownedRequirements(), journal, error), error);
    require(read(fixture.options.configPath).find("# concurrent admin\n") != std::string::npos,
            "retry after CAS rejection lost the concurrent foreign change");
    auto bad = activeFly(journal);
    fic::rollback::MutationId id = 0;
    std::get<fic::rollback::UndoRestoreDesktopScalar>(bad.undo.payload).originalLine = "ScreenSaverDelay=300\n";
    require(!journal.prepareMutation(bad, id, error), "refresh changed the original inverse delta");
    bad = activeFly(journal);
    bad.resource = "../../etc/fstab";
    require(!journal.prepareMutation(bad, id, error), "desktop path traversal accepted");
    bad = activeFly(journal);
    bad.undo.backend = fic::rollback::MutationBackend::Sysctl;
    require(!journal.prepareMutation(bad, id, error), "desktop payload accepted under another backend");
    auto doc = nlohmann::json::parse(read(fixture.root / "mutations.json"));
    doc["records"][0]["undo"]["original_line"] = "ScreenSaverDelay=999\n[Injected]\nKey=evil\n";
    write(fixture.root / "mutations.json", doc.dump());
    ::chmod((fixture.root / "mutations.json").c_str(), 0600);
    fic::rollback::MutationJournal corrupt(fixture.root / "mutations.json");
    require(!corrupt.initializeOrLoad(error), "multiline foreign-file inverse delta loaded");
}
void testInactiveScopeRetainsActiveProvenance() {
    for (const bool missing : {true,false}) {
        Fixture fixture;auto backend=fixture.backend();std::string error;
        write(fixture.options.configPath,"[Variables]\nScreenSaverDelay=900\n");
        fic::rollback::MutationJournal journal(fixture.root/"active-journal.json");require(journal.initializeOrLoad(error),error);
        require(backend.reconcileJournaled(ownedRequirements(),journal,error),error);
        const auto record=activeFly(journal);
        if(missing)fs::remove(fixture.options.configPath);
        else write(fixture.options.configPath,"[Theme]\nName=Foreign replacement\n");
        require(!backend.preflightJournaled({},journal,error),"inactive scope bypassed active FLY ownership proof");
        require(activeFly(journal).id==record.id && activeFly(journal).status==record.status,
                "failed preflight lost active provenance");
    }
}

void testUnmanagedForeignConfiguration() {
    for (const std::string content : {"", "[Theme]\nName=Example\n", "[Other]\r\nScreenSaverDelay=garbage\r\nUnknown=anything\r\n"}) {
        Fixture fixture;
        auto backend=fixture.backend();
        fic::rollback::MutationJournal journal(fixture.root/"foreign-journal.json");
        std::string error;require(journal.initializeOrLoad(error),error);
        if (!content.empty()) write(fixture.options.configPath,content);
        require(backend.preflightJournaled({},journal,error),error);
        require(backend.reconcileJournaled({},journal,error),error);
        require(journal.records().empty(),"unmanaged FLY acquired journal ownership");
        require(content.empty() ? !fs::exists(fixture.options.configPath) : read(fixture.options.configPath)==content,
                "unmanaged foreign FLY bytes changed");
        if (!content.empty()) require(!backend.preflightJournaled(ownedRequirements(),journal,error),
                "required FLY without Variables section accepted");
    }
    {
        Fixture fixture(false);auto backend=fixture.backend();
        fic::rollback::MutationJournal journal(fixture.root/"foreign-journal.json");std::string error;require(journal.initializeOrLoad(error),error);
        require(backend.preflightJournaled({},journal,error)&&!fs::exists(fixture.options.configPath),"safely absent parent blocked inactive FLY");
        ::chmod((fixture.root/"usr/share/fly-wm").c_str(),0777);
        require(!backend.preflightJournaled({},journal,error),"missing target bypassed unsafe ancestor check");
    }
    {
        Fixture fixture(false);
        fs::create_symlink(fixture.root/"absent",fixture.options.configPath.parent_path());
        fic::rollback::MutationJournal journal(fixture.root/"foreign-journal.json");std::string error;require(journal.initializeOrLoad(error),error);
        require(!fixture.backend().preflightJournaled({},journal,error),"missing target behind symlink bypassed path proof");
    }
    {
        Fixture fixture;write(fixture.options.configPath,"[Theme]\nName=Foreign\n");
        ::chmod(fixture.options.configPath.c_str(),0666);
        fic::rollback::MutationJournal journal(fixture.root/"foreign-journal.json");std::string error;require(journal.initializeOrLoad(error),error);
        require(!fixture.backend().preflightJournaled({},journal,error),"unmanaged file bypassed unsafe metadata guard");
    }
    for (const std::string content : {"[Theme]\n# FIC-DE 123 unexpected\n", "# FIC-DE malformed\n"}) {
        Fixture fixture;write(fixture.options.configPath,content);
        fic::rollback::MutationJournal journal(fixture.root/"foreign-journal.json");std::string error;require(journal.initializeOrLoad(error),error);
        require(!fixture.backend().preflightJournaled({},journal,error)&&error.find("Orphan")!=std::string::npos,
                "orphan marker without Variables accepted");
        require(read(fixture.options.configPath)==content&&journal.records().empty(),"orphan marker adopted or erased");
    }
    {
        Fixture fixture;auto backend=fixture.backend();std::string error;
        write(fixture.root/"foreign","[Theme]\nName=Example\n");
        fs::create_symlink(fixture.root/"foreign",fixture.options.configPath);
        fic::rollback::MutationJournal journal(fixture.root/"foreign-journal.json");require(journal.initializeOrLoad(error),error);
        require(!backend.preflightJournaled({},journal,error),"unmanaged symlink accepted");
    }
}

} // namespace

int main() {
    testUnmanagedForeignConfiguration();
    testInactiveScopeRetainsActiveProvenance();
    testInstalledFileAndVerification();
    testPreserveCrLfAndIdempotence();
    testMalformedAndUnknownFailBeforeMutation();
    testSymlinkAndUnsafeAncestorAreRejected();
    testMissingDirectoryAndVerificationFailures();
    testEmptyRequirementsDoNotTouchFilesystem();
    testJournaledExactDeltaAndSharedOwners();
    testJournaledPolicyOwnerReleaseAfterRestart();
    testJournaledInsertionAndOwnershipConflicts();
    testJournaledCrashRecovery();
    testJournaledCasAndMalformedProvenance();
    return 0;
}
