#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"

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
    ~Fixture() { std::error_code ignored; fs::remove_all(root, ignored); }
    FlySystemBackend backend() { return FlySystemBackend(options); }
    inline static unsigned long sequence = 0;
};

void testInitialCreationAndVerification() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.desktop() == DesktopEnvironmentKind::Fly &&
            backend.backendName() == "fly", "typed backend identity is wrong");
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(read(fixture.options.configPath) ==
        "[Variables]\nScreenSaverDelay=300\n",
        "initial FLY master state is wrong");
    write(fixture.root / "home/user/.fly/theme/current.themerc",
          "[Variables]\nScreenSaver=evil\nScreenSaverDBUS=false\n"
          "ScreenSaverDelay=99999\n");
    require(backend.verifyManagedSettings(requirements(), error), error);
}

void testMergeCrLfAndIdempotence() {
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
    require(merged.find("# admin\n") != std::string::npos &&
            merged.find("ForeignSetting=keep\n") != std::string::npos &&
            merged.find("ScreenSaver=internal fly-modern-locker\n") !=
                std::string::npos &&
            merged.find("ScreenSaverDBUS=false\n") != std::string::npos &&
            merged.find("ScreenSaverDelay=300\n") != std::string::npos &&
            merged.find("[Other]\nFoo=Bar\n") != std::string::npos,
            "FLY merge lost or failed to canonicalize state");
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
} // namespace

int main() {
    testInitialCreationAndVerification();
    testMergeCrLfAndIdempotence();
    testMalformedAndUnknownFailBeforeMutation();
    testSymlinkAndUnsafeAncestorAreRejected();
    testMissingDirectoryAndVerificationFailures();
    testEmptyRequirementsDoNotTouchFilesystem();
    return 0;
}
