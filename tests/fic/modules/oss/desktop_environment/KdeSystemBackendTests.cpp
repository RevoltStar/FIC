#include "modules/oss/desktop_environment/backends/KdeSystemBackend.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
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

std::string read(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), {}};
}

void write(const fs::path& path, const std::string& value) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << value;
}

DesktopManagedSettings requirements() {
    return {
        {{"kscreenlockerrc/Daemon/Autolock"}, "true"},
        {{"kscreenlockerrc/Daemon/Timeout"}, "5"},
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

struct FakeCommands {
    bool resolve = true;
    bool immutable = true;
    int executions = 0;
    std::vector<std::string> arguments;
    ProcessOptions options;
    std::map<std::string, std::string> values{
        {"Autolock", "true"}, {"Timeout", "5"}, {"Lock", "true"},
        {"LockGrace", "0"}, {"RequirePassword", "true"}};

    KdeSystemBackendDependencies dependencies() {
        return {
            [this](fic::platform::ExecutableId id, fs::path& path,
                   std::string& error) {
                require(id == fic::platform::ExecutableId::KconfigVerifier,
                        "backend resolved an unexpected executable");
                if (!resolve) {
                    error = "not installed";
                    return false;
                }
                path = "/fake/fic-kconfig-verifier";
                return true;
            },
            [this](const fs::path&, const std::vector<std::string>& args,
                   const ProcessOptions& processOptions) {
                ++executions;
                arguments = args;
                options = processOptions;
                ProcessResult result;
                result.started = true;
                result.exitCode = 0;
                result.standardOutput = "FIC-KCONFIG-V1\n";
                for (const char* key : {"Autolock", "Timeout", "Lock",
                                        "LockGrace", "RequirePassword"}) {
                    result.standardOutput += std::string(key) + "\t" +
                        values.at(key) + "\t" + (immutable ? "1\n" : "0\n");
                }
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
        options.globalsPath = root / "xdg/kdeglobals";
        options.systemConfigDirs = {root / "xdg", root / "lower-priority"};
        options.temporaryRoot = root;
        options.trustedOwner = ::geteuid();
        options.trustedGroup = ::getegid();
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

void requireFiveImmutableKeys(const std::string& content) {
    for (const auto& [physical, value] : requirements()) {
        const std::string key =
            physical.setting.substr(physical.setting.rfind('/') + 1);
        require(content.find(key + "[$i]=" + value + "\n") !=
                    std::string::npos,
                "missing immutable KDE setting: " + key);
    }
}

void testDualFileCreationAndSingleVerifierCall() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    requireFiveImmutableKeys(read(fixture.options.configPath));
    requireFiveImmutableKeys(read(fixture.options.globalsPath));
    require(fileMode(fixture.options.configPath) == 0644 &&
                fileMode(fixture.options.globalsPath) == 0644,
            "KDE system files are not 0644");
    require(fixture.commands.executions == 1 &&
                fixture.commands.arguments.empty(),
            "FullConfig verifier was not called exactly once without arguments");
    const std::string dirs =
        environmentValue(fixture.commands.options, "XDG_CONFIG_DIRS");
    const std::string expectedSuffix =
        (fixture.root / "xdg").string() + ":" +
        (fixture.root / "lower-priority").string();
    require(fixture.commands.options.clearEnvironment &&
                dirs.find("/user/kdedefaults:") != std::string::npos &&
                dirs.size() >= expectedSuffix.size() &&
                dirs.compare(dirs.size() - expectedSuffix.size(),
                             expectedSuffix.size(), expectedSuffix) == 0 &&
                environmentValue(fixture.commands.options, "LC_ALL") == "C",
            "KDE FullConfig verification hierarchy is incomplete");
}

void testDualFileMergeAndIdempotence() {
    Fixture fixture;
    const std::string original =
        "# admin\n[Other]\nForeign=kept\n[Daemon]\n"
        "AdminOnly=kept\nAutolock=false\nTimeout=999\n";
    write(fixture.options.configPath, original);
    write(fixture.options.globalsPath, original);
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    const std::string configOnce = read(fixture.options.configPath);
    const std::string globalsOnce = read(fixture.options.globalsPath);
    for (const auto& content : {configOnce, globalsOnce}) {
        require(content.find("# admin") != std::string::npos &&
                    content.find("[Other]\nForeign=kept") != std::string::npos &&
                    content.find("AdminOnly=kept") != std::string::npos &&
                    content.find("Autolock=false") == std::string::npos &&
                    content.find("Timeout=999") == std::string::npos,
                "dual-file merge did not preserve unrelated state");
        requireFiveImmutableKeys(content);
    }
    require(backend.ensureManagedSettings(requirements(), error), error);
    require(read(fixture.options.configPath) == configOnce &&
                read(fixture.options.globalsPath) == globalsOnce,
            "dual-file ensure is not idempotent");
}

void testBothFilesPrevalidatedBeforeMutation() {
    {
        Fixture fixture;
        write(fixture.options.globalsPath,
              "[Daemon]\nTimeout=1\nTimeout[$i]=2\n");
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "ambiguous kdeglobals was accepted");
        require(!fs::exists(fixture.options.configPath),
                "kscreenlockerrc was written before kdeglobals validation");
    }
    {
        Fixture fixture;
        write(fixture.root / "target", "foreign");
        fs::create_directories(fixture.root / "xdg");
        fs::create_symlink(fixture.root / "target", fixture.options.globalsPath);
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "kdeglobals symlink was accepted");
        require(!fs::exists(fixture.options.configPath),
                "first file was mutated before second-file safety check");
    }
}

void testHierarchyAndVerifierFailures() {
    {
        Fixture fixture;
        fixture.options.systemConfigDirs = {fixture.root / "other"};
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error),
                "managed directory outside hierarchy was accepted");
        require(!fs::exists(fixture.root / "xdg"),
                "invalid hierarchy caused filesystem mutation");
    }
    {
        Fixture fixture;
        fixture.commands.resolve = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                    error.find("fic-kconfig-verifier") != std::string::npos,
                "missing verifier did not fail closed");
        require(!fs::exists(fixture.root / "xdg"),
                "missing verifier caused filesystem mutation");
    }
    {
        Fixture fixture;
        fixture.commands.immutable = false;
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                    error.find("not immutable") != std::string::npos,
                "non-immutable effective FullConfig passed verification");
    }
    {
        Fixture fixture;
        fixture.commands.values["Timeout"] = "30";
        auto backend = fixture.backend();
        std::string error;
        require(!backend.ensureManagedSettings(requirements(), error) &&
                    error.find("required value") != std::string::npos,
                "foreign effective system value passed verification");
    }
}

void testVerifyChecksBothFiles() {
    Fixture fixture;
    auto backend = fixture.backend();
    std::string error;
    require(backend.ensureManagedSettings(requirements(), error), error);
    ::chmod(fixture.options.globalsPath.c_str(), 0640);
    require(!backend.verifyManagedSettings(requirements(), error) &&
                error.find("not readable") != std::string::npos,
            "unreadable kdeglobals passed verification");
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
        testDualFileCreationAndSingleVerifierCall();
        testDualFileMergeAndIdempotence();
        testBothFilesPrevalidatedBeforeMutation();
        testHierarchyAndVerifierFailures();
        testVerifyChecksBothFiles();
        testEmptyRequirementsDoNothing();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
