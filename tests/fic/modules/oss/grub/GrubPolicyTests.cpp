#include "modules/oss/grub/Grub.h"
#include "modules/oss/grub/policies/OSS_grub_cmdline_linux.h"
#include "modules/oss/grub/policies/OSS_grub_disable_recovery.h"
#include "modules/oss/grub/policies/OSS_grub_timeout.h"
#include "modules/oss/grub/GrubConfiguration.h"
#include "modules/oss/grub/GrubManagedConfig.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
    output.close();
    require(::chmod(path.c_str(), mode) == 0,
            "could not chmod " + path.string());
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

struct stat fileStatus(const fs::path& path) {
    struct stat status {};
    require(::lstat(path.c_str(), &status) == 0,
            "could not stat " + path.string());
    return status;
}

void initializeRuntimePaths(const fs::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";

    fs::create_directories(paths.configDir);
    fs::create_directories(paths.logDir);
    fs::create_directories(paths.dataDir);
    writeFile(
        paths.configDir / "AUDIT.conf",
        "_schema_version=1\n"
        "log_level.status=ENABLE\n"
        "log_level.value=ERROR\n");

    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

fic::platform::PlatformExecutableResolver makeResolver(
    const fs::path& executable) {
    fic::platform::PlatformExecutables executables;
    executables.entries.push_back(
        {fic::platform::ExecutableId::UpdateGrub, {executable}});
    fic::platform::PlatformExecutableResolverOptions options;
    options.enforceTrustedOwnership = false;
    return fic::platform::PlatformExecutableResolver(
        std::move(executables), options);
}

ProcessResult successfulProcess() {
    ProcessResult result;
    result.started = true;
    result.exitCode = 0;
    return result;
}

ProcessResult failedProcess(const std::string& error = "injected failure") {
    ProcessResult result;
    result.started = true;
    result.exitCode = 1;
    result.standardError = error;
    return result;
}

class RecordingGrubPolicy final : public Grub {
public:
    explicit RecordingGrubPolicy(
        const fic::platform::PlatformExecutableResolver& executables)
        : Grub(
              fic::platform::GrubPlatformConfig{
                  fic::platform::GrubConfigTopology::SharedDefaultsFile,
                  "/etc/default/grub", {}, {}, {}},
              executables) {
        this->policyName = "grub_test_policy";
        this->policyTypeValue =
            std::make_unique<PossibleListPolicyTypeValue>(
                std::vector<std::string>{"expected"});
    }

    bool called = false;
    std::string observedValue;

private:
    bool applyGrub(const std::string& expectedValue) override {
        called = true;
        observedValue = expectedValue;
        return true;
    }
};

class ApplyingGrubPolicy final : public Grub {
public:
    ApplyingGrubPolicy(
        fic::platform::GrubPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables)
        : Grub(std::move(platformConfig), executables, false) {
        this->policyName = "grub_apply_test_policy";
        this->policyTypeValue =
            std::make_unique<PossibleListPolicyTypeValue>(
                std::vector<std::string>{"expected"});
    }

private:
    bool applyGrub(const std::string& expectedValue) override {
        return applyGrubValue("GRUB_TEST_VALUE", expectedValue);
    }
};

GrubConfigurationOptions testOptions(const fs::path& defaults) {
    GrubConfigurationOptions options;
    options.defaultsPath = defaults;
    options.rebuildExecutable = "/test/grub-rebuild";
    options.rebuildArguments = {"--output", "/test/grub.cfg"};
    options.enforceOwnership = false;
    return options;
}

GrubManagedConfigurationOptions managedTestOptions(
    const fs::path& managed,
    const fs::path& baseDefaults = {}) {
    GrubManagedConfigurationOptions options;
    options.managedPath = managed;
    options.rebuildExecutable = "/test/grub-rebuild";
    options.rebuildArguments = {"--output", "/test/grub.cfg"};
    options.enforceOwnership = false;
    options.baseDefaultsPath = baseDefaults;
    return options;
}

GrubCommandRunner countingRebuildRunner(size_t& calls) {
    return [&calls](const std::string&, const std::vector<std::string>&,
                    const ProcessOptions&) {
        ++calls;
        return successfulProcess();
    };
}

void testGrubConfigurationEditor(const fs::path& root) {
    const fs::path defaults = root / "editor/etc/default/grub";
    writeFile(
        defaults,
        "# GRUB boot loader configuration\n"
        "GRUB_DEFAULT=0\n"
        "GRUB_TIMEOUT=5 # menu delay\n"
        "GRUB_CMDLINE_LINUX=\"quiet splash\"\n");

    size_t rebuildCalls = 0;
    const GrubCommandRunner runner =
        [&rebuildCalls](const std::string& executable,
                        const std::vector<std::string>& arguments,
                        const ProcessOptions& options) {
            ++rebuildCalls;
            require(executable == "/test/grub-rebuild",
                    "wrong rebuild executable");
            require(arguments == std::vector<std::string>{
                        "--output", "/test/grub.cfg"},
                    "wrong rebuild arguments");
            require(options.clearEnvironment,
                    "GRUB rebuild must clear the environment");
            return successfulProcess();
        };

    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    const GrubValueObservation cmdline =
        configuration.inspect("GRUB_CMDLINE_LINUX");
    require(cmdline.valid && cmdline.found &&
                cmdline.value == "quiet splash",
            "quoted GRUB command line was not decoded");

    const GrubOperationResult changed =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(changed.ok && changed.changed, changed.message);
    require(rebuildCalls == 1, "changed value must rebuild once");
    require(
        readFile(defaults).find("GRUB_TIMEOUT=\"10\" # menu delay") !=
            std::string::npos,
        "managed value was not safely quoted or comment was lost");

    GrubConfiguration verification(testOptions(defaults), runner);
    require(verification.load(error), error);
    const GrubOperationResult unchanged =
        verification.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(unchanged.ok && !unchanged.changed, unchanged.message);
    require(rebuildCalls == 2,
            "matching defaults must still rebuild a possibly stale grub.cfg");

    GrubConfiguration cmdlineUpdate(testOptions(defaults), runner);
    require(cmdlineUpdate.load(error), error);
    const GrubOperationResult cmdlineChanged =
        cmdlineUpdate.ensureManagedValue(
            "GRUB_CMDLINE_LINUX", "quiet audit=1 $literal");
    require(cmdlineChanged.ok && cmdlineChanged.changed,
            cmdlineChanged.message);
    const std::string content = readFile(defaults);
    require(
        content.find(
            "GRUB_CMDLINE_LINUX=\"quiet audit=1 \\$literal\"") !=
            std::string::npos,
        "command line was not emitted as a literal shell value");

    GrubConfiguration append(testOptions(defaults), runner);
    require(append.load(error), error);
    const GrubOperationResult appended =
        append.ensureManagedValue("GRUB_DISABLE_RECOVERY", "true");
    require(appended.ok && appended.changed, appended.message);
    GrubConfiguration finalVerification(testOptions(defaults), runner);
    require(finalVerification.load(error), error);
    const GrubValueObservation recovery =
        finalVerification.inspect("GRUB_DISABLE_RECOVERY");
    require(recovery.valid && recovery.found && recovery.value == "true",
            "missing GRUB assignment was not appended");
}

void testAmbiguousAndDynamicAssignmentsFailClosed(const fs::path& root) {
    const fs::path defaults = root / "ambiguous/etc/default/grub";
    const std::string duplicate =
        "GRUB_TIMEOUT=5\n"
        "GRUB_TIMEOUT=10\n";
    writeFile(defaults, duplicate);
    size_t calls = 0;
    const GrubCommandRunner runner =
        [&calls](const std::string&, const std::vector<std::string>&,
                 const ProcessOptions&) {
            ++calls;
            return successfulProcess();
        };

    GrubConfiguration duplicateConfiguration(testOptions(defaults), runner);
    std::string error;
    require(duplicateConfiguration.load(error), error);
    const GrubValueObservation observation =
        duplicateConfiguration.inspect("GRUB_TIMEOUT");
    require(!observation.valid &&
                observation.error.find("повторное определение") !=
                    std::string::npos,
            "duplicate target assignment must be ambiguous");
    require(
        !duplicateConfiguration.ensureManagedValue("GRUB_TIMEOUT", "15").ok,
        "ambiguous target assignment must fail before write");
    require(readFile(defaults) == duplicate && calls == 0,
            "ambiguous configuration was modified or rebuilt");

    writeFile(defaults, "GRUB_CMDLINE_LINUX=\"quiet $dynamic\"\n");
    GrubConfiguration dynamicConfiguration(testOptions(defaults), runner);
    require(dynamicConfiguration.load(error), error);
    require(
        !dynamicConfiguration.ensureManagedValue(
             "GRUB_CMDLINE_LINUX", "quiet").ok,
        "dynamic shell expression must fail closed");
    require(calls == 0, "dynamic expression must fail before rebuild");
}

void testRebuildFailureCompensates(const fs::path& root) {
    const fs::path defaults = root / "rollback/etc/default/grub";
    const std::string original = "GRUB_TIMEOUT=5\n";
    writeFile(defaults, original);

    size_t calls = 0;
    const GrubCommandRunner runner =
        [&calls](const std::string&, const std::vector<std::string>&,
                 const ProcessOptions&) {
            ++calls;
            return calls == 1
                ? failedProcess("new configuration rejected")
                : successfulProcess();
        };
    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    const GrubOperationResult result =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(!result.ok, "failed rebuild must fail policy application");
    require(calls == 2,
            "failed rebuild must regenerate grub.cfg after restoring defaults");
    require(readFile(defaults) == original,
            "defaults file was not restored after rebuild failure");
}

void testUnsafeInputAndPathsFailClosed(const fs::path& root) {
    const fs::path defaults = root / "unsafe/etc/default/grub";
    writeFile(defaults, "GRUB_TIMEOUT=5\n");
    size_t calls = 0;
    const GrubCommandRunner runner =
        [&calls](const std::string&, const std::vector<std::string>&,
                 const ProcessOptions&) {
            ++calls;
            return successfulProcess();
        };

    GrubConfiguration configuration(testOptions(defaults), runner);
    std::string error;
    require(configuration.load(error), error);
    require(
        !configuration.ensureManagedValue(
             "GRUB_TIMEOUT", "10\nMALICIOUS=1").ok,
        "multiline value must be rejected");
    require(calls == 0 && readFile(defaults) == "GRUB_TIMEOUT=5\n",
            "unsafe value changed configuration or ran rebuild");

    const fs::path target = root / "unsafe/target";
    const fs::path link = root / "unsafe/grub-link";
    writeFile(target, "GRUB_TIMEOUT=5\n");
    fs::create_symlink(target, link);
    GrubConfiguration symlinkConfiguration(testOptions(link), runner);
    require(!symlinkConfiguration.load(error),
            "GRUB defaults symlink must be rejected");

    GrubConfiguration missingConfiguration(
        testOptions(root / "unsafe/missing"), runner);
    require(!missingConfiguration.load(error),
            "missing GRUB defaults must not be created implicitly");
}

void testAltSharedTopologyStaysShared(const fs::path& root) {
    const fs::path defaults = root / "alt/etc/sysconfig/grub2";
    const fs::path managed =
        root / "alt/etc/default/grub.d/zzzz-fic.cfg";
    writeFile(defaults, "GRUB_TIMEOUT=5\n");
    std::size_t rebuildCalls = 0;
    GrubConfigurationOptions options = testOptions(defaults);
    options.rebuildArguments = {"-o", "/etc/grub.cfg"};
    GrubConfiguration configuration(
        options,
        [&rebuildCalls](const std::string&,
                        const std::vector<std::string>& arguments,
                        const ProcessOptions&) {
            ++rebuildCalls;
            require(arguments == std::vector<std::string>{
                        "-o", "/etc/grub.cfg"},
                    "ALT rebuild arguments changed");
            return successfulProcess();
        });
    std::string error;
    require(configuration.load(error), error);
    const GrubOperationResult result =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(result.ok && result.changed && rebuildCalls == 1 &&
                readFile(defaults).find("GRUB_TIMEOUT=\"10\"") !=
                    std::string::npos &&
                !fs::exists(managed),
            "ALT shared topology used a managed Debian drop-in");
}

void testManagedDropInEditingAndIdempotence(const fs::path& root) {
    const fs::path directory = root / "managed-edit/etc/default/grub.d";
    const fs::path managed = directory / "zzzz-fic.cfg";
    const fs::path shared = root / "managed-edit/etc/default/grub";
    fs::create_directories(directory);
    writeFile(shared, "GRUB_TIMEOUT=3\n");
    writeFile(directory / "50-vendor.cfg", "GRUB_DEFAULT=0\n");

    std::size_t rebuildCalls = 0;
    const GrubCommandRunner runner =
        [&rebuildCalls](const std::string& executable,
                        const std::vector<std::string>& arguments,
                        const ProcessOptions& processOptions) {
            ++rebuildCalls;
            require(executable == "/test/grub-rebuild" &&
                        arguments == std::vector<std::string>{
                            "--output", "/test/grub.cfg"} &&
                        processOptions.clearEnvironment,
                    "managed GRUB rebuild contract changed");
            return successfulProcess();
        };

    GrubOperationResult result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_TIMEOUT", "10", runner);
    require(result.ok && result.changed && rebuildCalls == 1,
            "missing managed GRUB file was not created and rebuilt");
    require(readFile(shared) == "GRUB_TIMEOUT=3\n",
            "Debian owned topology modified /etc/default/grub");
    require(readFile(managed) ==
                "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"10\"\n",
            "managed GRUB file was not canonically generated");
    require((fileStatus(managed).st_mode & 07777) == 0644,
            "managed GRUB file mode is unsafe");

    const std::string cmdline =
        "quiet \"quoted\" \\path $literal `literal` ;&";
    result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_CMDLINE_LINUX", cmdline, runner);
    require(result.ok && result.changed && rebuildCalls == 2,
            "second managed GRUB key was not added");
    GrubManagedConfig verification({managed, false});
    require(verification.loadConfig() &&
                verification.getValue("GRUB_TIMEOUT") == "10" &&
                verification.getValue("GRUB_CMDLINE_LINUX") == cmdline,
            "managed GRUB escaping did not round-trip logical values");
    const std::string escaped = readFile(managed);
    require(escaped.find("\\\"quoted\\\"") != std::string::npos &&
                escaped.find("\\\\path") != std::string::npos &&
                escaped.find("\\$literal") != std::string::npos &&
                escaped.find("\\`literal\\`") != std::string::npos,
            "managed GRUB shell-special characters were not escaped");

    result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_TIMEOUT", "20", runner);
    require(result.ok && result.changed && rebuildCalls == 3,
            "existing managed GRUB value was not changed");
    const ino_t inodeBefore = fileStatus(managed).st_ino;
    const std::string contentBefore = readFile(managed);
    result = ensureManagedGrubDropInValue(
        managedTestOptions(managed), "GRUB_TIMEOUT", "20", runner);
    require(result.ok && !result.changed && rebuildCalls == 4 &&
                fileStatus(managed).st_ino == inodeBefore &&
                readFile(managed) == contentBefore,
            "idempotent managed apply rewrote the file or skipped rebuild");
}

void testManagedTopologyAndStrictFormat(const fs::path& root) {
    const fs::path directory = root / "managed-strict/etc/default/grub.d";
    fs::create_directories(directory);

    const std::vector<std::string> invalidDocuments = {
        "GRUB_TIMEOUT=\"10\"\n",
        "# Managed by FIC. Do not edit.\nUNKNOWN=\"x\"\n",
        "# Managed by FIC. Do not edit.\nGRUB_TIMEOUT=\"5\"\nGRUB_TIMEOUT=\"10\"\n",
        "# Managed by FIC. Do not edit.\nGRUB_TIMEOUT=10\n",
        "# Managed by FIC. Do not edit.\nGRUB_TIMEOUT=\"1\"0\"\n",
        "# Managed by FIC. Do not edit.\nGRUB_CMDLINE_LINUX=\"quiet $(id)\"\n",
        "# Managed by FIC. Do not edit.\nsource /tmp/other\n"
    };
    for (std::size_t index = 0; index < invalidDocuments.size(); ++index) {
        const fs::path caseDirectory = directory / std::to_string(index);
        const fs::path path = caseDirectory / "zzzz-fic.cfg";
        fs::create_directories(caseDirectory);
        writeFile(path, invalidDocuments[index]);
        GrubManagedConfig configuration({path, false});
        require(!configuration.loadConfig(),
                "invalid managed GRUB document was accepted: " +
                    std::to_string(index));
    }

    const fs::path inputDirectory = directory / "input";
    const fs::path inputPath = inputDirectory / "zzzz-fic.cfg";
    fs::create_directories(inputDirectory);
    GrubManagedConfig input({inputPath, false});
    require(input.loadConfig(), input.lastError());
    require(!input.setValue("GRUB_TIMEOUT", "10\r") &&
                !input.setValue("GRUB_TIMEOUT", "10\n") &&
                !input.setValue("GRUB_TIMEOUT", std::string("10\0x", 4)),
            "CR, LF, or NUL managed GRUB values were accepted");
    require(!fs::exists(inputPath),
            "rejected managed values created the managed file");

    const fs::path symlinkDirectory = directory / "symlink";
    const fs::path symlinkPath = symlinkDirectory / "zzzz-fic.cfg";
    fs::create_directories(symlinkDirectory);
    writeFile(symlinkDirectory / "target", "# Managed by FIC. Do not edit.\n");
    fs::create_symlink("target", symlinkPath);
    GrubManagedConfig symlinkConfig({symlinkPath, false});
    require(!symlinkConfig.loadConfig(),
            "managed GRUB symlink was accepted");

    const fs::path unsafeDirectory = directory / "unsafe";
    const fs::path unsafePath = unsafeDirectory / "zzzz-fic.cfg";
    fs::create_directories(unsafeDirectory);
    writeFile(unsafePath, "# Managed by FIC. Do not edit.\n", 0666);
    GrubManagedConfig unsafeConfig({unsafePath, true});
    require(!unsafeConfig.loadConfig(),
            "unsafe managed GRUB ownership or mode was accepted");
}

void testManagedDropInOrdering(const fs::path& root) {
    const fs::path earlyDirectory = root / "ordering-early/etc/default/grub.d";
    const fs::path earlyManaged = earlyDirectory / "zzzz-fic.cfg";
    fs::create_directories(earlyDirectory);
    writeFile(earlyDirectory / "00-vendor.cfg", "GRUB_DEFAULT=0\n");
    writeFile(earlyDirectory / ".zzzzz-hidden.cfg", "GRUB_TIMEOUT=99\n");
    std::size_t earlyCalls = 0;
    GrubOperationResult early = ensureManagedGrubDropInValue(
        managedTestOptions(earlyManaged), "GRUB_TIMEOUT", "10",
        [&earlyCalls](const std::string&, const std::vector<std::string>&,
                      const ProcessOptions&) {
            ++earlyCalls;
            return successfulProcess();
        });
    require(early.ok && earlyCalls == 1,
            "earlier GRUB drop-in incorrectly blocked apply");

    const fs::path lateDirectory = root / "ordering-late/etc/default/grub.d";
    const fs::path lateManaged = lateDirectory / "zzzz-fic.cfg";
    fs::create_directories(lateDirectory);
    const std::string original =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n";
    writeFile(lateManaged, original);
    writeFile(lateDirectory / "zzzzz-local.cfg", "GRUB_TIMEOUT=99\n");
    std::size_t lateCalls = 0;
    GrubOperationResult late = ensureManagedGrubDropInValue(
        managedTestOptions(lateManaged), "GRUB_TIMEOUT", "10",
        [&lateCalls](const std::string&, const std::vector<std::string>&,
                     const ProcessOptions&) {
            ++lateCalls;
            return successfulProcess();
        });
    require(!late.ok && lateCalls == 0 && readFile(lateManaged) == original,
            "later GRUB drop-in did not fail before mutation and rebuild");
}

void testManagedRebuildFailureCompensation(const fs::path& root) {
    const auto runCase = [&](const std::string& name,
                             bool initiallyExists,
                             bool compensationSucceeds) {
        const fs::path directory =
            root / ("managed-compensation-" + name) / "etc/default/grub.d";
        const fs::path managed = directory / "zzzz-fic.cfg";
        fs::create_directories(directory);
        const std::string original =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n";
        if (initiallyExists) writeFile(managed, original);
        std::size_t calls = 0;
        GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed), "GRUB_TIMEOUT", "10",
            [&calls, compensationSucceeds](
                const std::string&, const std::vector<std::string>&,
                const ProcessOptions&) {
                ++calls;
                return calls == 2 && compensationSucceeds
                    ? successfulProcess()
                    : failedProcess("injected rebuild failure");
            });
        require(!result.ok && calls == 2,
                "managed rebuild failure did not run compensation rebuild");
        require(initiallyExists
                    ? fs::exists(managed) && readFile(managed) == original
                    : !fs::exists(managed),
                "managed source was not restored after rebuild failure");
        require(compensationSucceeds || !result.diagnostics.empty(),
                "compensating rebuild failure was not diagnosed");
    };
    runCase("existing", true, true);
    runCase("created", false, true);
    runCase("double-failure", true, false);
}

void testBaseDefaultsValidation(const fs::path& root) {
    const std::string managedContent =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"10\"\n";
    for (const char* name :
         {"base-missing", "base-safe", "base-symlink", "base-mode",
          "base-unsafedir", "base-idempotent"}) {
        fs::create_directories(root / name / "etc/default/grub.d");
    }

    // Missing base defaults: owned apply is allowed.
    {
        const fs::path base = root / "base-missing/etc/default/grub";
        const fs::path managed =
            root / "base-missing/etc/default/grub.d/zzzz-fic.cfg";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(result.ok && calls == 1 && !fs::exists(base) &&
                    readFile(managed) == managedContent,
                "missing base GRUB defaults must not block the owned apply");
    }

    // Safe regular base defaults: apply allowed, base file untouched.
    {
        const fs::path base = root / "base-safe/etc/default/grub";
        const fs::path managed =
            root / "base-safe/etc/default/grub.d/zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n");
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(result.ok && calls == 1 &&
                    readFile(base) == "GRUB_TIMEOUT=3\n" &&
                    readFile(managed) == managedContent,
                "safe base GRUB defaults must not block the owned apply");
    }

    // Symlinked base defaults: fail before any mutation or rebuild.
    {
        const fs::path defaultDirectory = root / "base-symlink/etc/default";
        fs::create_directories(defaultDirectory / "real");
        const fs::path base = defaultDirectory / "grub";
        fs::create_symlink(defaultDirectory / "real/other", base);
        const fs::path managed =
            root / "base-symlink/etc/default/grub.d/zzzz-fic.cfg";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "symlinked base GRUB defaults must fail before mutation");
    }

    // Group/world writable base defaults: fail before any mutation.
    {
        const fs::path base = root / "base-mode/etc/default/grub";
        const fs::path managed =
            root / "base-mode/etc/default/grub.d/zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n", 0666);
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "group/world writable base GRUB defaults must fail closed");
    }

    // Unsafe parent directory of the base defaults: fail before mutation.
    {
        const fs::path defaultDirectory = root / "base-unsafedir/etc/default";
        const fs::path base = defaultDirectory / "grub";
        writeFile(base, "GRUB_TIMEOUT=3\n");
        require(::chmod(defaultDirectory.c_str(), 0777) == 0,
                "could not chmod base defaults parent directory");
        const fs::path managed =
            root / "base-unsafedir/etc/default/grub.d/zzzz-fic.cfg";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(::chmod(defaultDirectory.c_str(), 0755) == 0,
                "could not restore base defaults parent directory mode");
        require(!result.ok && calls == 0 && !fs::exists(managed),
                "unsafe base GRUB defaults parent must fail before mutation");
    }

    // Idempotent managed value with unsafe base defaults: no rebuild,
    // no managed mutation.
    {
        const fs::path base = root / "base-idempotent/etc/default/grub";
        const fs::path managed =
            root / "base-idempotent/etc/default/grub.d/zzzz-fic.cfg";
        writeFile(base, "GRUB_TIMEOUT=3\n", 0666);
        writeFile(managed, managedContent);
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed, base), "GRUB_TIMEOUT", "10",
            countingRebuildRunner(calls));
        require(!result.ok && calls == 0 &&
                    readFile(managed) == managedContent,
                "unsafe base defaults must block even an idempotent apply");
    }
}

void testManagedConcurrentDriftCompensation(const fs::path& root) {
    // Existing managed file changed externally during the failed rebuild:
    // FIC must keep the external state, refuse to restore the original,
    // and skip the compensating rebuild.
    {
        const fs::path directory =
            root / "managed-drift-existing/etc/default/grub.d";
        const fs::path managed = directory / "zzzz-fic.cfg";
        fs::create_directories(directory);
        writeFile(
            managed, "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n");
        const std::string external =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"20\"\n";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed), "GRUB_TIMEOUT", "10",
            [&calls, &managed, external](
                const std::string&, const std::vector<std::string>&,
                const ProcessOptions&) {
                ++calls;
                if (calls == 1) {
                    // Privileged external writer mutates the FIC-installed
                    // file in place right before the rebuild fails.
                    writeFile(managed, external);
                    return failedProcess("injected rebuild failure");
                }
                return successfulProcess();
            });
        require(!result.ok && calls == 1,
                "concurrent drift must not trigger a compensating rebuild");
        require(readFile(managed) == external,
                "external concurrent change was overwritten by compensation");
        require(std::any_of(
                    result.diagnostics.begin(),
                    result.diagnostics.end(),
                    [](const std::string& diagnostic) {
                        return diagnostic.find("внешнее изменение") !=
                                std::string::npos ||
                            diagnostic.find("concurrent") !=
                                std::string::npos;
                    }),
                "concurrent drift was not diagnosed");
    }

    // Newly created managed file changed externally during the failed
    // rebuild: FIC must keep the file and its external content.
    {
        const fs::path directory =
            root / "managed-drift-created/etc/default/grub.d";
        const fs::path managed = directory / "zzzz-fic.cfg";
        fs::create_directories(directory);
        const std::string external =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"20\"\n";
        size_t calls = 0;
        const GrubOperationResult result = ensureManagedGrubDropInValue(
            managedTestOptions(managed), "GRUB_TIMEOUT", "10",
            [&calls, &managed, external](
                const std::string&, const std::vector<std::string>&,
                const ProcessOptions&) {
                ++calls;
                if (calls == 1) {
                    writeFile(managed, external);
                    return failedProcess("injected rebuild failure");
                }
                return successfulProcess();
            });
        require(!result.ok && calls == 1,
                "concurrent drift on a created file must not run "
                "a compensating rebuild");
        require(fs::exists(managed) && readFile(managed) == external,
                "FIC removed or overwrote an externally mutated created file");
        require(std::any_of(
                    result.diagnostics.begin(),
                    result.diagnostics.end(),
                    [](const std::string& diagnostic) {
                        return diagnostic.find("внешнее изменение") !=
                                std::string::npos ||
                            diagnostic.find("concurrent") !=
                                std::string::npos;
                    }),
                "concurrent drift on a created file was not diagnosed");
    }
}

void testConcretePolicyContracts(
    const fic::platform::PlatformExecutableResolver& executables) {
    const fic::platform::GrubPlatformConfig platform{
        fic::platform::GrubConfigTopology::OwnedDefaultsDropIn,
        {}, "/etc/default/grub.d/zzzz-fic.cfg", {}, {}};
    OSS_grub_timeout timeout(platform, executables);
    require(timeout.moduleName == "OSS" && timeout.submoduleName == "Grub" &&
                timeout.policyName == "grub_timeout",
            "timeout policy metadata is incorrect");
    require(timeout.validate("0") && timeout.validate("60") &&
                !timeout.validate("61"),
            "timeout policy bounds are incorrect");

    OSS_grub_cmdline_linux cmdline(platform, executables);
    require(cmdline.policyName == "grub_cmdline_linux" &&
                cmdline.getDefaultValue() == "" &&
                cmdline.validate(cmdline.getDefaultValue()) &&
                cmdline.validate("") && !cmdline.validate("bad\nvalue") &&
                cmdline.postprocessingValue("") == "[]" &&
                cmdline.reverse_postprocessingValue("[]") == "" &&
                cmdline.postprocessingValue("quiet isolcpus=1-3,5") ==
                    "[\"quiet isolcpus=1-3,5\"]" &&
                cmdline.reverse_postprocessingValue(
                    "[\"quiet isolcpus=1-3,5\"]") ==
                    "quiet isolcpus=1-3,5",
            "kernel command-line policy contract is incorrect");

    OSS_grub_disable_recovery recovery(platform, executables);
    require(recovery.policyName == "grub_disable_recovery" &&
                recovery.validate("ENABLE") && recovery.validate("DISABLE") &&
                !recovery.validate("true"),
            "recovery policy contract is incorrect");
}

} // namespace

int main() {
    static_assert(std::is_abstract_v<Grub>,
                  "Grub must remain abstract");

    const fs::path root = fs::temp_directory_path() /
        ("fic-grub-policy-test-" + std::to_string(::getpid()));
    fs::remove_all(root);

    try {
        initializeRuntimePaths(root);
        const fs::path fakeExecutable = root / "bin/grub-rebuild";
        writeFile(fakeExecutable, "test", 0755);
        auto resolver = makeResolver(fakeExecutable);

        writeFile(
            root / "config/OSS.conf",
            "_schema_version=1\n"
            "grub_test_policy.status=ENABLE\n"
            "grub_test_policy.value=expected\n"
            "grub_apply_test_policy.status=ENABLE\n"
            "grub_apply_test_policy.value=expected\n"
            "grub_timeout.status=DISABLE\n"
            "grub_timeout.value=5\n"
            "grub_cmdline_linux.status=DISABLE\n"
            "grub_cmdline_linux.value=[]\n"
            "grub_disable_recovery.status=DISABLE\n"
            "grub_disable_recovery.value=ENABLE\n");

        RecordingGrubPolicy policy(resolver);
        require(policy.moduleName == "OSS" && policy.submoduleName == "Grub",
                "Grub wrapper metadata is incorrect");
        require(policy.apply(), "Grub apply wrapper failed");
        require(policy.called && policy.observedValue == "expected",
                "Grub hook did not receive configured value");

        const fs::path applyDefaults = root / "apply/etc/default/grub";
        writeFile(applyDefaults, "GRUB_TEST_VALUE=expected\n");
        writeFile(fakeExecutable, "#!/bin/sh\nexit 1\n", 0755);
        writeFile(
            root / "data/commandhash.txt",
            fakeExecutable.string() +
                "=275239824e00e61b0a220e61a41791c7e9b4bd726f8b0c27077a338f8131c9dc\n");
        ApplyingGrubPolicy applyingPolicy(
            {fic::platform::GrubConfigTopology::SharedDefaultsFile,
             applyDefaults, {}, {}, {}}, resolver);
        require(!applyingPolicy.apply(),
                "matching defaults bypassed the mandatory GRUB rebuild");

        writeFile(
            root / "config/OSS.conf",
            "_schema_version=1\n"
            "grub_test_policy.status=ENABLE\n"
            "grub_test_policy.value=invalid\n"
            "grub_cmdline_linux.status=ENABLE\n"
            "grub_cmdline_linux.value=not-json\n");
        RecordingGrubPolicy invalidPolicy(resolver);
        require(!invalidPolicy.apply() && !invalidPolicy.called,
                "invalid value must fail before Grub hook");
        OSS_grub_cmdline_linux malformedCmdline(
            {fic::platform::GrubConfigTopology::SharedDefaultsFile,
             applyDefaults, {}, {}, {}}, resolver);
        require(!malformedCmdline.apply(),
                "malformed stored GRUB value must fail without escaping apply");

        testGrubConfigurationEditor(root);
        testAmbiguousAndDynamicAssignmentsFailClosed(root);
        testRebuildFailureCompensates(root);
        testUnsafeInputAndPathsFailClosed(root);
        testAltSharedTopologyStaysShared(root);
        testManagedDropInEditingAndIdempotence(root);
        testManagedTopologyAndStrictFormat(root);
        testManagedDropInOrdering(root);
        testManagedRebuildFailureCompensation(root);
        testBaseDefaultsValidation(root);
        testManagedConcurrentDriftCompensation(root);
        testConcretePolicyContracts(resolver);
    } catch (const std::exception& error) {
        std::cerr << "GrubPolicyTests failed: " << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }

    fs::remove_all(root);
    std::cout << "GrubPolicyTests passed\n";
    return 0;
}
