#include "modules/oss/grub/Grub.h"
#include "modules/oss/grub/policies/OSS_grub_cmdline_linux.h"
#include "modules/oss/grub/policies/OSS_grub_disable_recovery.h"
#include "modules/oss/grub/policies/OSS_grub_timeout.h"
#include "modules/oss/grub/GrubConfiguration.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
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
                  "/etc/default/grub", {}},
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

void testConcretePolicyContracts(
    const fic::platform::PlatformExecutableResolver& executables) {
    const fic::platform::GrubPlatformConfig platform{
        "/etc/default/grub", {}};
    OSS_grub_timeout timeout(platform, executables);
    require(timeout.moduleName == "OSS" && timeout.submoduleName == "Grub" &&
                timeout.policyName == "grub_timeout",
            "timeout policy metadata is incorrect");
    require(timeout.validate("0") && timeout.validate("60") &&
                !timeout.validate("61"),
            "timeout policy bounds are incorrect");

    OSS_grub_cmdline_linux cmdline(platform, executables);
    require(cmdline.policyName == "grub_cmdline_linux" &&
                cmdline.validate("") && !cmdline.validate("bad\nvalue") &&
                cmdline.postprocessingValue("") == "[]" &&
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
            {applyDefaults, {}}, resolver);
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
            {applyDefaults, {}}, resolver);
        require(!malformedCmdline.apply(),
                "malformed stored GRUB value must fail without escaping apply");

        testGrubConfigurationEditor(root);
        testAmbiguousAndDynamicAssignmentsFailClosed(root);
        testRebuildFailureCompensates(root);
        testUnsafeInputAndPathsFailClosed(root);
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
