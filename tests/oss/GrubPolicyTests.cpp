#include "modules/oss/submodules/Grub.h"
#include "modules/oss/submodules/GrubConfiguration.h"

#include <fic/core/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <unistd.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::filesystem::path& path,
               const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
    output.close();
}

void initializeRuntimePaths(const std::filesystem::path& root) {
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

    std::filesystem::create_directories(paths.configDir);
    std::filesystem::create_directories(paths.logDir);
    std::filesystem::create_directories(paths.dataDir);

    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

class RecordingGrubPolicy final : public Grub {
public:
    RecordingGrubPolicy()
        : Grub(fic::platform::GrubPlatformConfig{
              "/etc/default/grub",
              {"/usr/sbin/update-grub", "/usr/bin/update-grub"}
          }) {
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

void testGrubConfigurationEditor(const std::filesystem::path& root) {
    const std::filesystem::path defaults = root / "etc/default/grub";
    writeFile(defaults,
              "# GRUB boot loader configuration\n"
              "GRUB_DEFAULT=0\n"
              "GRUB_TIMEOUT=5\n"
              "GRUB_CMDLINE_LINUX=\"quiet splash\"\n");

    GrubConfigurationOptions options;
    options.defaultsPath = defaults;
    options.rebuildCandidates = {"/usr/bin/true"};
    options.enforceOwnership = false;

    GrubConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), "GrubConfiguration load failed: " + error);

    const GrubValueObservation timeout = configuration.inspect("GRUB_TIMEOUT");
    require(timeout.found && timeout.value == "5",
            "GRUB_TIMEOUT was not inspected correctly");

    const GrubValueObservation missing = configuration.inspect("GRUB_DISABLE_RECOVERY");
    require(!missing.found, "missing GRUB key must not be found");

    GrubOperationResult operation =
        configuration.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(operation.ok, "ensureManagedValue failed: " + operation.message);
    require(operation.changed, "ensureManagedValue must report a change");

    GrubConfiguration verification(options);
    require(verification.load(error), "verification load failed: " + error);
    const GrubValueObservation after = verification.inspect("GRUB_TIMEOUT");
    require(after.found && after.value == "10",
            "GRUB_TIMEOUT was not persisted correctly");

    // No deviation -> no change, no rebuild.
    GrubOperationResult unchanged =
        verification.ensureManagedValue("GRUB_TIMEOUT", "10");
    require(unchanged.ok && !unchanged.changed,
            "unchanged value must not trigger a rebuild");

    // Missing key is appended.
    GrubOperationResult appended =
        verification.ensureManagedValue("GRUB_DISABLE_RECOVERY", "true");
    require(appended.ok && appended.changed,
            "appending a missing key failed: " + appended.message);
    GrubConfiguration finalVerification(options);
    require(finalVerification.load(error), "final verification load failed: " + error);
    const GrubValueObservation recovery = finalVerification.inspect("GRUB_DISABLE_RECOVERY");
    require(recovery.found && recovery.value == "true",
            "GRUB_DISABLE_RECOVERY was not appended correctly");
}

} // namespace

int main() {
    static_assert(std::is_abstract_v<Grub>,
                  "Grub must remain abstract without concrete policies");

    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-grub-policy-test-" + std::to_string(::getpid()));
    fs::remove_all(root);

    try {
        initializeRuntimePaths(root);
        writeFile(
            root / "config/OSS.conf",
            "_schema_version=1\n"
            "grub_test_policy.status=ENABLE\n"
            "grub_test_policy.value=expected\n");

        RecordingGrubPolicy policy;
        require(policy.moduleName == "OSS",
                "Grub policy has the wrong module name");
        require(policy.submoduleName == "Grub",
                "Grub policy has the wrong submodule name");
        require(policy.apply(), "Grub apply wrapper failed");
        require(policy.called && policy.observedValue == "expected",
                "Grub hook did not receive the configured value");

        writeFile(
            root / "config/OSS.conf",
            "_schema_version=1\n"
            "grub_test_policy.status=ENABLE\n"
            "grub_test_policy.value=invalid\n");
        RecordingGrubPolicy invalidPolicy;
        require(!invalidPolicy.apply(),
                "invalid Grub policy value must fail before the hook");
        require(!invalidPolicy.called,
                "Grub hook must not run for an invalid value");

        testGrubConfigurationEditor(root);
    } catch (const std::exception& error) {
        std::cerr << "GrubPolicyTests failed: " << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }

    fs::remove_all(root);
    std::cout << "GrubPolicyTests passed\n";
    return 0;
}