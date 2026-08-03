#include "modules/oss/submodules/Grub.h"

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
    RecordingGrubPolicy() {
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
    } catch (const std::exception& error) {
        std::cerr << "GrubPolicyTests failed: " << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }

    fs::remove_all(root);
    std::cout << "GrubPolicyTests passed\n";
    return 0;
}
