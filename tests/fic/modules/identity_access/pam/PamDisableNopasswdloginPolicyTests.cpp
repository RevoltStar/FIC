#include "modules/identity_access/pam/policies/PamDisableNopasswdloginPolicy.h"
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

namespace fs = std::filesystem;
namespace {
void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}
void writeFile(const fs::path& path, const std::string& bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream file(path);
    file << bytes;
    require(file.good(), "fixture write failed");
}
std::string readFile(const fs::path& path) {
    std::ifstream file(path);
    return std::string(std::istreambuf_iterator<char>(file), {});
}
void initializeRuntime(const fs::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.runtimeDir = root / "run";
    paths.dataDir = root / "data";
    paths.commandHashFile = root / "data/commandhash.txt";
    fs::create_directories(paths.configDir);
    fs::create_directories(paths.logDir);
    fs::create_directories(paths.notifyDir);
    fs::create_directories(paths.runtimeDir);
    fs::create_directories(paths.dataDir);
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
    writeFile(paths.configDir / "IDENTITY_ACCESS.conf",
              "_schema_version=1\n"
              "disable_nopasswdlogin.status=ENABLE\n"
              "disable_nopasswdlogin.value=ENABLE\n");
}

}
int main() {
    const auto root = fs::temp_directory_path() /
        ("fic-passwordless-policy-" + std::to_string(getpid()));
    fs::remove_all(root);
    try {
        initializeRuntime(root);
        fic::rollback::DaemonMutationJournal::instance().setOverridePath(root / "data/journal");
        fic::platform::PamPlatformConfig platform;
        platform.configDirectories = {root / "pam.d"};
        platform.passwordlessLoginTargets = {
            {"lightdm", root / "pam.d/lightdm", {"lightdm"}},
            {"sddm", root / "pam.d/sddm", {"sddm"}}};
        writeFile(root / "pam.d/lightdm",
                  "auth sufficient pam_succeed_if.so user ingroup nopasswdlogin\n"
                  "auth required pam_unix.so\n");
        writeFile(root / "group", "nopasswdlogin:x:2000:alice\n");
        writeFile(root / "nsswitch.conf", "group: files [SUCCESS=merge] systemd role sss\n");
        PamDisableNopasswdloginPolicy policy(platform);
        require(policy.apply(), "production policy apply failed");
        const auto first = readFile(root / "pam.d/lightdm");
        require(first.find("FIC_PAM_NOPASSWDLOGIN BEGIN") != std::string::npos,
                "production policy did not publish a wrapper");
        require(policy.apply() && readFile(root / "pam.d/lightdm") == first,
                "production reapply must be idempotent");
        require(!fs::exists(root / "pam.d/sddm"), "missing service must not be created");
        require(readFile(root / "group") == "nopasswdlogin:x:2000:alice\n",
                "membership must remain untouched");
        fic::rollback::DaemonMutationJournal::instance().resetOverride();
        fs::remove_all(root);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        fic::rollback::DaemonMutationJournal::instance().resetOverride();
        fs::remove_all(root);
        return 1;
    }
    std::cout << "PamDisableNopasswdloginPolicyTests passed\n";
}
