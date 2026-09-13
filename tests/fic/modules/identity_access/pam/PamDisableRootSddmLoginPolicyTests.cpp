#include "modules/identity_access/pam/policies/PamDisableRootSddmLoginPolicy.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

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
    require(::chmod(path.c_str(), mode) == 0, "could not chmod fixture");
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

struct Tree {
    fs::path root;
    fs::path sddm;
    fic::platform::PamPlatformConfig platform;

    Tree()
        : root([] {
              std::string pattern =
                  (fs::temp_directory_path() / "fic-sddm-root-XXXXXX").string();
              char* path = ::mkdtemp(pattern.data());
              if (path == nullptr) {
                  throw std::runtime_error("mkdtemp failed");
              }
              return fs::path(path);
          }()),
          sddm(root / "etc/pam.d/sddm") {
        platform.trustedAuthenticationExclusions = {
            {"sddm", "pam_succeed_if.so",
             fic::platform::PamTrustedAuthenticationExclusionReason::
                 ExplicitSubjectExclusion,
             "root", "required", {"user", "!=", "root", "quiet_success"},
             sddm, "common-auth", "requisite"}};
    }

    ~Tree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }
};

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
              "disable_root_sddm_login.status=ENABLE\n"
              "disable_root_sddm_login.value=ENABLE\n");
}

const std::string kBase =
    "#%PAM-1.0\n"
    "auth requisite pam_nologin.so\n"
    "@include common-auth\n"
    "@include common-account\n";

const std::string kNative =
    "#%PAM-1.0\n"
    "auth requisite pam_nologin.so\n"
    "auth required pam_succeed_if.so user != root quiet_success\n"
    "@include common-auth\n"
    "@include common-account\n";

const std::string kManaged =
    "#%PAM-1.0\n"
    "auth requisite pam_nologin.so\n"
    "auth requisite pam_succeed_if.so user != root quiet_success\n"
    "@include common-auth\n"
    "@include common-account\n";

void runTests() {
    Tree tree;
    initializeRuntime(tree.root);

    writeFile(tree.sddm, kManaged);
    PamDisableRootSddmLoginPolicy policy(tree.platform);
    require(policy.apply() && policy.apply() && readFile(tree.sddm) == kManaged,
            "already compliant SDDM topology was not idempotent");

    writeFile(tree.sddm, kNative);
    require(policy.apply() && readFile(tree.sddm) == kManaged,
            "native required SDDM root exclusion was not upgraded to "
            "requisite");

    writeFile(tree.sddm, kBase);
    require(policy.apply() && readFile(tree.sddm) == kManaged,
            "missing SDDM root exclusion was not inserted before common-auth");
    require(policy.apply() && readFile(tree.sddm) == kManaged,
            "second SDDM root exclusion apply changed the file");

    const std::string conflict =
        "auth requisite pam_nologin.so\n"
        "auth sufficient pam_succeed_if.so user != root quiet_success\n"
        "@include common-auth\n"
        "@include common-account\n";
    writeFile(tree.sddm, conflict);
    require(!policy.apply() && readFile(tree.sddm) == conflict,
            "conflicting SDDM root exclusion was mutated");

    writeFile(tree.sddm, kBase);
    auto failingWriter = [](const std::string&,
                            const std::string&,
                            const AtomicWriteOptions&,
                            std::string* error) {
        if (error != nullptr) {
            *error = "fixture write failure";
        }
        return false;
    };
    PamDisableRootSddmLoginPolicy writeFailure(tree.platform, failingWriter);
    require(!writeFailure.apply() && readFile(tree.sddm) == kBase,
            "failed SDDM write changed the original file");

    writeFile(tree.sddm, kBase);
    std::size_t calls = 0;
    auto corruptThenRollback = [&](const std::string& path,
                                   const std::string& content,
                                   const AtomicWriteOptions& options,
                                   std::string* error) {
        ++calls;
        if (calls == 1) {
            return AtomicFileWriter::write(
                path,
                "auth requisite pam_nologin.so\n"
                "@include common-auth\n"
                "@include common-account\n",
                options, error);
        }
        return AtomicFileWriter::write(path, content, options, error);
    };
    PamDisableRootSddmLoginPolicy postconditionFailure(
        tree.platform, corruptThenRollback);
    require(!postconditionFailure.apply() && calls == 2 &&
                readFile(tree.sddm) == kBase,
            "SDDM postcondition failure did not restore exact original bytes");
}

} // namespace

int main() {
    try {
        runTests();
    } catch (const std::exception& exception) {
        std::cerr << "PamDisableRootSddmLoginPolicyTests failed: "
                  << exception.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "PamDisableRootSddmLoginPolicyTests passed\n";
    return EXIT_SUCCESS;
}
