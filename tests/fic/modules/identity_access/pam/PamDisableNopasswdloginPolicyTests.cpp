#include "modules/identity_access/pam/policies/PamDisableNopasswdloginPolicy.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
    output.close();
    require(::chmod(path.c_str(), mode) == 0, "could not chmod fixture");
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

struct Tree {
    fs::path root;
    fs::path group;
    fs::path passwd;
    fs::path nsswitch;
    fs::path gpasswd;
    fic::platform::PamPlatformConfig platform;
    fic::platform::PlatformExecutableResolver resolver;

    Tree()
        : root([] {
              std::string pattern =
                  (fs::temp_directory_path() / "fic-nopasswd-XXXXXX").string();
              char* path = ::mkdtemp(pattern.data());
              if (path == nullptr) throw std::runtime_error("mkdtemp failed");
              return fs::path(path);
          }()),
          group(root / "etc/group"), passwd(root / "etc/passwd"),
          nsswitch(root / "etc/nsswitch.conf"),
          gpasswd(root / "bin/gpasswd"),
          resolver(
              fic::platform::PlatformExecutables{{
                  {fic::platform::ExecutableId::Gpasswd, {gpasswd}}}},
              {false}) {
        writeFile(gpasswd, "fixture\n", 0755);
        platform.passwordlessLoginControl = {
            "nopasswdlogin", passwd, group, nsswitch};
    }

    ~Tree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    void reset(const std::string& groupContent,
               const std::string& passwdContent =
                   "alice:x:1000:1000::/home/alice:/bin/sh\n",
               const std::string& nssContent =
                   "passwd: files\ngroup: files\n") {
        writeFile(group, groupContent);
        writeFile(passwd, passwdContent);
        writeFile(nsswitch, nssContent);
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
              "disable_nopasswdlogin.status=ENABLE\n"
              "disable_nopasswdlogin.value=ENABLE\n");
}

void runTests() {
    Tree tree;
    initializeRuntime(tree.root);
    std::size_t calls = 0;
    auto clearingRunner = [&](const std::string& executable,
                              const std::vector<std::string>& arguments) {
        ++calls;
        require(executable == tree.gpasswd &&
                    arguments == std::vector<std::string>{
                        "-M", "", "nopasswdlogin"},
                "unexpected gpasswd invocation");
        writeFile(tree.group, "nopasswdlogin:x:2000:\n");
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };

    tree.reset("users:x:1000:alice\n");
    PamDisableNopasswdloginPolicy absent(
        tree.platform, tree.resolver, clearingRunner);
    require(absent.apply() && calls == 0,
            "absent group must be an applied no-op");

    tree.reset("nopasswdlogin:x:2000:\n");
    PamDisableNopasswdloginPolicy empty(
        tree.platform, tree.resolver, clearingRunner);
    require(empty.apply() && empty.apply() && calls == 0,
            "empty group must be idempotent");

    tree.reset("nopasswdlogin:x:2000:alice,bob\n");
    PamDisableNopasswdloginPolicy supplementary(
        tree.platform, tree.resolver, clearingRunner);
    require(supplementary.apply() && supplementary.apply() && calls == 1 &&
                readFile(tree.group) == "nopasswdlogin:x:2000:\n",
            "supplementary members were not cleared idempotently");

    tree.reset("nopasswdlogin:x:2000:alice\n",
               "alice:x:1000:2000::/home/alice:/bin/sh\n");
    PamDisableNopasswdloginPolicy primary(
        tree.platform, tree.resolver, clearingRunner);
    require(!primary.apply() && calls == 1,
            "primary-GID member must fail closed without mutation");

    tree.reset("users:x:1000:alice\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files\ngroup: files sss\n");
    PamDisableNopasswdloginPolicy remote(
        tree.platform, tree.resolver, clearingRunner);
    require(!remote.apply() && calls == 1,
            "non-local NSS group membership was reported as disabled");

    tree.reset("users:x:1000:alice\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files sss\ngroup: files\n");
    PamDisableNopasswdloginPolicy remotePrimaryGroup(
        tree.platform, tree.resolver, clearingRunner);
    require(!remotePrimaryGroup.apply() && calls == 1,
            "non-local NSS primary-group membership was reported as disabled");

    tree.reset("users:x:1000:alice\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files\ngroup: files\ninitgroups: files sss\n");
    PamDisableNopasswdloginPolicy remoteInitgroups(
        tree.platform, tree.resolver, clearingRunner);
    require(!remoteInitgroups.apply() && calls == 1,
            "non-local NSS initgroups membership was reported as disabled");

    tree.reset("nopasswdlogin:x:2000:\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files\ngroup: files\ninitgroups: files\n");
    PamDisableNopasswdloginPolicy localInitgroups(
        tree.platform, tree.resolver, clearingRunner);
    require(localInitgroups.apply() && calls == 1,
            "explicit local-files-only initgroups was rejected");

    tree.reset("nopasswdlogin:x:2000:alice\n");
    auto failingRunner = [](const std::string&,
                            const std::vector<std::string>&) {
        ProcessResult result;
        result.started = true;
        result.exitCode = 1;
        result.standardError = "fixture failure";
        return result;
    };
    PamDisableNopasswdloginPolicy failedMutation(
        tree.platform, tree.resolver, failingRunner);
    require(!failedMutation.apply() &&
                readFile(tree.group) == "nopasswdlogin:x:2000:alice\n",
            "failed gpasswd mutation was accepted");

    tree.reset("nopasswdlogin:x:2000:alice\n");
    auto ineffectiveRunner = [](const std::string&,
                                const std::vector<std::string>&) {
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    PamDisableNopasswdloginPolicy ineffective(
        tree.platform, tree.resolver, ineffectiveRunner);
    require(!ineffective.apply(),
            "successful command without postcondition was accepted");
}

} // namespace

int main() {
    try {
        runTests();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
