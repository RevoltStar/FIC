#include "modules/identity_access/pam/policies/PamDisableNopasswdloginPolicy.h"

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
            "nopasswdlogin", passwd, group, nsswitch,
            {
                {{"files"}, {"files", "systemd"}},
                {{"files"}, {"files", "systemd"}, {"files", "role"},
                 {"files", "systemd", "role"}},
                {{"files"}, {"files", "systemd"}, {"files", "role"},
                 {"files", "systemd", "role"}}
            }};
    }

    ~Tree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    void reset(const std::string& groupContent,
               const std::string& passwdContent =
                   "alice:x:1000:1000::/home/alice:/bin/sh\n",
               const std::string& nssContent =
                   "passwd: files systemd\ngroup: files systemd role\n") {
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
    bool clearEffectiveOnMutation = true;
    bool resolverFailure = false;
    fic::identity::pam::PamEffectiveGroupMembership effective;
    auto membershipResolver = [&effective, &resolverFailure](
                                  const std::string& group,
                                  fic::identity::pam::
                                      PamEffectiveGroupMembership& result,
                                  std::string& error) {
        require(group == "nopasswdlogin", "unexpected NSS group lookup");
        if (resolverFailure) {
            error = "fixture NSS failure";
            return false;
        }
        result = effective;
        error.clear();
        return true;
    };
    auto clearingRunner = [&](const std::string& executable,
                              const std::vector<std::string>& arguments) {
        ++calls;
        require(executable == tree.gpasswd &&
                    arguments == std::vector<std::string>{
                        "-M", "", "nopasswdlogin"},
                "unexpected gpasswd invocation");
        writeFile(tree.group, "nopasswdlogin:x:2000:\n");
        if (clearEffectiveOnMutation) effective.users.clear();
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    auto makePolicy = [&](PamDisableNopasswdloginPolicy::Runner runner = {}) {
        if (!runner) runner = clearingRunner;
        return std::make_unique<PamDisableNopasswdloginPolicy>(
            tree.platform, tree.resolver, std::move(runner),
            membershipResolver);
    };

    tree.reset("users:x:1000:alice\n");
    effective = {};
    auto policy = makePolicy();
    require(policy->apply() && calls == 0,
            "absent group must be an applied no-op");

    tree.reset("nopasswdlogin:x:2000:\n");
    effective = {true, 2000, {}};
    policy = makePolicy();
    require(policy->apply() && policy->apply() && calls == 0,
            "empty group must be idempotent");

    tree.reset("nopasswdlogin:x:2000:alice,bob\n");
    effective = {true, 2000, {"alice", "bob"}};
    policy = makePolicy();
    require(policy->apply() && policy->apply() && calls == 1 &&
                readFile(tree.group) == "nopasswdlogin:x:2000:\n",
            "supplementary members were not cleared idempotently");

    tree.reset("nopasswdlogin:x:2000:alice\n",
               "alice:x:1000:2000::/home/alice:/bin/sh\n");
    effective = {true, 2000, {"alice"}};
    policy = makePolicy();
    require(!policy->apply() && calls == 1,
            "primary-GID member must fail closed without mutation");

    tree.reset("nopasswdlogin:x:2000:\n");
    effective = {true, 2000, {}};
    policy = makePolicy();
    require(policy->apply(),
            "real ALT files/systemd/role topology was rejected");

    tree.reset("nopasswdlogin:x:2000:\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files systemd\ngroup: files systemd\n");
    effective = {true, 2000, {}};
    policy = makePolicy();
    require(policy->apply(), "supported systemd-only topology was rejected");

    for (const std::string& remote :
         {"sss", "winbind", "ldap", "nis", "compat"}) {
        tree.reset("nopasswdlogin:x:2000:\n",
                   "alice:x:1000:1000::/home/alice:/bin/sh\n",
                   "passwd: files systemd\ngroup: files " + remote + "\n");
        effective = {true, 2000, {}};
        policy = makePolicy();
        require(!policy->apply() && calls == 1,
                "remote NSS service was accepted: " + remote);
    }

    tree.reset("nopasswdlogin:x:2000:\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files sss\ngroup: files\n");
    effective = {true, 2000, {}};
    policy = makePolicy();
    require(!policy->apply(),
            "remote passwd NSS service was reported as disabled");

    tree.reset("nopasswdlogin:x:2000:\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files\ngroup: files\ninitgroups: files sss\n");
    effective = {true, 2000, {}};
    policy = makePolicy();
    require(!policy->apply(),
            "remote NSS initgroups membership was reported as disabled");

    tree.reset("nopasswdlogin:x:2000:\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files systemd\ngroup: files systemd role\n"
               "initgroups: files systemd role\n");
    effective = {true, 2000, {}};
    policy = makePolicy();
    require(policy->apply(), "supported explicit initgroups was rejected");

    tree.reset("nopasswdlogin:x:2000:\n");
    effective = {true, 2000, {"alice"}};
    policy = makePolicy();
    require(!policy->apply() && calls == 1,
            "role-derived effective membership was ignored");

    tree.reset("nopasswdlogin:x:2000:alice\n");
    effective = {true, 2000, {"alice"}};
    clearEffectiveOnMutation = false;
    policy = makePolicy();
    require(!policy->apply() && calls == 2 &&
                readFile(tree.group) == "nopasswdlogin:x:2000:\n",
            "residual effective membership passed the postcondition");
    clearEffectiveOnMutation = true;

    tree.reset("nopasswdlogin:x:2000:\n");
    effective = {true, 2000, {}};
    resolverFailure = true;
    policy = makePolicy();
    require(!policy->apply(), "NSS resolver failure was accepted");
    resolverFailure = false;

    tree.reset("nopasswdlogin:x:2000:alice\n");
    auto failingRunner = [](const std::string&,
                            const std::vector<std::string>&) {
        ProcessResult result;
        result.started = true;
        result.exitCode = 1;
        result.standardError = "fixture failure";
        return result;
    };
    effective = {true, 2000, {"alice"}};
    policy = makePolicy(failingRunner);
    require(!policy->apply() &&
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
    effective = {true, 2000, {"alice"}};
    policy = makePolicy(ineffectiveRunner);
    require(!policy->apply(),
            "successful command without postcondition was accepted");

    tree.reset("nopasswdlogin:x:2000:\n",
               "alice:x:1000:1000::/home/alice:/bin/sh\n",
               "passwd: files systemd\n"
               "group: files [SUCCESS=return] systemd role\n");
    effective = {true, 2000, {}};
    policy = makePolicy();
    require(!policy->apply(), "NSS action override was accepted");
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
