#include "modules/dac/submodules/sudo/SudoersConfiguration.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

class TempTree {
public:
    TempTree() {
        std::string pattern = "/tmp/fic-sudoers-test-XXXXXX";
        char* directory = ::mkdtemp(pattern.data());
        if (directory == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = directory;
    }

    ~TempTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path root;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << content;
    if (!stream) {
        throw std::runtime_error("failed to write " + path.string());
    }
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(stream),
                       std::istreambuf_iterator<char>());
}

SudoersConfigurationOptions optionsFor(const TempTree& tree) {
    SudoersConfigurationOptions options;
    options.mainPath = tree.root / "sudoers";
    options.managedPath = tree.root / "sudoers.d" / "zzzz-fic";
    options.validatorPath.clear();
    options.verifyValidatorHash = false;
    options.enforceOwnership = false;
    return options;
}

void testIncludeOrderAndManagedOverride() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "Defaults passwd_tries=2\n"
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    writeFile(tree.root / "sudoers.d" / "10-admin", "Defaults passwd_tries=4\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto before = configuration.inspectGlobalDefault("passwd_tries");
    require(before.found && before.value == "4", "included value must be effective");

    const auto operation = configuration.ensureManagedGlobalDefault(
        "passwd_tries", "Defaults passwd_tries=3", "3");
    require(operation.ok && operation.changed, operation.message);
    require(readFile(options.managedPath).find("Defaults passwd_tries=3") != std::string::npos,
            "managed value was not written");
    const auto managedPermissions = std::filesystem::status(options.managedPath).permissions();
    require((managedPermissions & std::filesystem::perms::all) ==
                (std::filesystem::perms::owner_read |
                 std::filesystem::perms::group_read),
            "managed file mode must be 0440");

    require(::chmod(options.managedPath.c_str(), 0644) == 0,
            "failed to alter managed file mode fixture");
    const auto secondOperation = configuration.ensureManagedGlobalDefault(
        "passwd_tries", "Defaults passwd_tries=2", "2");
    require(secondOperation.ok && secondOperation.changed, secondOperation.message);
    require((std::filesystem::status(options.managedPath).permissions() &
             std::filesystem::perms::all) ==
                (std::filesystem::perms::owner_read |
                 std::filesystem::perms::group_read),
            "existing managed file mode must be corrected to 0440");
    const auto after = configuration.inspectGlobalDefault("passwd_tries");
    require(after.found && after.value == "2", "managed value must be effective");
}

void testManagedOverrideRollsBackWhenNotEffective() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "@includedir " + (tree.root / "sudoers.d").string() + "\n"
              "Defaults passwd_tries=5\n");
    std::filesystem::create_directories(tree.root / "sudoers.d");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto operation = configuration.ensureManagedGlobalDefault(
        "passwd_tries", "Defaults passwd_tries=3", "3");
    require(!operation.ok, "ineffective managed override must fail");
    require(!std::filesystem::exists(options.managedPath), "failed override must be rolled back");
}

void testAuthenticationRewrite() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    const auto source = tree.root / "sudoers.d" / "i_am_first_file";
    writeFile(source,
              "# NOPASSWD: in a comment must stay intact\n"
              "alice ALL=(ALL:ALL) NOPASSWD: ALL\n"
              "%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n"
              "ALL ALL=(ALL:ALL) NOPASSWD :ALL\n"
              "alice ALL=(ALL) CWD = /tmp NOPASSWD: /bin/true\n"
              "mark ALL=(ALL:ALL) CWD=/tmp NOPASSWD: /usr/bin/id\n"
              "Defaults !authenticate\n"
              "Defaults env_reset, exempt_group=sudo\n"
              "alice ALL=(ALL) PASSWD: /bin/echo \"NOPASSWD:\"\n"
              "alice ALL=(ALL) PASSWD: /bin/echo NOPASSWD:\n"
              "Defaults passprompt=\"!authenticate\"\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.authenticationViolations().size() == 7,
            "all violating lines must be reported");
    const auto operation = configuration.enforceAuthentication();
    require(operation.ok && operation.changed, operation.message);

    const std::string changed = readFile(source);
    require(changed.find("alice ALL=(ALL:ALL) PASSWD: ALL") != std::string::npos,
            "alice rule was not rewritten");
    require(changed.find("%sudo ALL=(ALL:ALL) PASSWD: ALL") != std::string::npos,
            "group rule was not rewritten");
    require(changed.find("ALL ALL=(ALL:ALL) PASSWD :ALL") != std::string::npos,
            "ALL rule with whitespace was not rewritten");
    require(changed.find("CWD = /tmp PASSWD: /bin/true") != std::string::npos,
            "rule with a spaced command option was not rewritten");
    require(changed.find("(ALL:ALL) CWD=/tmp PASSWD: /usr/bin/id") != std::string::npos,
            "rule with a Runas group and command option was not rewritten");
    require(changed.find("Defaults authenticate") != std::string::npos,
            "authenticate was not enabled");
    require(changed.find("Defaults env_reset, !exempt_group") != std::string::npos,
            "exempt_group was not disabled");
    require(changed.find("# NOPASSWD: in a comment must stay intact") != std::string::npos,
            "comment was unexpectedly modified");
    require(changed.find("/bin/echo \"NOPASSWD:\"") != std::string::npos,
            "quoted command argument was unexpectedly modified");
    require(changed.find("/bin/echo NOPASSWD:") != std::string::npos,
            "unquoted command argument was unexpectedly modified");
    require(changed.find("passprompt=\"!authenticate\"") != std::string::npos,
            "quoted Defaults value was unexpectedly modified");
    require(configuration.authenticationViolations().empty(),
            "violations remain after enforcement");

    const auto second = configuration.enforceAuthentication();
    require(second.ok && !second.changed, "second application must be idempotent");
}

void testIncludeCycleAndMissingInclude() {
    TempTree tree;
    auto options = optionsFor(tree);
    writeFile(options.mainPath, "@include " + (tree.root / "other").string() + "\n");
    writeFile(tree.root / "other", "@include " + options.mainPath.string() + "\n");

    SudoersConfiguration cyclic(options);
    std::string error;
    require(!cyclic.load(error), "include cycle must fail");

    writeFile(options.mainPath, "@include " + (tree.root / "missing").string() + "\n");
    SudoersConfiguration missing(options);
    error.clear();
    require(missing.load(error), error);
    require(!std::filesystem::exists(tree.root / "missing"),
            "reading a missing include must not create it");
}

void testUnsupportedCompoundHostSpecFailsClosed() {
    TempTree tree;
    const auto options = optionsFor(tree);
    const std::string original =
        "alice host1=(ALL) PASSWD: ALL : host2=(ALL) NOPASSWD: ALL\n";
    writeFile(options.mainPath, original);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.authenticationViolations().size() == 1,
            "compound Host_Spec violation must be reported");
    const auto operation = configuration.enforceAuthentication();
    require(!operation.ok && !operation.changed,
            "unsupported compound Host_Spec must fail without partial rewrite");
    require(readFile(options.mainPath) == original,
            "unsupported compound Host_Spec was partially rewritten");
}

void testUnsupportedMultilineRuleFailsClosed() {
    TempTree tree;
    const auto options = optionsFor(tree);
    const std::string original =
        "alice ALL=(ALL) \\\n"
        "    NOPASSWD: ALL\n";
    writeFile(options.mainPath, original);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.authenticationViolations().size() == 1,
            "multiline NOPASSWD rule must be reported");
    const auto operation = configuration.enforceAuthentication();
    require(!operation.ok && !operation.changed,
            "unsupported multiline rule must fail without partial rewrite");
    require(readFile(options.mainPath) == original,
            "unsupported multiline rule was partially rewritten");
}

void testUnsupportedRulePreventsChangesInOtherFiles() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    const auto supported = tree.root / "sudoers.d" / "10-supported";
    const auto unsupported = tree.root / "sudoers.d" / "20-unsupported";
    const std::string supportedOriginal =
        "alice ALL=(ALL) NOPASSWD: /bin/true\n";
    const std::string unsupportedOriginal =
        "mark ALL=(ALL) \\\n"
        "    NOPASSWD: /bin/false\n";
    writeFile(supported, supportedOriginal);
    writeFile(unsupported, unsupportedOriginal);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto operation = configuration.enforceAuthentication();
    require(!operation.ok && !operation.changed,
            "unsupported rule must fail before changing any document");
    require(readFile(supported) == supportedOriginal,
            "supported document was changed before graph preflight completed");
    require(readFile(unsupported) == unsupportedOriginal,
            "unsupported document was unexpectedly changed");
}

void testValidationFailureRollsBackAllChangedFiles() {
    TempTree tree;
    auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    const auto first = tree.root / "sudoers.d" / "10-first";
    const auto second = tree.root / "sudoers.d" / "20-second";
    const std::string firstOriginal = "alice ALL=(ALL) NOPASSWD: /bin/true\n";
    const std::string secondOriginal = "mark ALL=(ALL) NOPASSWD: /bin/false\n";
    writeFile(first, firstOriginal);
    writeFile(second, secondOriginal);

    const auto validator = tree.root / "validator";
    writeFile(validator,
              "#!/bin/sh\n"
              "if /bin/grep -q ' PASSWD:' '" + first.string() +
              "' && /bin/grep -q ' PASSWD:' '" + second.string() +
              "'; then exit 1; fi\n"
              "exit 0\n");
    require(::chmod(validator.c_str(), 0700) == 0, "failed to make validator executable");
    options.validatorPath = validator;

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto operation = configuration.enforceAuthentication();
    require(!operation.ok && !operation.changed,
            "validation failure must be reported after a complete rollback");
    require(readFile(first) == firstOriginal, "first document was not rolled back");
    require(readFile(second) == secondOriginal, "second document was not rolled back");
}

void testRealVisudoWhenAvailable() {
    const std::filesystem::path visudo = "/usr/sbin/visudo";
    if (!std::filesystem::is_regular_file(visudo)) {
        return;
    }

    TempTree tree;
    auto options = optionsFor(tree);
    options.validatorPath = visudo;
    options.verifyValidatorHash = false;
    writeFile(options.mainPath, "Defaults env_reset\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto operation = configuration.enforceAuthentication();
    require(operation.ok && !operation.changed,
            "real visudo rejected the temporary fixture: " + operation.message);
}

void testMissingMainAndSymlinkAreRejected() {
    TempTree tree;
    auto options = optionsFor(tree);
    SudoersConfiguration missingMain(options);
    std::string error;
    require(!missingMain.load(error), "missing main sudoers must fail");
    require(!std::filesystem::exists(options.mainPath), "missing main sudoers was created");

    const auto realMain = tree.root / "real-sudoers";
    writeFile(realMain, "Defaults env_reset\n");
    std::filesystem::create_symlink(realMain, options.mainPath);
    SudoersConfiguration symlinkMain(options);
    error.clear();
    require(!symlinkMain.load(error), "sudoers symlink must be rejected");
}

} // namespace

int main() {
    try {
        testIncludeOrderAndManagedOverride();
        testManagedOverrideRollsBackWhenNotEffective();
        testAuthenticationRewrite();
        testIncludeCycleAndMissingInclude();
        testUnsupportedCompoundHostSpecFailsClosed();
        testUnsupportedMultilineRuleFailsClosed();
        testUnsupportedRulePreventsChangesInOtherFiles();
        testValidationFailureRollsBackAllChangedFiles();
        testMissingMainAndSymlinkAreRejected();
        testRealVisudoWhenAvailable();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
