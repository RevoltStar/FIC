#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersIncludeDirective.h"
#include "modules/dac/sudo/SudoersScopedDefaults.h"
#include "modules/dac/sudo/SudoersDisabledWrapper.h"
#include "modules/dac/sudo/SudoersScopedDefaultsTransaction.h"

#include <filesystem>
#include <utility>
#include <vector>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

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

void testManagedInspectionIsIndependentFromEffectiveSource() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "Defaults timestamp_timeout=2\n"
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    // Sorts after zzzz-fic: shadows the FIC managed entry effectively.
    writeFile(tree.root / "sudoers.d" / "zzzzz-external",
              "Defaults timestamp_timeout=10\n");
    writeFile(options.managedPath, "Defaults timestamp_timeout=5\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    const auto effective = configuration.inspectGlobalDefault("timestamp_timeout");
    require(effective.found && effective.value == "10",
            "external source must win the effective inspection");
    require(effective.source.path != options.managedPath,
            "effective value must not come from the FIC managed file");

    const auto managed = configuration.inspectManagedGlobalDefault("timestamp_timeout");
    require(managed.found, "shadowed managed entry must still be visible");
    require(managed.value == "5",
            "managed inspection must report the managed artifact value");
    require(managed.source.path == options.managedPath,
            "managed inspection source must be the FIC managed file");

    const auto missing = configuration.inspectManagedGlobalDefault("passwd_tries");
    require(!missing.found,
            "keys absent from the managed artifact must not be reported");
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
    // 6 violations: exempt_group is NOT one of them any more. Its single
    // owner is sudo_exempt_group_disable; see
    // sudo_require_authenticationDoesNotOwnExemptGroup.
    require(configuration.authenticationViolations().size() == 6,
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
    // Ownership regression (Part G): require_authentication must leave
    // exempt_group byte-exact; it is managed by sudo_exempt_group_disable.
    require(changed.find("Defaults env_reset, exempt_group=sudo") != std::string::npos,
            "exempt_group must not be rewritten by require_authentication");
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
        "alice ALL=(ALL) NOPASSWD: /bin/true, \\\n"
        "    /bin/false\n"
        "mark ALL=(ALL) \\\n"
        "    NOPASSWD: /usr/bin/id\n"
        "Defaults env_reset, \\\n"
        "    !authenticate\n"
        "Defaults env_reset, \\\n"
        "    exempt_group=sudo\n"
        "bob ALL=(ALL) PASSWD: /bin/true, \\\n"
        "    /bin/false\n";
    writeFile(options.mainPath, original);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    // The multiline exempt_group block is deliberately NOT a violation: that
    // security state belongs to sudo_exempt_group_disable.
    require(configuration.authenticationViolations().size() == 3,
            "all authentication-bypassing multiline rules must be reported");
    const auto operation = configuration.enforceAuthentication();
    require(!operation.ok && !operation.changed,
            "unsupported multiline rules must fail without partial rewrite");
    require(readFile(options.mainPath) == original,
            "unsupported multiline rules were partially rewritten");
}

void testInvalidRulesFailBeforeChanges() {
    const std::filesystem::path visudo = "/usr/sbin/visudo";
    if (!std::filesystem::is_regular_file(visudo)) {
        return;
    }

    const std::vector<std::string> invalidRules = {
        "ALL,!alice ALL = ALL NOPASSWD: ALL\n",
        "alice ALL=(ALL) NOPASSWD ALL\n",
        "alice ALL=(ALL NOPASSWD: ALL\n",
        "alice ALL=(ALL) NOPASSWD:\n",
        "alice ALL=(ALL) NOPASSWD: /bin/true,\n",
        "alice ALL=(ALL) NOPASSWD: /bin/true \\\n"
    };

    for (const std::string& invalidRule : invalidRules) {
        TempTree tree;
        auto options = optionsFor(tree);
        options.validatorPath = visudo;
        options.verifyValidatorHash = false;
        const std::string original = "root ALL=(ALL:ALL) ALL\n" + invalidRule;
        writeFile(options.mainPath, original);

        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        const auto operation = configuration.enforceAuthentication();
        require(!operation.ok && !operation.changed,
                "invalid sudoers rule must fail before changes");
        require(readFile(options.mainPath) == original,
                "invalid sudoers file was unexpectedly modified");
    }

    TempTree tree;
    auto options = optionsFor(tree);
    options.validatorPath = visudo;
    options.verifyValidatorHash = false;
    writeFile(options.mainPath,
              "root ALL=(ALL:ALL) ALL\n"
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    const auto supported = tree.root / "sudoers.d" / "10-supported";
    const auto invalid = tree.root / "sudoers.d" / "20-invalid";
    const std::string supportedOriginal = "alice ALL=(ALL) NOPASSWD: /bin/true\n";
    const std::string invalidOriginal = "ALL,!alice ALL = ALL NOPASSWD: ALL\n";
    writeFile(supported, supportedOriginal);
    writeFile(invalid, invalidOriginal);

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto operation = configuration.enforceAuthentication();
    require(!operation.ok && !operation.changed,
            "invalid included rule must fail before changing other files");
    require(readFile(supported) == supportedOriginal,
            "valid included file changed despite invalid graph");
    require(readFile(invalid) == invalidOriginal,
            "invalid included file was unexpectedly modified");
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


// ---------------------------------------------------------------------------
// Part A: include directive lexer regressions.
// ---------------------------------------------------------------------------

void testIncludeArgumentLexing() {
    TempTree tree;
    const auto options = optionsFor(tree);

    // The include directive must be recognized BEFORE comment handling, and
    // the ARGUMENT must honour quotes/escapes/trailing comments.
    struct Case {
        const char* line;
        bool isDirective;
        bool expectSupported;
        const char* expectedPath;
    };
    const std::vector<Case> cases = {
        {"@include /etc/sudoers.local # site settings", true, true, "/etc/sudoers.local"},
        {"#include /etc/sudoers.local # site settings", true, true, "/etc/sudoers.local"},
        {"@include \"/etc/sudoers local\"", true, true, "/etc/sudoers local"},
        {"@include \"/etc/sudoers local\" # site", true, true, "/etc/sudoers local"},
        {"@includedir /etc/sudoers.d # drop-in", true, true, "/etc/sudoers.d"},
        {"#includedir /etc/sudoers.d # drop-in", true, true, "/etc/sudoers.d"},
        // Escaped whitespace in an unquoted include argument is VALID upstream
        // (copy_string() collapses "\\ " to " "), identical in 1.9.13+ and
        // current: the tokenizer keeps "\\ " inside the <GOTINC> token.
        {"@include /etc/a\\b", true, true, "/etc/ab"},
        {"@include /etc/sudoers\\ local", true, true, "/etc/sudoers local"},
        {"#include /etc/sudoers\\ local", true, true, "/etc/sudoers local"},
        // Inside quotes the escapes are collapsed too (append()->copy_string()),
        // so "\\\\" is a single backslash and "\\\"" is a literal quote.
        {"@include \"/etc/back\\\\slash\"", true, true, "/etc/back\\slash"},
        {"@include \"/etc/a\\\"b\"", true, true, "/etc/a\"b"},
        // "\\xHH" is a hex byte.
        {"@include /etc/a\\x2fb", true, true, "/etc/a/b"},
        {"  @include /etc/spaces  ", true, true, "/etc/spaces"},
        {"# a plain comment mentioning @include /etc/x", false, false, nullptr},
        {"#includenotadirective /etc/x", false, false, nullptr},
        {"@includee /etc/x", false, false, nullptr},
        {"Defaults:x env_reset", false, false, nullptr},
        // Unsupported (must fail closed, never silently ignored).
        {"@include", true, false, nullptr},
        {"@include \"unterminated", true, false, nullptr},
        {"@include /etc/x /etc/extra", true, false, nullptr},
        {"@include is a comment-like tail", true, false, nullptr},
        {"@includedir", true, false, nullptr},
    };

    for (const Case& item : cases) {
        const auto directive = fic::sudoers::parseIncludeDirective(item.line);
        if (!item.isDirective) {
            require(directive.kind == fic::sudoers::IncludeKind::None,
                    std::string("line must not be an include directive: ") + item.line);
            continue;
        }
        if (!item.expectSupported) {
            // An include FIC does not model safely must be reported as
            // Unsupported so the caller fails closed.
            require(directive.kind == fic::sudoers::IncludeKind::Unsupported,
                    std::string("line must fail closed as unsupported: ") + item.line);
            require(!directive.error.empty(),
                    std::string("unsupported include must carry a reason: ") +
                    item.line);
            continue;
        }
        require(directive.kind != fic::sudoers::IncludeKind::Unsupported,
                std::string("line must parse as a supported include: ") + item.line);
        require(directive.path == item.expectedPath,
                std::string("wrong include path for '") + item.line + "': got '" +
                directive.path + "'");
    }
    (void)tree;
    (void)options;
}

void testIncludeInlineCommentReachesRealFile() {
    // The false-positive fixture: a scoped/foreign Defaults reachable ONLY
    // through `@include <file> # comment` must be part of the active graph.
    TempTree tree;
    const auto options = optionsFor(tree);
    const auto local = tree.root / "sudoers.local";
    writeFile(local, "Defaults:alice timestamp_timeout=10\n"
                     "Defaults passwd_tries=7\n");
    writeFile(options.mainPath,
              "@include " + local.string() + " # site settings\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.inspectGlobalDefault("passwd_tries").found,
            "included Defaults behind a trailing comment must be visible");
    require(configuration.scopedDefaultsViolations().size() == 1,
            "scoped Defaults behind a trailing comment must be detected");
}

void testLegacyIncludeDirectivesAreNotComments() {
    TempTree tree;
    const auto options = optionsFor(tree);
    const auto local = tree.root / "legacy.local";
    writeFile(local, "Defaults passwd_tries=9\n");
    writeFile(options.mainPath,
              "#include " + local.string() + "\n"
              "# #include " + local.string() + "\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto observed = configuration.inspectGlobalDefault("passwd_tries");
    require(observed.found && observed.value == "9",
            "#include directive must be honoured, unlike a '#' comment line");
}

void testEscapedAndQuotedIncludePaths() {
    TempTree tree;
    const auto options = optionsFor(tree);
    const auto quotedName = std::string("quoted with space");
    const auto backslashName = std::string("back\\slash");
    writeFile(tree.root / quotedName, "Defaults passwd_tries=5\n");
    writeFile(tree.root / backslashName, "Defaults passwd_tries=7\n");

    // Quoted pathnames need no escaping: whitespace is ordinary content, and
    // FIC must select the SAME file sudo selects (expand_include only strips
    // the surrounding quotes; the content is taken verbatim).
    writeFile(options.mainPath,
              "@include \"" + (tree.root / quotedName).string() + "\" # site\n");
    SudoersConfiguration quoted(options);
    std::string error;
    require(quoted.load(error), error);
    const auto quotedValue = quoted.inspectGlobalDefault("passwd_tries");
    require(quotedValue.found && quotedValue.value == "5",
            "double-quoted include pathname must resolve to the real file");

    // To name a file whose path really contains a backslash, the include line
    // must escape it: upstream copy_string() collapses "\\" to a single "\".
    // The on-disk name holds one backslash; the include text holds two.
    writeFile(options.mainPath,
              "@include \"" + tree.root.string() + "/back\\\\slash\"\n");
    SudoersConfiguration backslashed(options);
    error.clear();
    require(backslashed.load(error), error);
    const auto backslashValue =
        backslashed.inspectGlobalDefault("passwd_tries");
    require(backslashValue.found && backslashValue.value == "7",
            "an escaped backslash must resolve to the same file sudo opens: " +
                error);

    // An UNQUOTED escaped blank is valid upstream (the <GOTINC> token keeps
    // "\\ " and copy_string() collapses it to " ").
    std::string escaped;
    const std::string realPath = (tree.root / quotedName).string();
    for (const char c : realPath) {
        if (c == ' ') {
            escaped += "\\ ";
        } else {
            escaped += c;
        }
    }
    writeFile(options.mainPath, "@include " + escaped + "\n");
    SudoersConfiguration unquotedEscape(options);
    error.clear();
    require(unquotedEscape.load(error),
            "an escaped blank in an unquoted include path must resolve: " +
                error);
    const auto escapedValue = unquotedEscape.inspectGlobalDefault("passwd_tries");
    require(escapedValue.found && escapedValue.value == "5",
            "escaped whitespace must resolve to the same file sudo opens");
}

void testRelativeNestedAndOrderedIncludes() {
    TempTree tree;
    const auto options = optionsFor(tree);
    const auto nested = tree.root / "nested.conf";
    const auto spaced = tree.root / "spaced.conf";
    writeFile(nested, "Defaults passwd_tries=6\n");
    writeFile(spaced, "Defaults secure_path=/bin\n");
    // Relative include: resolved against the INCLUDING file's directory.
    writeFile(options.mainPath,
              "@include nested.conf\n"
              "@include ./spaced.conf # relative with comment\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(configuration.inspectGlobalDefault("passwd_tries").found,
            "relative nested include must be followed");
    require(configuration.inspectGlobalDefault("secure_path").found,
            "relative include with trailing comment must be followed");
}

void testUnsupportedIncludeSyntaxFailsClosed() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath, "@include \"unterminated\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(!configuration.load(error),
            "an unsupported include must fail closed, never be ignored");
}

void testPercentIncludeExpansionStaysFailClosed() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "@include " + (tree.root / "sudoers.%h").string() + "\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(!configuration.load(error),
            "%h include expansion must stay fail-closed");
    require(error.find('%') != std::string::npos,
            "fail-closed message must mention the unsupported expansion");
}

void testMissingIncludeKeepsExistingSemantics() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "@include " + (tree.root / "absent").string() + " # missing\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    require(!std::filesystem::exists(tree.root / "absent"),
            "a missing include must never be created");
}

// ---------------------------------------------------------------------------
// Part B: scoped Defaults detection.
// ---------------------------------------------------------------------------

void testScopedDefaultsDetection() {
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"Defaults:alice env_reset", ":"},
        {"Defaults:%admins env_reset", ":"},
        {"Defaults:ADMINS env_reset", ":"},
        {"Defaults:ALL,!root env_reset", ":"},
        {"Defaults@localhost env_reset", "@"},
        {"Defaults@BUILDERS env_reset", "@"},
        {"Defaults>postgres env_reset", ">"},
        {"Defaults>RUNAS_ALIAS env_reset", ">"},
        {"Defaults!/usr/bin/vi env_reset", "!"},
        {"Defaults!EDITOR_CMDS env_reset", "!"},
        {"Defaults:%admins,!alice log_year", ":"},
        {"  Defaults:alice log_year", ":"},
        {"Defaults:alice log_year, logfile=/var/log/sudo.log", ":"},
    };
    for (const auto& [line, scope] : cases) {
        require(fic::sudoers::scopedDefaultsScope(line) == scope,
                "wrong scope for '" + line + "'");
    }

    // Must NOT be treated as scoped.
    const std::vector<std::string> globals = {
        "Defaults env_reset",
        "Defaults !env_reset",
        "Defaults passwd_tries=3, timestamp_timeout=1",
        "# Defaults:alice in a comment",
        "   # Defaults:alice in an indented comment",
        "alice ALL=(ALL:ALL) NOPASSWD: ALL",
        "Defaults",
        "Defaultsthings:alice",
    };
    for (const std::string& line : globals) {
        require(fic::sudoers::scopedDefaultsScope(line).empty(),
                "must not be treated as a scoped Defaults: '" + line + "'");
    }
}

void testScopedDefaultsAcrossTheRealIncludeGraph() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "Defaults env_reset\n"
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    writeFile(tree.root / "sudoers.d" / "10-first",
              "Defaults:bob timestamp_timeout=5\n"
              "Defaults@buildhost log_year\n");
    writeFile(tree.root / "sudoers.d" / "20-second",
              "Defaults:carol !authenticate\n");
    writeFile(options.managedPath, "Defaults secure_path=/bin\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto violations = configuration.scopedDefaultsViolations();
    require(violations.size() == 3,
            "scoped Defaults in included files must all be detected");
}


// ---------------------------------------------------------------------------
// Part F/G: exempt_group single ownership and the managed override.
// ---------------------------------------------------------------------------

void testExemptGroupSingleOwnership() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "Defaults env_reset\n"
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    const auto foreign = tree.root / "sudoers.d" / "10-foreign";
    writeFile(foreign, "Defaults exempt_group=wheel\n");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);

    // sudo_require_authentication must NOT rewrite exempt_group any more.
    const auto operation = configuration.enforceAuthentication();
    require(operation.ok, operation.message);
    require(readFile(foreign) == "Defaults exempt_group=wheel\n",
            "require_authentication must not own exempt_group");

    // sudo_exempt_group_disable owns it through the managed global Defaults.
    const auto managed = configuration.ensureManagedGlobalDefault(
        "exempt_group", "Defaults !exempt_group", "DISABLE");
    require(managed.ok, managed.message);
    require(configuration.inspectGlobalDefault("exempt_group").value == "DISABLE",
            "the managed override must be effective");
    require(readFile(foreign) == "Defaults exempt_group=wheel\n",
            "the foreign global Defaults entry must not be edited");

    // Contextual exempt_group is a scoped violation the blocker must catch:
    // until sudo_disable_scoped_defaults runs, the bypass is still possible.
    writeFile(foreign,
              "Defaults exempt_group=wheel\n"
              "Defaults:alice exempt_group=wheel\n");
    SudoersConfiguration contextual(options);
    error.clear();
    require(contextual.load(error), error);
    require(contextual.scopedDefaultsViolations().size() == 1,
            "a contextual exempt_group must be a scoped Defaults violation");
    fic::sudoers::ScopedDefaultsTransaction transaction(
        contextual, "sudo_disable_scoped_defaults");
    const auto plan = transaction.plan({});
    fic::sudoers::SudoScopedDefaultsHooks hooks;
    hooks.reloadAndVerify = [&contextual](std::string& reloadError) {
        return contextual.load(reloadError) &&
            contextual.scopedDefaultsViolations().empty();
    };
    const auto blocked = transaction.apply(plan.fresh, hooks);
    require(blocked.ok(), blocked.operation.message);
    require(contextual.scopedDefaultsViolations().empty(),
            "after the blocker no contextual exempt_group may remain active");
}

void testManagedExemptGroupFailsWhenShadowed() {
    TempTree tree;
    const auto options = optionsFor(tree);
    writeFile(options.mainPath,
              "@includedir " + (tree.root / "sudoers.d").string() + "\n");
    std::filesystem::create_directories(tree.root / "sudoers.d");

    SudoersConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    const auto firstWrite = configuration.ensureManagedGlobalDefault(
        "exempt_group", "Defaults !exempt_group", "DISABLE");
    require(firstWrite.ok, "the first managed write must succeed: " + firstWrite.message);
    const std::string managedContent = readFile(options.managedPath);

    // A later external source shadows the FIC entry.
    // Sorts AFTER zzzz-fic, so it overrides the managed entry.
    writeFile(tree.root / "sudoers.d" / "zzzzzz-later-external",
              "Defaults exempt_group=wheel\n");
    SudoersConfiguration shadowed(options);
    error.clear();
    require(shadowed.load(error), error);
    // exempt_group=wheel is a string-valued key, so the effective observation
    // is the raw value, not the ENABLE/DISABLE flag form.
    const auto shadowing = shadowed.inspectGlobalDefault("exempt_group");
    require(shadowing.value == "wheel",
            "the later external override must win, got: " + shadowing.value);
    require(shadowing.source.path.filename() == "zzzzzz-later-external",
            "the winning source must be the later external file");

    const auto second = shadowed.ensureManagedGlobalDefault(
        "exempt_group", "Defaults !exempt_group", "DISABLE");
    require(!second.ok,
            "an apply must fail when the desired value is not effective");
    require(readFile(options.managedPath) == managedContent,
            "the managed mutation must be compensated on failure");
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
        testManagedInspectionIsIndependentFromEffectiveSource();
        testAuthenticationRewrite();
        testIncludeCycleAndMissingInclude();
        testUnsupportedCompoundHostSpecFailsClosed();
        testUnsupportedMultilineRuleFailsClosed();
        testInvalidRulesFailBeforeChanges();
        testUnsupportedRulePreventsChangesInOtherFiles();
        testValidationFailureRollsBackAllChangedFiles();
        testScopedDefaultsAcrossTheRealIncludeGraph();
        testIncludeArgumentLexing();
        testIncludeInlineCommentReachesRealFile();
        testLegacyIncludeDirectivesAreNotComments();
        testEscapedAndQuotedIncludePaths();
        testRelativeNestedAndOrderedIncludes();
        testUnsupportedIncludeSyntaxFailsClosed();
        testPercentIncludeExpansionStaysFailClosed();
        testMissingIncludeKeepsExistingSemantics();
        testScopedDefaultsDetection();
        testExemptGroupSingleOwnership();
        testManagedExemptGroupFailsWhenShadowed();
        testMissingMainAndSymlinkAreRejected();
        testRealVisudoWhenAvailable();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
