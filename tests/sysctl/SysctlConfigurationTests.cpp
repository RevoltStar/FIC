#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlRuntime.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

class TemporaryTree {
public:
    TemporaryTree() {
        std::string pattern = "/tmp/fic-sysctl-tests-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = created;
        for (const char* directory : {"etc/sysctl.d", "run/sysctl.d",
                                      "usr/local/lib/sysctl.d", "usr/lib/sysctl.d",
                                      "lib/sysctl.d"}) {
            std::filesystem::create_directories(root / directory);
        }
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }

    SysctlConfigurationOptions options() const {
        SysctlConfigurationOptions value;
        value.platform.loader = fic::platform::SysctlLoaderKind::SystemdSysctl;
        value.platform.managedConfigPath = root / "etc/sysctl.d/zzzz-fic.conf";
        value.directories = {
            root / "etc/sysctl.d",
            root / "run/sysctl.d",
            root / "usr/local/lib/sysctl.d",
            root / "usr/lib/sysctl.d",
            root / "lib/sysctl.d"
        };
        value.procpsMainPath = root / "etc/sysctl.conf";
        value.enforceOwnership = false;
        return value;
    }

    std::filesystem::path root;
};

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        throw std::runtime_error("could not create " + path.string());
    }
    stream << content;
    if (!stream.good()) {
        throw std::runtime_error("could not write " + path.string());
    }
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(stream),
                       std::istreambuf_iterator<char>());
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

SysctlConfiguration loaded(const SysctlConfigurationOptions& options) {
    SysctlConfiguration configuration(options);
    std::string error;
    require(configuration.load(error), error);
    return configuration;
}

void testGlobalLexicalOrder() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.d/20-admin.conf", "kernel.test = 20\n");
    writeFile(tree.root / "usr/lib/sysctl.d/90-vendor.conf", "kernel.test = 90\n");

    const auto observation = loaded(tree.options()).inspect("kernel.test");
    require(observation.found && observation.value == "90",
            "filenames must be sorted globally, not grouped by directory priority");
    require(observation.source.path.filename() == "90-vendor.conf",
            "wrong source for globally latest value");
}

void testSameNameUsesHigherPriorityDirectory() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.d/50-default.conf", "kernel.test = etc\n");
    writeFile(tree.root / "run/sysctl.d/50-default.conf", "kernel.test = run\n");
    writeFile(tree.root / "usr/lib/sysctl.d/50-default.conf", "kernel.test = usr\n");

    const auto observation = loaded(tree.options()).inspect("kernel.test");
    require(observation.found && observation.value == "etc",
            "same basename from /etc must suppress lower-priority files");
    require(observation.source.path.parent_path() == tree.root / "etc/sysctl.d",
            "same-name source must come from the highest-priority directory");
}

void testSuppressedInvalidFileIsNotParsed() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.d/50-default.conf", "kernel.test = etc\n");
    writeFile(tree.root / "usr/lib/sysctl.d/50-default.conf", "invalid vendor line\n");

    const auto observation = loaded(tree.options()).inspect("kernel.test");
    require(observation.found && observation.value == "etc",
            "a suppressed same-name file must not be parsed");
}

void testProcpsMainFileIsLastOnlyForProcpsLoader() {
    TemporaryTree tree;
    SysctlConfigurationOptions options = tree.options();
    options.platform.loader = fic::platform::SysctlLoaderKind::ProcpsSystem;
    writeFile(tree.root / "etc/sysctl.d/zzzz.conf", "kernel.test = snippet\n");
    writeFile(tree.root / "etc/sysctl.conf",
              "kernel.test = first\n; comment\nkernel.test = main\n");

    const auto observation = loaded(options).inspect("kernel.test");
    require(observation.found && observation.value == "main",
            "/etc/sysctl.conf must override sysctl.d only for procps-system semantics");
    require(observation.source.path == tree.root / "etc/sysctl.conf" &&
                observation.source.line == 3,
            "wrong location for last assignment in main file");
}

void testSystemdIgnoresSysctlConfForBootEffectiveValue() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.conf", "net.ipv4.ip_forward = 1\n");
    writeFile(tree.root / "etc/sysctl.d/zzzz-fic.conf", "net.ipv4.ip_forward = 0\n");

    SysctlConfiguration configuration = loaded(tree.options());
    const auto observation = configuration.inspect("net.ipv4.ip_forward");
    require(observation.found && observation.value == "0",
            "systemd-sysctl boot-effective value must ignore /etc/sysctl.conf");
    require(observation.source.path == tree.root / "etc/sysctl.d/zzzz-fic.conf",
            "systemd-sysctl source must be the managed sysctl.d file");

    const std::string before = readFile(tree.root / "etc/sysctl.conf");
    const SysctlOperationResult result =
        configuration.ensureManagedValue("net.ipv4.ip_forward", "0");
    require(result.ok && !result.changed,
            "matching systemd boot-effective value must be idempotent");
    require(readFile(tree.root / "etc/sysctl.conf") == before,
            "/etc/sysctl.conf must remain untouched under systemd semantics");
}

void testSlashNotationAndIgnoredFailurePrefix() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/10-notation.conf",
              "-net/ipv4/ip_forward = 0\n");

    const auto observation = loaded(tree.options()).inspect("net.ipv4.ip_forward");
    require(observation.found && observation.value == "0",
            "slash notation and leading ignore-failure marker must normalize");
}

void testGlobAssignmentAndExclusion() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/50-default.conf",
              "net.ipv4.conf.*.rp_filter = 2\n"
              "-net.ipv4.conf.all.rp_filter\n");

    SysctlConfiguration configuration = loaded(tree.options());
    require(configuration.inspect("net.ipv4.conf.ens18.rp_filter").value == "2",
            "glob assignment must apply to a matching exact key");
    require(!configuration.inspect("net.ipv4.conf.all.rp_filter").found,
            "an exclusion without '=' must suppress matching glob assignments");
}

void testExplicitAssignmentIsNotOverriddenByGlob() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/10-explicit.conf",
              "net.ipv4.conf.all.rp_filter = 1\n");
    writeFile(tree.root / "usr/lib/sysctl.d/90-glob.conf",
              "net.ipv4.conf.*.rp_filter = 2\n");

    const auto observation = loaded(tree.options()).inspect("net.ipv4.conf.all.rp_filter");
    require(observation.found && observation.value == "1",
            "an explicit assignment must exclude the key from glob matching");
}

void testDevNullMaskSuppressesVendorFile() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/40-vendor.conf", "kernel.test = vendor\n");
    std::filesystem::create_symlink("/dev/null", tree.root / "etc/sysctl.d/40-vendor.conf");

    const auto observation = loaded(tree.options()).inspect("kernel.test");
    require(!observation.found, "a higher-priority /dev/null mask must suppress vendor file");
}

void testRegularForeignSymlinkIsParsed() {
    TemporaryTree tree;
    writeFile(tree.root / "target.conf", "kernel.test = symlink\n");
    std::filesystem::create_symlink(tree.root / "target.conf",
                                    tree.root / "etc/sysctl.d/70-linked.conf");

    const auto observation = loaded(tree.options()).inspect("kernel.test");
    require(observation.found && observation.value == "symlink",
            "regular foreign sysctl.d symlink target must be parsed");
    require(observation.source.displayPath.find(" -> ") != std::string::npos,
            "symlink diagnostics must show resolved target");
}

void testSystemdSysctlConfSymlinkIsOverriddenByFic() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.conf", "net.ipv4.ip_forward = 1\n");
    std::filesystem::create_symlink(tree.root / "etc/sysctl.conf",
                                    tree.root / "etc/sysctl.d/99-sysctl.conf");
    writeFile(tree.root / "etc/sysctl.d/zzzz-fic.conf", "net.ipv4.ip_forward = 0\n");

    const auto observation = loaded(tree.options()).inspect("net.ipv4.ip_forward");
    require(observation.found && observation.value == "0",
            "FIC managed file must override active sysctl.conf symlink under systemd semantics");
    require(readFile(tree.root / "etc/sysctl.conf") == "net.ipv4.ip_forward = 1\n",
            "sysctl.conf target of foreign symlink must remain untouched");
}

void testUnsafeForeignSymlinkIsRejected() {
    TemporaryTree tree;
    std::filesystem::create_directories(tree.root / "linked-directory");
    std::filesystem::create_symlink(tree.root / "linked-directory",
                                    tree.root / "etc/sysctl.d/70-linked.conf");

    SysctlConfiguration configuration(tree.options());
    std::string error;
    require(!configuration.load(error),
            "foreign sysctl.d symlink to a directory must be rejected");
}

void testManagedSymlinkIsRejectedAndTargetUnchanged() {
    TemporaryTree tree;
    writeFile(tree.root / "target.conf", "kernel.test = target\n");
    std::filesystem::create_symlink(tree.root / "target.conf",
                                    tree.root / "etc/sysctl.d/zzzz-fic.conf");

    SysctlConfiguration configuration(tree.options());
    std::string error;
    require(!configuration.load(error), "managed sysctl file symlink must be rejected");
    require(readFile(tree.root / "target.conf") == "kernel.test = target\n",
            "managed symlink target must not be altered");
}

void testCorrectEffectiveValueDoesNotCreateManagedFile() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/10-vendor.conf", "kernel.test = expected\n");
    SysctlConfiguration configuration = loaded(tree.options());

    const SysctlOperationResult result = configuration.ensureManagedValue("kernel.test", "expected");
    require(result.ok && !result.changed, "already effective value must be idempotent");
    require(!std::filesystem::exists(tree.root / "etc/sysctl.d/zzzz-fic.conf"),
            "correct foreign effective value must not create FIC managed file");
}

void testManagedFileOverridesAndPreservesValues() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/90-vendor.conf", "kernel.alpha = wrong\n");
    writeFile(tree.root / "etc/sysctl.conf", "# administrator content\nkernel.alpha = old\n");

    SysctlConfiguration first = loaded(tree.options());
    const SysctlOperationResult firstResult = first.ensureManagedValue("kernel.alpha", "one");
    require(firstResult.ok && firstResult.changed, "first override must be written");

    SysctlConfiguration second = loaded(tree.options());
    const SysctlOperationResult secondResult = second.ensureManagedValue("kernel.beta", "two");
    require(secondResult.ok && secondResult.changed, "second managed value must be added");

    const std::string content = readFile(tree.root / "etc/sysctl.d/zzzz-fic.conf");
    require(readFile(tree.root / "etc/sysctl.conf") == "# administrator content\nkernel.alpha = old\n",
            "/etc/sysctl.conf must remain untouched during remediation");
    require(content.find("kernel.alpha = one") != std::string::npos &&
                content.find("kernel.beta = two") != std::string::npos,
            "managed file must preserve values from other policies");

    SysctlConfiguration verification = loaded(tree.options());
    require(verification.inspect("kernel.alpha").value == "one" &&
                verification.inspect("kernel.beta").value == "two",
            "managed assignments must be effective");

    const std::string before = content;
    const SysctlOperationResult idempotent =
        verification.ensureManagedValue("kernel.beta", "two");
    require(idempotent.ok && !idempotent.changed,
            "reapplying a managed value must be idempotent");
    require(readFile(tree.root / "etc/sysctl.d/zzzz-fic.conf") == before,
            "idempotent application must not rewrite content");
}

void testStaleManagedAssignmentIsRemoved() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.d/zzzz-fic.conf",
              "kernel.test = stale\nkernel.keep = value\n");
    writeFile(tree.root / "etc/sysctl.d/zzzzz-local.conf", "kernel.test = expected\n");

    SysctlConfiguration configuration = loaded(tree.options());
    const SysctlOperationResult result = configuration.ensureManagedValue("kernel.test", "expected");
    require(result.ok && result.changed,
            "stale managed assignment must be removed when effective value is already correct");

    const std::string managed = readFile(tree.root / "etc/sysctl.d/zzzz-fic.conf");
    require(managed.find("kernel.test") == std::string::npos &&
                managed.find("kernel.keep = value") != std::string::npos,
            "stale key must be removed without deleting unrelated managed values");
}

void testStaleManagedAssignmentRemovalRollback() {
    TemporaryTree tree;
    SysctlConfigurationOptions options = tree.options();
    options.platform.managedConfigPath = tree.root / "etc/sysctl.d/40-same.conf";
    writeFile(options.platform.managedConfigPath, "kernel.test = stale\n");
    std::filesystem::create_symlink(tree.root / "missing-target.conf",
                                    tree.root / "usr/lib/sysctl.d/40-same.conf");
    writeFile(tree.root / "etc/sysctl.d/99-local.conf", "kernel.test = expected\n");
    const std::string before = readFile(options.platform.managedConfigPath);

    SysctlConfiguration configuration = loaded(options);
    const SysctlOperationResult result = configuration.ensureManagedValue("kernel.test", "expected");
    require(!result.ok,
            "stale cleanup must fail if removing managed file activates invalid lower-priority source");
    require(readFile(options.platform.managedConfigPath) == before,
            "failed stale cleanup must restore managed file");
}

void testConflictingLaterSourceRollsBackManagedFile() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.d/zzzz-fic.conf", "kernel.test = stale\n");
    writeFile(tree.root / "etc/sysctl.d/zzzzz-local.conf", "kernel.test = administrator\n");
    const std::string beforeManaged = readFile(tree.root / "etc/sysctl.d/zzzz-fic.conf");
    const std::string beforeForeign = readFile(tree.root / "etc/sysctl.d/zzzzz-local.conf");

    SysctlConfiguration configuration = loaded(tree.options());
    const SysctlOperationResult result = configuration.ensureManagedValue("kernel.test", "expected");
    require(!result.ok, "later source must be reported as conflict");
    require(result.message.find("zzzzz-local.conf:1") != std::string::npos,
            "conflict diagnostics must include overriding source location");
    require(readFile(tree.root / "etc/sysctl.d/zzzz-fic.conf") == beforeManaged,
            "managed file must be rolled back after conflict");
    require(readFile(tree.root / "etc/sysctl.d/zzzzz-local.conf") == beforeForeign,
            "foreign conflicting file must remain untouched");
}

void testMalformedManagedFileFailsClosed() {
    TemporaryTree tree;
    const std::string original = "kernel.test = value\nthis is not valid\n";
    writeFile(tree.root / "etc/sysctl.d/zzzz-fic.conf", original);

    SysctlConfiguration configuration(tree.options());
    std::string error;
    require(!configuration.load(error), "invalid managed file must fail loading");
    require(readFile(tree.root / "etc/sysctl.d/zzzz-fic.conf") == original,
            "malformed managed file must remain untouched");
}

void testInvalidActiveConfigurationFailsLoad() {
    TemporaryTree tree;
    writeFile(tree.root / "run/sysctl.d/50-invalid.conf", "this is not an assignment\n");

    SysctlConfiguration configuration(tree.options());
    std::string error;
    require(!configuration.load(error), "invalid active sysctl line must fail loading");
    require(error.find("50-invalid.conf:1") != std::string::npos,
            "parse failure must include source location");
}

void testDottedInterfacePersistentKey() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/20-interface.conf",
              "net.ipv4.conf.enp3s0.200.forwarding = 1\n");

    SysctlConfiguration configuration = loaded(tree.options());
    require(configuration.inspect("net/ipv4/conf/enp3s0.200/forwarding").value == "1",
            "persistent parser must preserve dotted network interface names");
    require(configuration.inspect("net.ipv4.conf.enp3s0/200.forwarding").value == "1",
            "systemd slash/dot notation must match dotted interface names");
}

void testRuntimeValueAlreadyCorrect() {
    TemporaryTree tree;
    writeFile(tree.root / "proc/sys/kernel/test", "expected\n");

    SysctlRuntime runtime({tree.root / "proc/sys"});
    const SysctlRuntimeResult result = runtime.ensureValue("kernel.test", "expected");
    require(result.ok && !result.changed,
            "matching runtime value must be successful and idempotent");
}

void testRuntimeValueIsWrittenAndVerified() {
    TemporaryTree tree;
    writeFile(tree.root / "proc/sys/kernel/test", "old\n");

    SysctlRuntime runtime({tree.root / "proc/sys"});
    const SysctlRuntimeResult result = runtime.ensureValue("kernel.test", "expected");
    require(result.ok && result.changed, "runtime deviation must be corrected");

    std::string value;
    std::string error;
    require(runtime.readValue("kernel.test", value, error), error);
    require(value == "expected", "runtime value must be verified after writing");
}

void testRuntimeMissingParameterFails() {
    TemporaryTree tree;
    SysctlRuntime runtime({tree.root / "proc/sys"});

    const SysctlRuntimeResult result = runtime.ensureValue("kernel.missing", "1");
    require(!result.ok, "missing kernel parameter must not be treated as deferred success");
}

void testRuntimeRejectsUnsafeKeyAndValue() {
    TemporaryTree tree;
    writeFile(tree.root / "proc/sys/kernel/test", "old\n");
    SysctlRuntime runtime({tree.root / "proc/sys"});

    require(!runtime.ensureValue("../outside", "1").ok,
            "runtime key traversal must be rejected");
    require(!runtime.ensureValue("kernel.test", "one\ntwo").ok,
            "multiline runtime value must be rejected");
    require(readFile(tree.root / "proc/sys/kernel/test") == "old\n",
            "rejected runtime input must not modify the parameter");
}

void testRuntimeRejectsSymlinkParameter() {
    TemporaryTree tree;
    writeFile(tree.root / "outside", "old\n");
    std::filesystem::create_directories(tree.root / "proc/sys/kernel");
    std::filesystem::create_symlink(tree.root / "outside",
                                    tree.root / "proc/sys/kernel/test");
    SysctlRuntime runtime({tree.root / "proc/sys"});

    require(!runtime.ensureValue("kernel.test", "expected").ok,
            "runtime sysctl symlink must be rejected");
    require(readFile(tree.root / "outside") == "old\n",
            "symlink target must remain untouched");
}

void testRuntimeDottedInterfacePath() {
    TemporaryTree tree;
    writeFile(tree.root / "proc/sys/net/ipv4/conf/enp3s0.200/forwarding", "1\n");
    SysctlRuntime runtime({tree.root / "proc/sys"});

    std::string value;
    std::string error;
    require(runtime.readValue("net.ipv4.conf.enp3s0.200.forwarding", value, error), error);
    require(value == "1", "runtime dotted interface key must resolve to one path component");
    require(runtime.readValue("net.ipv4.conf.enp3s0/200.forwarding", value, error), error);
    require(value == "1", "runtime slash/dot notation must resolve dotted interface key");
}

} // namespace

int runManualMode(int argc, char* argv[]) {
    if (argc != 3 && argc != 4) {
        std::cerr << "usage: --inspect KEY | --ensure KEY VALUE\n";
        return 2;
    }
    SysctlConfiguration configuration;
    std::string error;
    if (!configuration.load(error)) {
        std::cerr << error << '\n';
        return 1;
    }
    if (std::string(argv[1]) == "--inspect" && argc == 3) {
        const SysctlValueObservation observation = configuration.inspect(argv[2]);
        if (!observation.found) {
            std::cout << "NOT_SET\n";
            return 0;
        }
        std::cout << observation.value << '\t' << observation.source.path.string()
                  << ':' << observation.source.line << '\n';
        return 0;
    }
    if (std::string(argv[1]) == "--ensure" && argc == 4) {
        const SysctlOperationResult result = configuration.ensureManagedValue(argv[2], argv[3]);
        std::cout << (result.ok ? "OK" : "ERROR") << '\t'
                  << (result.changed ? "CHANGED" : "UNCHANGED") << '\t'
                  << result.message << '\n';
        return result.ok ? 0 : 1;
    }
    std::cerr << "usage: --inspect KEY | --ensure KEY VALUE\n";
    return 2;
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        return runManualMode(argc, argv);
    }
    const std::vector<std::pair<const char*, void (*)()>> tests = {
        {"global lexical order", testGlobalLexicalOrder},
        {"same-name directory priority", testSameNameUsesHigherPriorityDirectory},
        {"suppressed invalid file", testSuppressedInvalidFileIsNotParsed},
        {"procps main file last", testProcpsMainFileIsLastOnlyForProcpsLoader},
        {"systemd ignores sysctl.conf", testSystemdIgnoresSysctlConfForBootEffectiveValue},
        {"slash notation", testSlashNotationAndIgnoredFailurePrefix},
        {"glob and exclusion", testGlobAssignmentAndExclusion},
        {"explicit beats glob", testExplicitAssignmentIsNotOverriddenByGlob},
        {"dev-null mask", testDevNullMaskSuppressesVendorFile},
        {"regular foreign symlink", testRegularForeignSymlinkIsParsed},
        {"sysctl.conf symlink overridden", testSystemdSysctlConfSymlinkIsOverriddenByFic},
        {"unsafe foreign symlink", testUnsafeForeignSymlinkIsRejected},
        {"managed symlink", testManagedSymlinkIsRejectedAndTargetUnchanged},
        {"correct value no managed write", testCorrectEffectiveValueDoesNotCreateManagedFile},
        {"managed file override", testManagedFileOverridesAndPreservesValues},
        {"stale managed removal", testStaleManagedAssignmentIsRemoved},
        {"stale cleanup rollback", testStaleManagedAssignmentRemovalRollback},
        {"later source conflict rollback", testConflictingLaterSourceRollsBackManagedFile},
        {"malformed managed file", testMalformedManagedFileFailsClosed},
        {"invalid active configuration", testInvalidActiveConfigurationFailsLoad},
        {"dotted interface persistent key", testDottedInterfacePersistentKey},
        {"runtime value already correct", testRuntimeValueAlreadyCorrect},
        {"runtime write and verify", testRuntimeValueIsWrittenAndVerified},
        {"runtime missing parameter", testRuntimeMissingParameterFails},
        {"runtime unsafe input", testRuntimeRejectsUnsafeKeyAndValue},
        {"runtime symlink", testRuntimeRejectsSymlinkParameter},
        {"runtime dotted interface path", testRuntimeDottedInterfacePath}
    };

    size_t failures = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS: " << name << '\n';
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "FAIL: " << name << ": " << exception.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}
