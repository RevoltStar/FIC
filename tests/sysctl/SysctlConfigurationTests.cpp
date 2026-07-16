#include "modules/sysctl/SysctlConfiguration.h"

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
        value.directories = {
            root / "etc/sysctl.d",
            root / "run/sysctl.d",
            root / "usr/local/lib/sysctl.d",
            root / "usr/lib/sysctl.d",
            root / "lib/sysctl.d"
        };
        value.mainPath = root / "etc/sysctl.conf";
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

void testMainFileIsLast() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.d/zzzz.conf", "kernel.test = snippet\n");
    writeFile(tree.root / "etc/sysctl.conf",
              "kernel.test = first\n; comment\nkernel.test = main\n");

    const auto observation = loaded(tree.options()).inspect("kernel.test");
    require(observation.found && observation.value == "main",
            "/etc/sysctl.conf must override every sysctl.d file");
    require(observation.source.path == tree.root / "etc/sysctl.conf" &&
                observation.source.line == 3,
            "wrong location for last assignment in main file");
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

void testCorrectEffectiveValueDoesNotCreateMainFile() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/10-vendor.conf", "kernel.test = expected\n");
    SysctlConfiguration configuration = loaded(tree.options());

    const SysctlOperationResult result = configuration.ensureManagedValue("kernel.test", "expected");
    require(result.ok && !result.changed, "already effective value must be idempotent");
    require(!std::filesystem::exists(tree.root / "etc/sysctl.conf"),
            "correct effective value must not create /etc/sysctl.conf");
}

void testManagedBlockOverridesAndPreservesValues() {
    TemporaryTree tree;
    writeFile(tree.root / "usr/lib/sysctl.d/90-vendor.conf", "kernel.alpha = wrong\n");
    writeFile(tree.root / "etc/sysctl.conf", "# administrator content\nkernel.alpha = old\n");

    SysctlConfiguration first = loaded(tree.options());
    const SysctlOperationResult firstResult = first.ensureManagedValue("kernel.alpha", "one");
    require(firstResult.ok && firstResult.changed, "first override must be written");

    SysctlConfiguration second = loaded(tree.options());
    const SysctlOperationResult secondResult = second.ensureManagedValue("kernel.beta", "two");
    require(secondResult.ok && secondResult.changed, "second managed value must be added");

    const std::string content = readFile(tree.root / "etc/sysctl.conf");
    require(content.find("# administrator content") != std::string::npos,
            "administrator content must be preserved");
    require(content.find("kernel.alpha = one") != std::string::npos &&
                content.find("kernel.beta = two") != std::string::npos,
            "managed block must preserve values from other policies");
    require(content.rfind("# END FIC MANAGED SYSCTL\n") ==
                content.size() - std::string("# END FIC MANAGED SYSCTL\n").size(),
            "managed block must be the final content of /etc/sysctl.conf");

    SysctlConfiguration verification = loaded(tree.options());
    require(verification.inspect("kernel.alpha").value == "one" &&
                verification.inspect("kernel.beta").value == "two",
            "managed assignments must be effective");

    const std::string before = content;
    const SysctlOperationResult idempotent =
        verification.ensureManagedValue("kernel.beta", "two");
    require(idempotent.ok && !idempotent.changed,
            "reapplying a managed value must be idempotent");
    require(readFile(tree.root / "etc/sysctl.conf") == before,
            "idempotent application must not rewrite content");
}

void testExistingManagedBlockMovesAfterAdministratorLines() {
    TemporaryTree tree;
    writeFile(tree.root / "etc/sysctl.conf",
              "# BEGIN FIC MANAGED SYSCTL\n"
              "kernel.test = stale\n"
              "# END FIC MANAGED SYSCTL\n"
              "kernel.test = administrator\n");

    SysctlConfiguration configuration = loaded(tree.options());
    const SysctlOperationResult result = configuration.ensureManagedValue("kernel.test", "expected");
    require(result.ok && result.changed, "managed block before later lines must be repaired");
    require(loaded(tree.options()).inspect("kernel.test").value == "expected",
            "moved managed block must become effective");
}

void testMalformedManagedBlockFailsClosed() {
    TemporaryTree tree;
    const std::string original =
        "# BEGIN FIC MANAGED SYSCTL\nkernel.test = value\n";
    writeFile(tree.root / "etc/sysctl.conf", original);

    SysctlConfiguration configuration = loaded(tree.options());
    const SysctlOperationResult result = configuration.ensureManagedValue("kernel.test", "expected");
    require(!result.ok, "unclosed managed block must fail closed");
    require(readFile(tree.root / "etc/sysctl.conf") == original,
            "malformed managed block must remain untouched");
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
        {"main file last", testMainFileIsLast},
        {"slash notation", testSlashNotationAndIgnoredFailurePrefix},
        {"glob and exclusion", testGlobAssignmentAndExclusion},
        {"explicit beats glob", testExplicitAssignmentIsNotOverriddenByGlob},
        {"dev-null mask", testDevNullMaskSuppressesVendorFile},
        {"correct value no write", testCorrectEffectiveValueDoesNotCreateMainFile},
        {"managed override", testManagedBlockOverridesAndPreservesValues},
        {"managed block moved last", testExistingManagedBlockMovesAfterAdministratorLines},
        {"malformed managed block", testMalformedManagedBlockFailsClosed},
        {"invalid active configuration", testInvalidActiveConfigurationFailsLoad}
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
