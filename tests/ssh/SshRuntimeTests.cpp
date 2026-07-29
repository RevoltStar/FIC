#include "modules/net/submodules/SshRuntime.h"
#include "modules/net/submodules/SshConfigFile.h"
#include "modules/net/submodules/SshConfigSyntax.h"

#include <fic/policy/Policy.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

namespace {

class TemporaryTree {
public:
    TemporaryTree() {
        std::string pattern = "/tmp/fic-ssh-runtime-tests-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = created;
    }

    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path executable(const std::string& name) const {
        const std::filesystem::path path = root / name;
        std::ofstream stream(path);
        stream << "#!/bin/sh\nexit 0\n";
        stream.close();
        ::chmod(path.c_str(), 0755);
        return path;
    }

    std::filesystem::path write(const std::filesystem::path& relative,
                                const std::string& content) const {
        const std::filesystem::path path = root / relative;
        std::filesystem::create_directories(path.parent_path());
        std::ofstream stream(path);
        stream << content;
        stream.close();
        return path;
    }

    std::string read(const std::filesystem::path& relative) const {
        std::ifstream stream(root / relative);
        return {
            std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>()
        };
    }

    std::filesystem::path root;
};

class FixedPolicyUnderTest : public Policy {
public:
    explicit FixedPolicyUnderTest(const std::filesystem::path& configDirectory) {
        moduleName = "NET";
        submoduleName = "SshEdit";
        policyName = "ssh_pubkey_auth";
        moduleConf = std::make_unique<ModuleConfigFileHandler>(configDirectory, moduleName);
        moduleConf->loadConfig();
        policyTypeValue = std::make_unique<FixedPolicyTypeValue>("yes");
    }

    bool apply() override {
        return true;
    }
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

ProcessResult success(std::string output = {}) {
    ProcessResult result;
    result.started = true;
    result.exitCode = 0;
    result.standardOutput = std::move(output);
    return result;
}

ProcessResult inactive() {
    ProcessResult result;
    result.started = true;
    result.exitCode = 3;
    return result;
}

SshRuntimeOptions options(const TemporaryTree& tree) {
    SshRuntimeOptions value;
    value.configPath = tree.root / "sshd_config";
    value.includeBasePath = tree.root;
    value.sshdCandidates = {tree.executable("sshd").string()};
    value.systemctlCandidates = {tree.executable("systemctl").string()};
    value.serviceUnits = {"ssh.service", "sshd.service"};
    return value;
}

void testFixedPubkeyValueRejectsOtherValues() {
    FixedPolicyTypeValue type("yes");

    require(type.getDefaultValue() == "yes",
            "the fixed public-key authentication value must default to yes");
    require(type.validate("yes"),
            "the fixed public-key authentication value must accept yes");
    require(!type.validate("no") && !type.validate("ENABLE"),
            "the fixed public-key authentication value must reject other values");

    const PolicyEditorSpec editor = type.getEditorSpec();
    require(editor.editor == "label",
            "a fixed public-key authentication value must remain read-only in clients");
}

void testFixedPubkeyValueSupportsExistingConfigs() {
    TemporaryTree tree;
    tree.write(
        "config/NET.conf",
        "ssh_port.status=DISABLE\n"
        "ssh_port.value=22\n"
        "ssh_pubkey_auth.status=ENABLE\n"
    );

    FixedPolicyUnderTest policy(tree.root / "config");
    require(!policy.hasConfiguredValue(),
            "an existing NET.conf must remain unchanged when the new value is absent");
    const std::optional<std::string> value = policy.getValue();
    require(value.has_value() && *value == "yes",
            "the intrinsic public-key value must support upgraded configurations");
}

void testDirectiveSyntaxSupportsEqualsSeparators() {
    const std::vector<std::string> lines = {
        "PermitRootLogin=yes",
        "PermitRootLogin =yes",
        "PermitRootLogin= yes",
        "PermitRootLogin = yes"
    };

    for (const std::string& line : lines) {
        const SshLineParseResult parsed = parseSshConfigLine(line);
        require(parsed.ok && parsed.hasDirective,
                "SSH directive with '=' must be parsed: " + line);
        require(normalizeSshKeyword(parsed.directive.keyword) == "permitrootlogin",
                "SSH keyword must not include '='");
        require(parsed.directive.arguments == std::vector<std::string>({"yes"}),
                "SSH value after '=' must be preserved");
    }
}

void testQuotedKeywordsAreRecognized() {
    const SshLineParseResult parsed =
        parseSshConfigLine("\"PermitRootLogin\" yes");
    require(parsed.ok && parsed.hasDirective,
            "a double-quoted SSH keyword must be parsed");
    require(normalizeSshKeyword(parsed.directive.keyword) == "permitrootlogin",
            "quotes must not remain part of the SSH keyword");
    require(parsed.directive.arguments == std::vector<std::string>({"yes"}),
            "arguments after a quoted SSH keyword must be preserved");
}

void testConfigFileHandlerUsesSharedSyntaxWithoutRewritingIncludes() {
    TemporaryTree tree;
    const std::filesystem::path config = tree.write(
        "sshd_config",
        "Include=sshd_config.d/01.conf\n"
        "Include sshd_config.d/02.conf\n"
        "PermitRootLogin=yes\n"
        "Match=User root\n"
        "    PermitRootLogin no\n"
    );

    SshConfigFileHandler handler(config.string());
    require(handler.loadConfig(), "SSH configuration handler must load '=' syntax");
    require(handler.getValue("PermitRootLogin") == "yes",
            "global SSH value using '=' must be visible to the handler");
    require(handler.setValue("PermitRootLogin", "prohibit-password"),
            "global SSH value using '=' must be updatable");
    require(handler.saveFile(), "updated SSH configuration must be saved");

    const std::string content = tree.read("sshd_config");
    require(content.find("Include=sshd_config.d/01.conf") != std::string::npos &&
            content.find("Include sshd_config.d/02.conf") != std::string::npos,
            "updating a policy must preserve repeated unrelated Include directives");
    require(content.find("PermitRootLogin prohibit-password") != std::string::npos,
            "the global SSH value must be rewritten");
    require(content.find("    PermitRootLogin no") != std::string::npos,
            "a conditional value after Match= must remain unchanged");
}

void testEffectiveValuesUseAllSshdOutput() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>& arguments,
           const ProcessOptions&) {
            require(arguments.size() == 3 && arguments[0] == "-T" && arguments[1] == "-f",
                    "sshd must be invoked in extended test mode");
            return success("port 2222\nport 22\npermitrootlogin prohibit-password\n");
        }
    );

    std::vector<std::string> values;
    std::string error;
    require(runtime.effectiveValues("Port", values, error), error);
    require(values == std::vector<std::string>({"2222", "22"}),
            "all effective SSH values must be returned");
}

void testMultipleEffectivePortsAreRejected() {
    TemporaryTree tree;
    tree.write("sshd_config", "Port 2222\n");
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("port 2222\nport 22\nlistenaddress 0.0.0.0:2222\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("Port", "2222", error),
            "an additional effective SSH port must fail verification");
    require(error.find("2222, 22") != std::string::npos ||
            error.find("22, 2222") != std::string::npos,
            "port failure must identify all effective ports");
}

void testListenAddressPortIsVerified() {
    TemporaryTree tree;
    tree.write("sshd_config", "Port 2222\nListenAddress 127.0.0.1:22\n");
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("port 2222\nlistenaddress 127.0.0.1:22\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("Port", "2222", error),
            "ListenAddress must not bypass the expected SSH port");
    require(error.find("ListenAddress") != std::string::npos,
            "ListenAddress failure must be diagnostic");
}

void testWeakerMatchOverrideIsRejected() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "PermitRootLogin no\n"
        "Match User root\n"
        "    PermitRootLogin yes\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin no\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("PermitRootLogin", "no", error),
            "a weaker Match override must fail verification");
    require(error.find("Match User root") != std::string::npos,
            "Match failure must identify the condition");
}

void testEqualsConditionalOverrideIsRejected() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "PermitRootLogin no\n"
        "Match=User root\n"
        "    PermitRootLogin=yes\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin no\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("PermitRootLogin", "no", error),
            "a conditional override using '=' must not bypass verification");
    require(error.find("Match User root") != std::string::npos,
            "Match parsed through '=' must remain diagnostic");
}

void testQuotedConditionalOverrideIsRejected() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "PermitRootLogin no\n"
        "\"Match\" User root\n"
        "    \"PermitRootLogin\" yes\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin no\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("PermitRootLogin", "no", error),
            "quoted keywords must not bypass conditional verification");
}

void testStricterMatchOverrideIsAccepted() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "PermitRootLogin prohibit-password\n"
        "Match User root\n"
        "    PermitRootLogin forced-commands-only\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin prohibit-password\n");
        }
    );

    std::string error;
    require(runtime.verifyPolicyValue("PermitRootLogin", "prohibit-password", error),
            error);
}

void testPermitRootLoginAliasesAreEquivalent() {
    TemporaryTree tree;
    tree.write("sshd_config", "PermitRootLogin prohibit-password\n");
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin without-password\n");
        }
    );

    std::string error;
    require(runtime.verifyPolicyValue("PermitRootLogin", "prohibit-password", error),
            "OpenSSH's without-password alias must satisfy prohibit-password: " + error);
}

void testDifferentPermitRootLoginValuesAreNotEquivalent() {
    TemporaryTree tree;
    tree.write("sshd_config", "PermitRootLogin prohibit-password\n");
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin forced-commands-only\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("PermitRootLogin", "prohibit-password", error),
            "a different global PermitRootLogin restriction must not be treated as an alias");
}

void testDisabledPubkeyAuthenticationInMatchIsRejected() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "PubkeyAuthentication yes\n"
        "Match Group legacy\n"
        "    PubkeyAuthentication no\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("pubkeyauthentication yes\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("PubkeyAuthentication", "yes", error),
            "a Match override must not disable public-key authentication");
    require(error.find("PubkeyAuthentication") != std::string::npos &&
            error.find("Match Group legacy") != std::string::npos,
            "a public-key authentication override must identify the parameter and Match");
}

void testIncludedMatchOverrideIsRejected() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "MaxAuthTries 3\n"
        "Include sshd_config.d/*.conf\n"
    );
    tree.write(
        "sshd_config.d/override.conf",
        "Match Address 192.0.2.0/24\n"
        "    MaxAuthTries 5\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("maxauthtries 3\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("MaxAuthTries", "3", error),
            "a weaker override from Include must fail verification");
    require(error.find("override.conf:2") != std::string::npos,
            "included override failure must identify its source");
}

void testEqualsIncludeIsAudited() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "MaxAuthTries 3\n"
        "Include=sshd_config.d/*.conf\n"
    );
    tree.write(
        "sshd_config.d/override.conf",
        "Match Address 192.0.2.0/24\n"
        "    MaxAuthTries=5\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("maxauthtries 3\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("MaxAuthTries", "3", error),
            "an Include using '=' must not bypass conditional auditing");
    require(error.find("override.conf:2") != std::string::npos,
            "override reached through Include= must identify its source");
}

void testNestedIncludedMatchOverrideIsRejected() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "PermitRootLogin no\n"
        "Include sshd_config.d/first.conf\n"
    );
    tree.write(
        "sshd_config.d/first.conf",
        "Include sshd_config.d/nested/*.conf\n"
    );
    tree.write(
        "sshd_config.d/nested/override.conf",
        "Match Group administrators\n"
        "    PermitRootLogin yes\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin no\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("PermitRootLogin", "no", error),
            "a nested included Match override must fail verification");
    require(error.find("nested/override.conf:2") != std::string::npos,
            "nested override failure must identify its source");
}

void testIncludedMatchStateDoesNotLeak() {
    TemporaryTree tree;
    tree.write(
        "sshd_config",
        "PermitRootLogin no\n"
        "Include sshd_config.d/*.conf\n"
    );
    tree.write(
        "sshd_config.d/01-match.conf",
        "Match User alice\n"
        "    MaxAuthTries 2\n"
    );
    tree.write(
        "sshd_config.d/02-global.conf",
        "PermitRootLogin yes\n"
    );
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin no\n");
        }
    );

    std::string error;
    require(runtime.verifyPolicyValue("PermitRootLogin", "no", error),
            "Match state from one included file must not affect the next file: " + error);
}

void testMultipleScalarEffectiveValuesAreRejected() {
    TemporaryTree tree;
    tree.write("sshd_config", "MaxAuthTries 3\n");
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("maxauthtries 3\nmaxauthtries 2\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("MaxAuthTries", "3", error),
            "multiple effective values for a scalar policy must fail closed");
    require(error.find("2 effective values") != std::string::npos,
            "ambiguous scalar failure must be diagnostic");
}

void testRecursiveIncludeFailsClosed() {
    TemporaryTree tree;
    tree.write("sshd_config", "PermitRootLogin no\nInclude loop.conf\n");
    tree.write("loop.conf", "Include sshd_config\n");
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return success("permitrootlogin no\n");
        }
    );

    std::string error;
    require(!runtime.verifyPolicyValue("PermitRootLogin", "no", error),
            "a recursive Include graph must fail closed");
    require(error.find("recursive SSH Include") != std::string::npos,
            "recursive Include failure must be diagnostic");
}

void testInactiveServiceDoesNotRequireReload() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            return inactive();
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(result.ok && !result.serviceActive && !result.reloaded,
            "inactive SSH service must not require runtime reload");
}

void testActiveServiceIsReloadedAndVerified() {
    TemporaryTree tree;
    int reloads = 0;
    SshRuntime runtime(
        options(tree),
        [&reloads](const std::string&,
                   const std::vector<std::string>& arguments,
                   const ProcessOptions&) {
            if (!arguments.empty() && arguments[0] == "reload") {
                ++reloads;
            }
            return success();
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(result.ok && result.serviceActive && result.reloaded,
            "active SSH service must be reloaded");
    require(reloads == 1, "SSH service must be reloaded exactly once");
}

void testReloadFailureIsReported() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>& arguments,
           const ProcessOptions&) {
            if (!arguments.empty() && arguments[0] == "reload") {
                ProcessResult result;
                result.started = true;
                result.exitCode = 1;
                result.standardError = "reload rejected";
                return result;
            }
            return success();
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(!result.ok && result.serviceActive && !result.reloaded,
            "reload failure must make SSH activation unsuccessful");
}

void testServiceInspectionFailureIsReported() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        [](const std::string&,
           const std::vector<std::string>&,
           const ProcessOptions&) {
            ProcessResult result;
            result.started = true;
            result.exitCode = 1;
            result.standardError = "systemd unavailable";
            return result;
        }
    );

    const SshActivationResult result = runtime.activateIfRunning();
    require(!result.ok && !result.serviceActive,
            "systemctl failure must not be treated as an inactive SSH service");
}

} // namespace

int main() {
    const std::vector<std::pair<const char*, void (*)()>> tests = {
        {"fixed pubkey value", testFixedPubkeyValueRejectsOtherValues},
        {"existing config pubkey value", testFixedPubkeyValueSupportsExistingConfigs},
        {"equals directive syntax", testDirectiveSyntaxSupportsEqualsSeparators},
        {"quoted keyword syntax", testQuotedKeywordsAreRecognized},
        {"shared config file syntax", testConfigFileHandlerUsesSharedSyntaxWithoutRewritingIncludes},
        {"effective values", testEffectiveValuesUseAllSshdOutput},
        {"multiple ports", testMultipleEffectivePortsAreRejected},
        {"listen address port", testListenAddressPortIsVerified},
        {"weaker Match", testWeakerMatchOverrideIsRejected},
        {"equals conditional Match", testEqualsConditionalOverrideIsRejected},
        {"quoted conditional Match", testQuotedConditionalOverrideIsRejected},
        {"stricter Match", testStricterMatchOverrideIsAccepted},
        {"PermitRootLogin aliases", testPermitRootLoginAliasesAreEquivalent},
        {"different PermitRootLogin values", testDifferentPermitRootLoginValuesAreNotEquivalent},
        {"disabled pubkey Match", testDisabledPubkeyAuthenticationInMatchIsRejected},
        {"included Match", testIncludedMatchOverrideIsRejected},
        {"equals Include", testEqualsIncludeIsAudited},
        {"nested included Match", testNestedIncludedMatchOverrideIsRejected},
        {"included Match isolation", testIncludedMatchStateDoesNotLeak},
        {"multiple scalar values", testMultipleScalarEffectiveValuesAreRejected},
        {"recursive Include", testRecursiveIncludeFailsClosed},
        {"inactive service", testInactiveServiceDoesNotRequireReload},
        {"active reload", testActiveServiceIsReloadedAndVerified},
        {"reload failure", testReloadFailureIsReported},
        {"service inspection failure", testServiceInspectionFailureIsReported}
    };

    std::size_t failures = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "FAIL: " << name << ": " << exception.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}
