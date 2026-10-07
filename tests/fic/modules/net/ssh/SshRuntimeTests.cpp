#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "incident/SshIncidentPamBridgeVerifier.h"

#include <fic/policy/Policy.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
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

    const fic::platform::PlatformExecutableResolver& executables() const {
        if (!executables_) {
            fic::platform::PlatformExecutables registry;
            registry.entries = {
                {
                    fic::platform::ExecutableId::Sshd,
                    {executable("sshd")}
                },
                {
                    fic::platform::ExecutableId::Systemctl,
                    {executable("systemctl")}
                }
            };
            fic::platform::PlatformExecutableResolverOptions resolverOptions;
            resolverOptions.enforceTrustedOwnership = false;
            executables_ =
                std::make_unique<fic::platform::PlatformExecutableResolver>(
                    std::move(registry), resolverOptions);
        }
        return *executables_;
    }

    std::filesystem::path root;
    mutable std::unique_ptr<fic::platform::PlatformExecutableResolver> executables_;
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
    // Direct global-section rewriting is intentionally refused: every FIC
    // mutation goes through FIC-managed blocks and the config transaction.
    require(!handler.setValue("PermitRootLogin", "prohibit-password"),
            "global SSH value must not be rewritable outside a managed block");
}

void testEffectiveValuesUseAllSshdOutput() {
    TemporaryTree tree;
    SshRuntime runtime(
        options(tree),
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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
        tree.executables(),
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

void testSshPamBridge() {
    TemporaryTree tree;
    const auto config = tree.write("sshd_config", "UsePAM yes\n");
    fic::platform::SshPlatformConfig platform;
    platform.configPath = config;
    platform.includeBasePath = tree.root;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    std::string error;
    const auto prove = [&](fic::platform::SshPamServiceRouting routing,
                           const std::string& output) {
        platform.pamServiceRouting = routing;
        return fic::incident::SshIncidentPamBridgeVerifier::prove(
            platform, tree.executables(), error,
            [&tree, output](const std::string&,
                            const std::vector<std::string>& arguments,
                            const ProcessOptions&) {
                if (!arguments.empty() && arguments.front() == "show" &&
                    arguments.back() == "ssh.socket") {
                    return success("LoadState=not-found\n");
                }
                if (!arguments.empty() && arguments.front() == "show") {
                    const std::string sshd = (tree.root / "sshd").string();
                    return success("Id=ssh.service\nLoadState=loaded\n"
                                   "ActiveState=inactive\nExecStart={ path=" +
                                   sshd + " ; argv[]=" + sshd +
                                   " -D ; ignore_errors=no }\n");
                }
                if (std::find(arguments.begin(), arguments.end(),
                              "PAMServiceName=fic-capability-probe") !=
                    arguments.end()) {
                    ProcessResult result;
                    result.started = true;
                    result.exitCode = 1;
                    result.standardError = "Bad configuration option: PAMServiceName";
                    return result;
                }
                return success(output);
            });
    };
    using Routing = fic::platform::SshPamServiceRouting;
    platform.pamServiceRouting = Routing::LegacyExecutableName;
    bool invoked = false;
    const auto optOut =
        fic::incident::SshIncidentPamBridgeVerifier::evaluateReadiness(
            false, platform, tree.executables(),
            [&invoked](const std::string&,
                       const std::vector<std::string>&,
                       const ProcessOptions&) {
                invoked = true;
                return success();
            });
    require(optOut.ready && optOut.optedOut && !invoked &&
                optOut.diagnostic.find("not guaranteed") != std::string::npos,
            "disabled ssh_use_pam must explicitly opt out without SSH probing");
    const auto failedReady =
        fic::incident::SshIncidentPamBridgeVerifier::evaluateReadiness(
            true, platform, tree.executables(),
            [](const std::string&, const std::vector<std::string>&,
               const ProcessOptions&) { return success("usepam no\n"); });
    require(!failedReady.ready && !failedReady.optedOut,
            "enabled ssh_use_pam with UsePAM=no must prevent READY");
    const auto sshdFailure =
        fic::incident::SshIncidentPamBridgeVerifier::evaluateReadiness(
            true, platform, tree.executables(),
            [](const std::string&, const std::vector<std::string>&,
               const ProcessOptions&) {
                ProcessResult result;
                result.started = true;
                result.exitCode = 1;
                result.standardError = "invalid sshd_config";
                return result;
            });
    require(!sshdFailure.ready && !sshdFailure.diagnostic.empty(),
            "inspection failure must prevent READY with a useful diagnostic");
    const auto provenReady =
        fic::incident::SshIncidentPamBridgeVerifier::evaluateReadiness(
            true, platform, tree.executables(),
            [&tree](const std::string&,
                    const std::vector<std::string>& arguments,
                    const ProcessOptions&) {
                if (!arguments.empty() && arguments.front() == "show" &&
                    arguments.back() == "ssh.socket") {
                    return success("LoadState=not-found\n");
                }
                if (!arguments.empty() && arguments.front() == "show") {
                    const std::string sshd = (tree.root / "sshd").string();
                    return success("Id=ssh.service\nLoadState=loaded\n"
                                   "ActiveState=inactive\nExecStart={ path=" +
                                   sshd + " ; argv[]=" + sshd +
                                   " -D ; ignore_errors=no }\n");
                }
                if (std::find(arguments.begin(), arguments.end(),
                              "PAMServiceName=fic-capability-probe") !=
                    arguments.end()) {
                    ProcessResult result;
                    result.started = true;
                    result.exitCode = 1;
                    result.standardError = "Bad configuration option: PAMServiceName";
                    return result;
                }
                return success("usepam yes\n");
            });
    require(provenReady.ready && !provenReady.optedOut,
            "enabled ssh_use_pam with proven bridge must allow READY");
    require(prove(Routing::LegacyExecutableName, "usepam yes\n"),
            "legacy service routing must not require PAMServiceName output");
    require(prove(Routing::ConfigurablePamServiceName, "usepam yes\n"),
            "actual legacy sshd must use legacy routing on a modern baseline");
    require(!prove(Routing::LegacyExecutableName, "usepam no\n"),
            "UsePAM=no must not prove SSH account processing");
    require(!prove(Routing::LegacyExecutableName, ""),
            "missing UsePAM output must fail closed");
    require(!prove(Routing::LegacyExecutableName, "usepam yes\nusepam no\n"),
            "multiple UsePAM values must fail closed");
    require(prove(Routing::LegacyExecutableName, "usepam YES\n"),
            "sshd boolean output is case insensitive");
    require(!prove(Routing::LegacyExecutableName,
                   "usepam yes\npamservicename custom\n"),
            "a modern trusted sshd must not bypass PAMServiceName on a legacy distro profile");
    platform.pamServiceRouting = Routing::LegacyExecutableName;
    require(!fic::incident::SshIncidentPamBridgeVerifier::prove(
                platform, tree.executables(), error,
                [&tree](const std::string&,
                        const std::vector<std::string>& arguments,
                        const ProcessOptions&) {
                    if (!arguments.empty() && arguments.front() == "show") {
                        const std::string sshd = (tree.root / "sshd").string();
                        return success("LoadState=loaded\nExecStart={ path=" +
                                       sshd + " ; argv[]=custom-sshd -D ; "
                                              "ignore_errors=no }\n");
                    }
                    return success("usepam yes\n");
                }),
            "legacy OpenSSH with custom argv[0] must not prove PAM service sshd");
    require(!fic::incident::SshIncidentPamBridgeVerifier::prove(
                platform, tree.executables(), error,
                [](const std::string&,
                   const std::vector<std::string>& arguments,
                   const ProcessOptions&) {
                    return success(!arguments.empty() &&
                                   arguments.front() == "show"
                        ? "LoadState=not-found\nExecStart=\n"
                        : "usepam yes\n");
                }),
            "legacy OpenSSH without a proven service unit must fail closed");
    require(prove(Routing::ConfigurablePamServiceName,
                  "usepam yes\npamservicename sshd\n"),
            "global sshd PAM service must prove the bridge");
    require(!prove(Routing::ConfigurablePamServiceName,
                   "usepam yes\npamservicename custom\n"),
            "custom global PAM service must fail closed");
    platform.pamServiceRouting = Routing::ConfigurablePamServiceName;
    const auto customServiceReady =
        fic::incident::SshIncidentPamBridgeVerifier::evaluateReadiness(
            true, platform, tree.executables(),
            [](const std::string&, const std::vector<std::string>&,
               const ProcessOptions&) {
                return success("usepam yes\npamservicename custom\n");
            });
    require(!customServiceReady.ready,
            "a custom PAM service must prevent READY");

    tree.write("sshd_config", "UsePAM yes\nMatch User alice\n"
                              "PAMServiceName custom\n");
    require(!prove(Routing::ConfigurablePamServiceName,
                   "usepam yes\npamservicename sshd\n"),
            "conditional custom PAM service must fail closed");
    tree.write("sshd_config", "UsePAM yes\nMatch Group admins\n"
                              "PAMServiceName sshd\n");
    require(prove(Routing::ConfigurablePamServiceName,
                  "usepam yes\npamservicename sshd\n"),
            "conditional sshd PAM service must be accepted");
    tree.write("sshd_config", "UsePAM yes\nInclude child.conf\n");
    tree.write("child.conf", "Match User alice\nInclude grandchild.conf\n");
    tree.write("grandchild.conf", "\"PAMServiceName\"=custom\n");
    require(!prove(Routing::ConfigurablePamServiceName,
                   "usepam yes\npamservicename sshd\n"),
            "nested conditional PAM service must fail closed");
    tree.write("sshd_config", "UsePAM yes\nInclude recursive.conf\n");
    tree.write("recursive.conf", "Include recursive.conf\n");
    require(!prove(Routing::ConfigurablePamServiceName,
                   "usepam yes\npamservicename sshd\n"),
            "a recursive include must fail closed");
    tree.write("sshd_config", "UsePAM yes\nMatch User alice\nUsePAM no\n");
    require(!prove(Routing::LegacyExecutableName, "usepam yes\n"),
            "invalid Match UsePAM must not be accepted by the real sshd");
}

void testSshActualActivationArguments() {
    TemporaryTree tree;
    const auto config = tree.write("sshd_config", "UsePAM yes\nPAMServiceName sshd\n");
    const auto alternate = tree.write("alternate", "UsePAM no\n");
    fic::platform::SshPlatformConfig platform;
    platform.configPath = config;
    platform.includeBasePath = tree.root;
    platform.serviceUnits = {"ssh.service", "sshd.service"};
    platform.socketUnits = {"ssh.socket"};
    platform.pamServiceRouting = fic::platform::SshPamServiceRouting::LegacyExecutableName;
    const std::string sshd = (tree.root / "sshd").string();
    (void)tree.executables();
    std::string environment;
    std::string rootDirectory;
    std::string unsetEnvironment;
    bool identityMismatch = false;
    bool pidDrift = false;
    bool startTimeDrift = false;
    bool secondService = false;
    const auto check = [&](const std::string& launchArgs,
                           const std::string& socketTarget,
                           const std::vector<std::string>& activeArgv,
                           bool expected) {
        std::string error;
        struct stat info {};
        require(::stat(sshd.c_str(), &info) == 0, "test sshd stat failed");
        int serviceShows = 0;
        int processReads = 0;
        const auto runner = [&](const std::string&,
                                const std::vector<std::string>& args,
                                const ProcessOptions&) {
            if (!args.empty() && args.front() == "show") {
                const std::string& unit = args.back();
                if (unit == "ssh.socket") {
                    return success("LoadState=loaded\nActiveState=active\n"
                                   "Accept=no\nTriggers=" + socketTarget + "\n");
                }
                if (unit == "sshd.service") {
                    if (!secondService) return success("LoadState=not-found\n");
                    return success("Id=sshd.service\nLoadState=loaded\n"
                                   "ActiveState=inactive\nExecStart={ path=" + sshd +
                                   " ; argv[]=" + sshd +
                                   " -D -o UsePAM=no ; ignore_errors=no }\n");
                }
                ++serviceShows;
                return success("Id=ssh.service\nNames=ssh.service sshd.service\n"
                               "LoadState=loaded\nActiveState=" +
                               std::string(activeArgv.empty() ? "inactive" : "active") +
                               "\nMainPID=" +
                               std::string(activeArgv.empty() ? "0" :
                                   (pidDrift && serviceShows > 1 ? "43" : "42")) +
                               "\nEnvironment=" + environment +
                               "\nRootDirectory=" + rootDirectory +
                               "\nUnsetEnvironment=" + unsetEnvironment +
                               "\nExecStart={ path=" + sshd + " ; argv[]=" +
                               sshd + launchArgs + " ; ignore_errors=no }\n");
            }
            const auto has = [&](const std::string& value) {
                return std::find(args.begin(), args.end(), value) != args.end();
            };
            if (has("UsePAM=no") || has(alternate.string()))
                return success("usepam no\npamservicename sshd\n");
            if (has("PAMServiceName=custom"))
                return success("usepam yes\npamservicename custom\n");
            return success("usepam yes\npamservicename sshd\n");
        };
        const auto reader = [&](unsigned int pid,
                                fic::incident::SshProcessSnapshot& snapshot,
                                std::string&) {
            if (pid != 42 || activeArgv.empty()) return false;
            snapshot.device = info.st_dev;
            snapshot.inode = info.st_ino + (identityMismatch ? 1 : 0);
            snapshot.startTime = ++processReads > 1 && startTimeDrift ? "101" : "100";
            snapshot.arguments = activeArgv;
            return true;
        };
        const bool actual = fic::incident::SshIncidentPamBridgeVerifier::prove(
            platform, tree.executables(), error, runner, reader);
        require(actual == expected, "activation proof mismatch: " + error);
    };
    check(" -D", "ssh.service", {}, true);
    check(" -D -o UsePAM=no", "ssh.service", {}, false);
    check(" -D -f " + alternate.string(), "ssh.service", {}, false);
    check(" -D -o PAMServiceName=custom", "ssh.service", {}, false);
    check(" -D -Z", "ssh.service", {}, false);
    environment = "SSHD_OPTS=\"-o UsePAM=no\"";
    check(" -D $SSHD_OPTS", "ssh.service", {}, false);
    environment = "EXTRAOPTIONS=\"-o UsePAM=no\"";
    check(" -D $EXTRAOPTIONS", "ssh.service", {}, false);
    environment.clear();
    check(" -D $SSHD_OPTS", "ssh.service", {}, false);
    rootDirectory = "/alternate-root";
    check(" -D", "ssh.service", {}, false);
    rootDirectory.clear();
    unsetEnvironment = "SSHD_OPTS";
    check(" -D", "ssh.service", {}, false);
    unsetEnvironment.clear();
    check(" -D", "custom.service", {}, false);
    secondService = true;
    check(" -D", "ssh.service", {}, false);
    secondService = false;
    check(" -D", "ssh.service", {sshd, "-D", "-o", "UsePAM=no"}, false);
    check(" -D -o UsePAM=no", "ssh.service", {sshd, "-D"}, true);
    identityMismatch = true;
    check(" -D", "ssh.service", {sshd, "-D"}, false);
    identityMismatch = false;
    pidDrift = true;
    check(" -D", "ssh.service", {sshd, "-D"}, false);
    pidDrift = false;
    startTimeDrift = true;
    check(" -D", "ssh.service", {sshd, "-D"}, false);
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
        {"service inspection failure", testServiceInspectionFailureIsReported},
        {"SSH PAM bridge", testSshPamBridge},
        {"SSH actual activation arguments", testSshActualActivationArguments}
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
