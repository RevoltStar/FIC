#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "incident/SshIncidentPamBridgeVerifier.h"
#include "incident/SshAccessContainmentBackend.h"

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
    if (output.find("ExecStart={") != std::string::npos) {
        for (const char* property : {"Type=simple\n", "ExecCondition=\n",
                                     "ExecStartPre=\n", "ExecStartPost=\n",
                                     "ExecReload=\n", "CanReload=no\n",
                                     "ReloadResult=success\n",
                                     "NotifyAccess=main\n"}) {
            const std::string entry(property);
            const auto equal = entry.find('=');
            if (output.find(entry.substr(0, equal + 1)) == std::string::npos)
                output += entry;
        }
    }
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

void testNarrowIncidentSshBridge() {
    TemporaryTree tree;
    const auto config = tree.write("sshd_config", "UsePAM yes\nPAMServiceName sshd\n");
    const auto options = tree.write("default/ssh", "SSHD_OPTS=\n");
    fic::platform::SshPlatformConfig platform;
    platform.configPath = config;
    platform.includeBasePath = tree.root;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    platform.optionVariable = "SSHD_OPTS";
    platform.optionFile = options;
    const auto sshd = (tree.root / "sshd").string();
    (void)tree.executables();
    int restarts = 0;
    bool active = true;
    std::string environment;
    std::string managerEnvironment = "LANG=C.UTF-8\nPATH=/usr/bin:/bin\n";
    bool managerUnavailable = false;
    bool changeManagerOnRestart = false;
    bool legacyPamRouting = false;
    std::string execArgs = " -D $SSHD_OPTS";
    std::string effective = "usepam yes\npamservicename sshd\n";
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        if (!args.empty() && args.front() == "restart") {
            ++restarts;
            if (changeManagerOnRestart)
                managerEnvironment = "LANG=en_US.UTF-8\nPATH=/usr/bin:/bin\n";
            return success();
        }
        if (args == std::vector<std::string>{"--system", "show-environment"}) {
            if (managerUnavailable) {
                ProcessResult result;
                result.started = true;
                result.exitCode = 1;
                return result;
            }
            return success(managerEnvironment);
        }
        if (legacyPamRouting && !args.empty() && args.front() == "-T" &&
            std::find(args.begin(), args.end(),
                      "PAMServiceName=fic-capability-probe") != args.end()) {
            ProcessResult result;
            result.started = true;
            result.exitCode = 1;
            result.standardError = "Bad configuration option: PAMServiceName";
            return result;
        }
        if (!args.empty() && args.front() == "show") {
            if (args.back() == "ssh.socket")
                return success("LoadState=loaded\nActiveState=active\n"
                               "Accept=no\nTriggers=ssh.service\n");
            return success("Id=ssh.service\nLoadState=loaded\n"
                           "ActiveState=" + std::string(active ? "active" : "inactive") +
                           "\nMainPID=42\nType=notify\nDynamicUser=no\n"
                           "NoNewPrivileges=no\nEnvironment=" + environment +
                           "\nPassEnvironment=\nEnvironmentFiles=" +
                           options.string() + " (ignore_errors=yes)\n"
                           "ExecStart={ path=" + sshd + " ; argv[]=" + sshd +
                           execArgs + " ; ignore_errors=no }\n");
        }
        return success(effective);
    };
    const auto process = [&](unsigned int pid, const std::filesystem::path& path,
                             std::string&) { return pid == 42 && path == sshd; };
    std::string error;
    require(fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "stock future SSH proof failed: " + error);
    require(fic::incident::SshIncidentPamBridgeVerifier::activate(
                platform, tree.executables(), error, runner, process) && restarts == 1,
            "ACTIVE must restart stock active SSH once: " + error);
    require(fic::incident::SshIncidentPamBridgeVerifier::proveCurrent(
                platform, tree.executables(), error, runner, process) && restarts == 1,
            "healthy drift check must not restart SSH");
    managerEnvironment = "LANG=C.UTF-8\nLD_PRELOAD=/tmp/wrap.so\n";
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "manager-wide loader environment must fail closed");
    managerEnvironment = "LANG=C.UTF-8\nPATH=/usr/bin:/bin\n";
    managerEnvironment = "LANG=C.UTF-8\nSSHD_OPTS=-o UsePAM=no\n";
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "manager-wide SSH options must fail closed");
    managerEnvironment = "LANG=C.UTF-8\nPATH=/usr/bin:/bin\n";
    tree.write("sshd_config",
               "UsePAM yes\nPAMServiceName sshd\n"
               "Match User alice\n    PAMServiceName custom\n");
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "conditional PAMServiceName override must fail closed");
    tree.write("sshd_config", "UsePAM yes\nPAMServiceName sshd\n"
                              "Include sshd_config.d/outer.conf\n");
    tree.write("sshd_config.d/outer.conf",
               "Match User alice\nInclude sshd_config.d/nested.conf\n");
    tree.write("sshd_config.d/nested.conf", "PAMServiceName custom\n");
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "nested Include must not hide a conditional PAM route override");
    tree.write("sshd_config.d/nested.conf", "PAMServiceName sshd\n");
    require(fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "matching PAM route in every Match context must be proven: " + error);
    tree.write("sshd_config.d/outer.conf", "Include ../ambiguous.conf\n");
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "ambiguous Include must fail closed");
    tree.write("sshd_config", "UsePAM yes\nPAMServiceName sshd\n");
    managerEnvironment = "LANG=$'C.UTF-8'\n";
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "escaped manager environment must be unproven");
    managerEnvironment = "LANG=C.UTF-8";
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "truncated manager environment must be unproven");
    managerEnvironment = "LANG=C.UTF-8\nPATH=/usr/bin:/bin\n";
    managerUnavailable = true;
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "unavailable manager environment must be unproven");
    managerUnavailable = false;
    changeManagerOnRestart = true;
    restarts = 0;
    require(!fic::incident::SshIncidentPamBridgeVerifier::activate(
                platform, tree.executables(), error, runner, process) && restarts == 1,
            "environment change during restart must not yield READY");
    changeManagerOnRestart = false;
    managerEnvironment = "LANG=C.UTF-8\nPATH=/usr/bin:/bin\n";
    bool restoreCalled = false;
    require(fic::incident::SshIncidentPamBridgeVerifier::activateBlocked(
                platform, tree.executables(), error,
                [&](std::string&) { restoreCalled = true; active = true; return true; },
                runner, process) && restoreCalled,
            "blocked SSH may restore only after future proof: " + error);
    active = false;
    restoreCalled = false;
    managerEnvironment = "LD_PRELOAD=/tmp/wrap.so\n";
    require(!fic::incident::SshIncidentPamBridgeVerifier::activateBlocked(
                platform, tree.executables(), error,
                [&](std::string&) { restoreCalled = true; return true; },
                runner, process) && !restoreCalled,
            "unsafe manager environment must prevent SSH restoration");
    managerEnvironment = "LANG=C.UTF-8\nPATH=/usr/bin:/bin\n";
    require(!fic::incident::SshIncidentPamBridgeVerifier::activateBlocked(
                platform, tree.executables(), error,
                [&](std::string&) {
                    active = true;
                    managerEnvironment = "LANG=en_US.UTF-8\nPATH=/usr/bin:/bin\n";
                    return true;
                }, runner, process),
            "manager environment drift across restore must prevent READY");
    managerEnvironment = "LANG=C.UTF-8\nPATH=/usr/bin:/bin\n";
    active = true;
    effective = "usepam yes\n";
    legacyPamRouting = true;
    require(fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "legacy sshd capability probe must remain supported: " + error);
    legacyPamRouting = false;
    effective = "usepam yes\npamservicename sshd\n";
    environment = "LD_PRELOAD=/tmp/x.so";
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "loader environment must fail closed");
    environment.clear();
    execArgs = " -D -o UsePAM=no";
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "custom SSH options must fail closed");
    execArgs = " -D $SSHD_OPTS";
    effective = "usepam no\npamservicename sshd\n";
    require(!fic::incident::SshIncidentPamBridgeVerifier::proveFuture(
                platform, tree.executables(), error, runner),
            "UsePAM=no must fail closed");
    effective = "usepam yes\npamservicename sshd\n";
    active = false;
    restarts = 0;
    require(fic::incident::SshIncidentPamBridgeVerifier::activate(
                platform, tree.executables(), error, runner, process) && restarts == 0,
            "inactive SSH must not be started for proof");
}

void testSshAccessContainmentOwnership() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    bool serviceActive = true, socketActive = true;
    int stops = 0, starts = 0;
    std::vector<std::string> startOrder;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        const bool socket = args.back() == "ssh.socket";
        bool& state = socket ? socketActive : serviceActive;
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (state ? "active\n" : "inactive\n"));
        if (args.front() == "stop") { ++stops; state = false; return success(); }
        if (args.front() == "start") {
            ++starts;
            startOrder.push_back(args.back());
            state = true;
            return success();
        }
        return success();
    };
    fic::incident::SshAccessContainmentBackend guard(witness);
    std::string error;
    require(guard.block(platform, tree.executables(), error, runner) &&
            !serviceActive && !socketActive && stops == 2 && guard.ownsBlock(),
            "SSH guard must stop the declared active listener: " + error);
    require(guard.block(platform, tree.executables(), error, runner) && stops == 2,
            "repeated block must not claim extra actions");
    require(guard.restore(platform, tree.executables(), error, runner) &&
            serviceActive && socketActive && starts == 2 && !guard.ownsBlock() &&
            startOrder == std::vector<std::string>({"ssh.socket", "ssh.service"}),
            "SSH guard must restore only its own stops: " + error);
    serviceActive = false;
    socketActive = false;
    require(guard.block(platform, tree.executables(), error, runner) &&
            !guard.ownsBlock() && stops == 2,
            "already stopped listener must not become FIC-owned");
    require(guard.restore(platform, tree.executables(), error, runner) &&
            starts == 2, "pre-disabled SSH must remain stopped");

    serviceActive = true;
    socketActive = true;
    require(guard.block(platform, tree.executables(), error, runner),
            "second block must succeed: " + error);
    fic::incident::SshAccessContainmentBackend afterCrash(witness);
    require(afterCrash.restore(platform, tree.executables(), error, runner) &&
            serviceActive && socketActive,
            "a new backend must restore FIC-owned listeners after crash");

    // An activating listener can still accept connections. Stop it and prove
    // the final inactive state rather than treating the transition as safe.
    auto transitionalRunner = [&](const std::string&,
                                    const std::vector<std::string>& args,
                                    const ProcessOptions&) {
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (serviceActive ? "activating\n" : "inactive\n"));
        if (args.front() == "stop") { ++stops; serviceActive = false; }
        return success();
    };
    serviceActive = true;
    require(guard.block(platform, tree.executables(), error, transitionalRunner) &&
            !serviceActive && stops == 5 && guard.ownsBlock(),
            "transitional SSH listener must be stopped: " + error);
}

void testInitiallyFailedServiceIsNotOwned() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    bool socketActive = true;
    int serviceStarts = 0;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        const bool socket = args.back() == "ssh.socket";
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (socket ? (socketActive ? "active\n" : "inactive\n")
                                   : "failed\n"));
        if (socket && args.front() == "stop") socketActive = false;
        if (!socket && args.front() == "start") ++serviceStarts;
        if (socket && args.front() == "start") socketActive = true;
        return success();
    };
    fic::incident::SshAccessContainmentBackend guard(witness);
    std::string error;
    require(guard.block(platform, tree.executables(), error, runner) &&
                !socketActive && guard.ownsBlock(),
            "active SSH socket must be blocked beside failed service");
    require(guard.restore(platform, tree.executables(), error, runner) &&
                socketActive && serviceStarts == 0,
            "originally failed SSH service must not be owned or started");
}

void testDeactivatingServiceIsNotOwned() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    bool serviceInactive = false;
    int serviceStarts = 0;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        const bool service = args.back() == "ssh.service";
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (service ? (serviceInactive ? "inactive\n" : "deactivating\n")
                                    : "inactive\n"));
        if (service && args.front() == "stop") serviceInactive = true;
        if (service && args.front() == "start") ++serviceStarts;
        return success();
    };
    std::string error;
    fic::incident::SshAccessContainmentBackend guard(witness);
    require(guard.block(platform, tree.executables(), error, runner) &&
                serviceInactive && !guard.ownsBlock(),
            "deactivating SSH service must reach inactive without ownership");
    fic::incident::SshAccessContainmentBackend restarted(witness);
    require(restarted.restore(platform, tree.executables(), error, runner) &&
                serviceStarts == 0,
            "deactivating SSH service must not be started on restore");
}

void testActivatingServiceStopIsOwnedAfterProof() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    std::string serviceState = "activating";
    int starts = 0;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        const bool service = args.back() == "ssh.service";
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (service ? serviceState + "\n" : "inactive\n"));
        if (service && args.front() == "stop") serviceState = "inactive";
        if (service && args.front() == "start") {
            ++starts;
            serviceState = "active";
        }
        return success();
    };
    std::string error;
    fic::incident::SshAccessContainmentBackend guard(witness);
    require(guard.block(platform, tree.executables(), error, runner) &&
                serviceState == "inactive" && guard.ownsBlock(),
            "activating SSH service must be owned after confirmed stop");
    fic::incident::SshAccessContainmentBackend restarted(witness);
    require(restarted.restore(platform, tree.executables(), error, runner) &&
                starts == 1,
            "proven activating service stop must restore after crash");
}

void testSocketStopAlsoStopsOwnedService() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    bool socketActive = true, serviceActive = true;
    int serviceStops = 0;
    std::vector<std::string> starts;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        const bool socket = args.back() == "ssh.socket";
        bool& active = socket ? socketActive : serviceActive;
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (active ? "active\n" : "inactive\n"));
        if (args.front() == "stop") {
            active = false;
            if (socket) serviceActive = false; // real Ubuntu 24.04 topology
            else ++serviceStops;
        }
        if (args.front() == "start") {
            starts.push_back(args.back());
            active = true;
        }
        return success();
    };
    std::string error;
    fic::incident::SshAccessContainmentBackend guard(witness);
    require(guard.block(platform, tree.executables(), error, runner) &&
                !socketActive && !serviceActive && serviceStops == 0,
            "socket stop must capture its side effect on initially active service");
    fic::incident::SshAccessContainmentBackend restarted(witness);
    require(restarted.restore(platform, tree.executables(), error, runner) &&
                socketActive && serviceActive &&
                starts == std::vector<std::string>({"ssh.socket", "ssh.service"}),
            "socket and service ownership must survive crash in restore order");
}

void testWitnessCrashAmbiguity() {
    for (const bool stopWasPerformed : {false, true}) {
        TemporaryTree tree;
        fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
            tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
            ::getegid(), 0700};
        fic::platform::SshPlatformConfig platform;
        platform.serviceUnits = {"ssh.service"};
        platform.socketUnits = {"ssh.socket"};
        bool socketActive = true;
        int starts = 0;
        const auto runner = [&](const std::string&,
                                const std::vector<std::string>& args,
                                const ProcessOptions&) {
            if (args.front() == "show")
                return success(std::string("ActiveState=") +
                               (args.back() == "ssh.socket" && socketActive
                                    ? "active\n" : "inactive\n"));
            if (args.front() == "stop" && args.back() == "ssh.socket") {
                if (stopWasPerformed) socketActive = false;
                throw std::runtime_error("simulated daemon crash during stop");
            }
            if (args.front() == "start") ++starts;
            return success();
        };
        fic::incident::SshAccessContainmentBackend first(witness);
        std::string error;
        try {
            (void)first.block(platform, tree.executables(), error, runner);
            require(false, "injected crash must interrupt the stop");
        } catch (const std::runtime_error& exception) {
            require(std::string(exception.what()) ==
                        "simulated daemon crash during stop",
                    "unexpected stop exception");
        }
        fic::incident::SshAccessContainmentBackend restarted(witness);
        require(!restarted.restore(platform, tree.executables(), error, runner) &&
                    starts == 0 && error.find("ambiguous") != std::string::npos,
                "intent-only witness must never start a unit after crash");
    }
}

void testPartialStopKeepsCompletedAndAmbiguousOwnershipSeparate() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    bool socketActive = true;
    int starts = 0;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        const bool socket = args.back() == "ssh.socket";
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (socket && socketActive ? "active\n" :
                            socket ? "inactive\n" : "active\n"));
        if (args.front() == "stop" && socket) socketActive = false;
        if (args.front() == "stop" && !socket) {
            ProcessResult failed;
            failed.started = true;
            failed.exitCode = 1;
            return failed;
        }
        if (args.front() == "start") ++starts;
        return success();
    };
    std::string error;
    fic::incident::SshAccessContainmentBackend guard(witness);
    require(!guard.block(platform, tree.executables(), error, runner),
            "partial stop must not claim success");
    std::ifstream stream(witness.path);
    const std::string content((std::istreambuf_iterator<char>(stream)),
                              std::istreambuf_iterator<char>());
    require(content.find("socket ssh.socket stopped\n") != std::string::npos &&
            content.find("service ssh.service intent\n") != std::string::npos,
            "partial witness must distinguish completed socket from service intent");
    fic::incident::SshAccessContainmentBackend restarted(witness);
    require(!restarted.restore(platform, tree.executables(), error, runner) &&
                starts == 0 && error.find("ambiguous") != std::string::npos,
            "ambiguous partial stop must never trigger blind start");
}

void testWitnessDurabilityFailureNeverReportsReversibleBlock() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    bool active = true;
    int starts = 0;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (active ? "active\n" : "inactive\n"));
        if (args.front() == "stop") active = false;
        if (args.front() == "start") ++starts;
        return success();
    };
    struct HookReset {
        ~HookReset() { AtomicFileWriter::setDirectoryFsyncHookForTests({}); }
    } reset;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& path) { return path != witness.path.string(); });
    fic::incident::SshAccessContainmentBackend guard(witness);
    std::string error;
    require(!guard.block(platform, tree.executables(), error, runner) && !active,
            "undurable witness must fail and close declared SSH entry points");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    fic::incident::SshAccessContainmentBackend restarted(witness);
    require(!restarted.restore(platform, tree.executables(), error, runner) &&
                starts == 0,
            "undurable intent may not authorize blind restore after restart");
}

void testUntrustedAndStaleWitness() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "new-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    int starts = 0;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        if (args.front() == "show") return success("ActiveState=inactive\n");
        if (args.front() == "start") ++starts;
        return success();
    };
    const auto path = witness.path;
    const auto write = [&](const std::string& content) {
        std::ofstream stream(path, std::ios::trunc);
        stream << content;
        stream.close();
        ::chmod(path.c_str(), 0600);
    };
    std::string error;
    fic::incident::SshAccessContainmentBackend guard(witness);
    write("fic-ssh-block-v1\nboot=new-boot\nservice foreign.service stopped\n");
    require(!guard.restore(platform, tree.executables(), error, runner) && starts == 0,
            "unknown unit must not authorize start");
    write("broken witness\n");
    require(!guard.restore(platform, tree.executables(), error, runner) && starts == 0,
            "malformed witness must not authorize start");
    write("fic-ssh-block-v1\nboot=new-boot\nservice ssh.service stopped\n");
    ::chmod(path.c_str(), 0644);
    require(!guard.restore(platform, tree.executables(), error, runner) && starts == 0,
            "foreign witness metadata must not authorize start");
    std::filesystem::remove(path);
    std::filesystem::create_symlink("/etc/passwd", path);
    require(!guard.restore(platform, tree.executables(), error, runner) && starts == 0,
            "symlink witness must not authorize start");
    std::filesystem::remove(path);
    write("fic-ssh-block-v1\nboot=old-boot\nservice ssh.service stopped\n");
    require(guard.restore(platform, tree.executables(), error, runner) &&
                starts == 0 && !std::filesystem::exists(path),
            "stale boot witness must be discarded without starting SSH");
}

void testExternallyRestoredUnitDoesNotRestart() {
    TemporaryTree tree;
    fic::incident::SshAccessContainmentBackend::WitnessOptions witness{
        tree.root / "incident-ssh-block", "test-boot", ::geteuid(),
        ::getegid(), 0700};
    fic::platform::SshPlatformConfig platform;
    platform.serviceUnits = {"ssh.service"};
    platform.socketUnits = {"ssh.socket"};
    bool active = true;
    int starts = 0;
    const auto runner = [&](const std::string&, const std::vector<std::string>& args,
                            const ProcessOptions&) {
        if (args.front() == "show")
            return success(std::string("ActiveState=") +
                           (active ? "active\n" : "inactive\n"));
        if (args.front() == "stop") active = false;
        if (args.front() == "start") ++starts;
        return success();
    };
    fic::incident::SshAccessContainmentBackend first(witness);
    std::string error;
    require(first.block(platform, tree.executables(), error, runner), error);
    active = true; // independent administrator start before daemon recovery
    fic::incident::SshAccessContainmentBackend restarted(witness);
    require(restarted.restore(platform, tree.executables(), error, runner) &&
                starts == 0 && !std::filesystem::exists(witness.path),
            "already-active owned unit must clear witness without restart");
    require(restarted.restore(platform, tree.executables(), error, runner) &&
                starts == 0, "repeat restore must be idempotent");
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
        {"narrow incident SSH bridge", testNarrowIncidentSshBridge},
        {"SSH block ownership", testSshAccessContainmentOwnership},
        {"originally failed SSH service", testInitiallyFailedServiceIsNotOwned},
        {"deactivating SSH service", testDeactivatingServiceIsNotOwned},
        {"activating SSH service", testActivatingServiceStopIsOwnedAfterProof},
        {"socket stop owns service side effect", testSocketStopAlsoStopsOwnedService},
        {"crash ambiguity", testWitnessCrashAmbiguity},
        {"partial stop ownership", testPartialStopKeepsCompletedAndAmbiguousOwnershipSeparate},
        {"witness durability failure", testWitnessDurabilityFailureNeverReportsReversibleBlock},
        {"untrusted and stale witness", testUntrustedAndStaleWitness},
        {"externally restored unit", testExternallyRestoredUnitDoesNotRestart}
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
