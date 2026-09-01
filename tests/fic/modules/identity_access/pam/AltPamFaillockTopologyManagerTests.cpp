#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"
#include "modules/identity_access/pam/AltPamPasswordHistoryTopologyManager.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamProviderInspector.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using fic::identity::pam::AltPamFaillockTopologyManager;
using fic::identity::pam::AltPamFaillockTopologyOptions;
using fic::identity::pam::AltPamFaillockTopologyState;
using fic::identity::pam::AltPamPasswordHistoryTopologyManager;
using fic::identity::pam::AltPamPasswordHistoryTopologyOptions;
using fic::identity::pam::PamTopologyManager;
using fic::identity::pam::PamTopologyState;
using fic::identity::pam::PamTopologyStatus;

namespace {

const std::string kCanonical =
    "#%PAM-1.0\n"
    "auth\t\trequired\tpam_tcb.so shadow fork nullok\n"
    "account\t\trequired\tpam_tcb.so shadow fork\n"
    "password\trequired\tpam_passwdqc.so config=/etc/passwdqc.conf\n"
    "password\trequired\tpam_tcb.so use_authtok shadow fork nullok write_to=tcb\n"
    "session\t\trequired\tpam_tcb.so\n";

class TemporaryTree {
public:
    TemporaryTree() {
        std::string pattern =
            (fs::temp_directory_path() / "fic-alt-pam-topology-XXXXXX").string();
        char* created = ::mkdtemp(pattern.data());
        if (created == nullptr) {
            throw std::runtime_error("cannot create temporary tree");
        }
        root = created;
        fs::create_directories(root / "pam.d");
        fs::create_directories(root / "security-modules");
        fs::create_directories(root / "run");
        write(root / "pam.d/system-auth-local",
              "auth include system-auth-local-only\n"
              "account include system-auth-local-only\n"
              "password include system-auth-local-only\n"
              "session include system-auth-local-only\n");
        fs::create_symlink("system-auth-local", root / "pam.d/system-auth");
        write(root / "pam.d/system-policy-local", "#%PAM-1.0\n");
        fs::create_symlink(
            "system-policy-local", root / "pam.d/system-policy");
        write(root / "pam.d/system-auth-local-only", kCanonical);
        write(root / "security-modules/pam_faillock.so", "fixture\n", 0555);
    }

    ~TemporaryTree() {
        std::error_code ignored;
        fs::remove_all(root, ignored);
    }

    static void write(const fs::path& path,
                      const std::string& content,
                      mode_t mode = 0644) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output.is_open()) {
            throw std::runtime_error("cannot write " + path.string());
        }
        output << content;
        output.close();
        ::chmod(path.c_str(), mode);
    }

    static std::string read(const fs::path& path) {
        std::ifstream input(path, std::ios::binary);
        return std::string(
            std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>());
    }

    fic::platform::PamPlatformConfig platform() const {
        fic::platform::PamPlatformConfig result;
        result.configDirectories = {root / "pam.d"};
        result.moduleDirectories = {root / "security-modules"};
        result.scopes = {
            {fic::platform::PamScope::EffectiveAuthenticationStack,
             {"system-auth"}},
            {fic::platform::PamScope::EffectivePasswordStack,
             {"system-auth"}},
            {fic::platform::PamScope::LocalPasswordChange,
             {"system-auth-local-only"}}
        };
        result.capabilities = {
            {fic::platform::PamCapability::AuthenticationLockout,
             fic::platform::PamProviderKind::PamFaillock,
             fic::platform::PamScope::EffectiveAuthenticationStack,
             "/etc/security/faillock.conf",
             fic::platform::PamTopologyStrategyKind::AltTcbManaged,
             {}},
            {fic::platform::PamCapability::PasswordQuality,
             fic::platform::PamProviderKind::PamPasswdqc,
             fic::platform::PamScope::LocalPasswordChange,
             root / "passwdqc.conf",
             fic::platform::PamTopologyStrategyKind::StaticReadOnly, {}}
        };
        result.capabilities.front().managedTopologyTargets = {
            {root / "pam.d/system-auth-local-only",
             fic::platform::PamManagedTopologyTargetRole::
                 AuthenticationAndAccount}
        };
        result.trustedServiceAliases = {
            {root / "pam.d/system-auth",
             {root / "pam.d/system-auth-local"}},
            {root / "pam.d/system-policy",
             {root / "pam.d/system-policy-local"}}
        };
        return result;
    }

    AltPamFaillockTopologyOptions options() const {
        AltPamFaillockTopologyOptions result;
        result.lockFilePath = root / "run/pam-faillock.lock";
        result.lockDebugLogPath = root / "lock-debug.log";
        return result;
    }

    fs::path target() const {
        return root / "pam.d/system-auth-local-only";
    }

    fs::path root;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::size_t count(const std::string& value, const std::string& needle) {
    std::size_t result = 0;
    std::size_t offset = 0;
    while ((offset = value.find(needle, offset)) != std::string::npos) {
        ++result;
        offset += needle.size();
    }
    return result;
}

std::string enabledFixture() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    return TemporaryTree::read(tree.target());
}

void writeSshUseFirstPassGraph(TemporaryTree& tree) {
    TemporaryTree::write(
        tree.root / "pam.d/sshd",
        "auth include common-login-use_first_pass\n"
        "account include common-login\n");
    TemporaryTree::write(
        tree.root / "pam.d/common-login-use_first_pass",
        "auth substack system-auth-use_first_pass\n");
    TemporaryTree::write(
        tree.root / "pam.d/common-login",
        "account substack system-auth\n");
    TemporaryTree::write(
        tree.root / "pam.d/system-auth-use_first_pass-local",
        "auth include system-auth-use_first_pass-local-only\n");
    TemporaryTree::write(
        tree.root / "pam.d/system-auth-use_first_pass-local-only",
        "#%PAM-1.0\n"
        "auth required pam_tcb.so shadow fork nullok use_first_pass\n"
        "password required pam_tcb.so use_authtok shadow fork nullok "
        "write_to=tcb\n");
    fs::create_symlink(
        "system-auth-use_first_pass-local",
        tree.root / "pam.d/system-auth-use_first_pass");
}

fic::platform::PamPlatformConfig useFirstPassPlatform(
    const TemporaryTree& tree) {
    auto platform = tree.platform();
    platform.scopes.front().services = {"sshd", "system-auth"};
    platform.trustedServiceAliases.push_back(
        {tree.root / "pam.d/system-auth-use_first_pass",
         {tree.root / "pam.d/system-auth-use_first_pass-local"}});
    platform.capabilities.front().managedTopologyTargets.push_back(
        {tree.root / "pam.d/system-auth-use_first_pass-local-only",
         fic::platform::PamManagedTopologyTargetRole::Authentication});
    return platform;
}

fic::platform::PamPlatformConfig coexistencePlatform(
    const TemporaryTree& tree) {
    auto platform = useFirstPassPlatform(tree);
    platform.capabilities.push_back({
        fic::platform::PamCapability::PasswordHistory,
        fic::platform::PamProviderKind::PamPwhistory,
        fic::platform::PamScope::LocalPasswordChange,
        "/etc/security/fic-pwhistory.conf",
        fic::platform::PamTopologyStrategyKind::AltTcbManaged,
        tree.target()});
    return platform;
}

AltPamPasswordHistoryTopologyOptions historyOptions(
    const TemporaryTree& tree) {
    AltPamPasswordHistoryTopologyOptions options;
    options.lockFilePath = tree.root / "run/pam-pwhistory.lock";
    options.lockDebugLogPath = tree.root / "pwhistory-lock-debug.log";
    options.stateDirectory = tree.root / "pwhistory-state";
    options.historyFile = options.stateDirectory / "opasswd";
    options.transactionLockFile = options.stateDirectory / ".lock";
    options.storageOwner = ::geteuid();
    options.storageGroup = ::getegid();
    options.semanticVerifier = [](std::string& error) {
        error.clear();
        return true;
    };
    return options;
}

void testCanonicalRoundTrip() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    PamTopologyManager& topology = manager;
    PamTopologyStatus genericStatus;
    require(topology.canEnable(error), error);
    require(topology.inspect(genericStatus, error) &&
                genericStatus.state == PamTopologyState::Disabled &&
                genericStatus.manageable,
            error);
    AltPamFaillockTopologyState state;
    require(manager.status(state, error) &&
                state == AltPamFaillockTopologyState::Disabled,
            error);
    require(manager.enable(error), error);
    const std::string enabled = TemporaryTree::read(tree.target());
    require(enabled.find(
                std::string(AltPamFaillockTopologyManager::PREAUTH_BEGIN) +
                "\n" + AltPamFaillockTopologyManager::PREAUTH_RULE + "\n") !=
                std::string::npos,
            "preauth block is missing");
    require(enabled.find(
                std::string(AltPamFaillockTopologyManager::AUTHFAIL_BEGIN) +
                "\n" + AltPamFaillockTopologyManager::AUTHFAIL_RULE + "\n") !=
                std::string::npos,
            "authfail block is missing");
    require(enabled.find(
                std::string(AltPamFaillockTopologyManager::ACCOUNT_BEGIN) +
                "\n" + AltPamFaillockTopologyManager::ACCOUNT_RULE + "\n") !=
                std::string::npos,
            "account block is missing");
    require(manager.status(state, error) &&
                state == AltPamFaillockTopologyState::Enabled,
            error);
    require(topology.inspect(genericStatus, error) &&
                genericStatus.state == PamTopologyState::Enabled,
            error);
    require(manager.enable(error), error);
    require(TemporaryTree::read(tree.target()) == enabled,
            "second enable changed the file");
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) == kCanonical,
            "enable-disable did not restore exact original bytes");
    require(manager.disable(error), error);
}

void testWhitespaceAndUnrelatedContent() {
    TemporaryTree tree;
    const std::string fixture =
        "# administrator comment\n"
        "auth    required    pam_tcb.so   shadow fork nullok\n"
        "# auth tail comment\n"
        "\n"
        "account    required    pam_tcb.so shadow fork\n"
        "password required pam_passwdqc.so config=/etc/passwdqc.conf\n"
        "session required pam_tcb.so";
    TemporaryTree::write(tree.target(), fixture);
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) == fixture,
            "whitespace/unrelated bytes were not preserved");
}

void testExecutableAuthTailRejectedBeforeWrite() {
    for (const std::string& tail : {
             std::string("auth required pam_succeed_if.so user != root quiet\n"),
             std::string("auth optional pam_env.so\n")}) {
        TemporaryTree tree;
        const std::string fixture =
            "auth required pam_tcb.so shadow fork nullok\n" + tail +
            "account required pam_tcb.so shadow fork\n";
        TemporaryTree::write(tree.target(), fixture);
        auto options = tree.options();
        std::size_t writes = 0;
        options.writer = [&writes](const std::string& path,
                                   const std::string& content,
                                   const AtomicWriteOptions& writeOptions,
                                   std::string* error) {
            ++writes;
            return AtomicFileWriter::write(path, content, writeOptions, error);
        };
        AltPamFaillockTopologyManager manager(
            tree.platform(), std::move(options));
        std::string error;
        require(!manager.enable(error),
                "executable auth rule after pam_tcb was accepted");
        require(writes == 0, "auth-tail rejection happened after a write");
        require(TemporaryTree::read(tree.target()) == fixture,
                "auth-tail rejection changed the target");
    }
}

void testIncludedExternalFaillockRejectedBeforeWrite() {
    TemporaryTree tree;
    TemporaryTree::write(
        tree.root / "pam.d/system-auth",
        "auth include system-auth-local-only\n"
        "auth include system-auth-common\n"
        "account include system-auth-local-only\n"
        "account include system-auth-common\n");
    TemporaryTree::write(
        tree.root / "pam.d/system-auth-common",
        "auth requisite pam_faillock.so preauth\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "account required pam_faillock.so\n");
    const std::string original = TemporaryTree::read(tree.target());
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    AltPamFaillockTopologyManager manager(
        tree.platform(), std::move(options));
    std::string error;
    require(!manager.enable(error),
            "included external pam_faillock topology was accepted");
    require(writes == 0,
            "included external pam_faillock was detected only after mutation");
    require(TemporaryTree::read(tree.target()) == original,
            "included external topology changed the target");
}

void testTrustedUseFirstPassAliasInSshGraph() {
    TemporaryTree tree;
    writeSshUseFirstPassGraph(tree);
    auto platform = useFirstPassPlatform(tree);
    const fs::path useFirstPassTarget =
        tree.root / "pam.d/system-auth-use_first_pass-local-only";
    const std::string originalPrimary = TemporaryTree::read(tree.target());
    const std::string originalUseFirstPass =
        TemporaryTree::read(useFirstPassTarget);
    AltPamFaillockTopologyManager manager(platform, tree.options());
    std::string error;
    require(manager.enable(error),
            "trusted ALT use_first_pass alias was rejected: " + error);
    const std::string enabledPrimary = TemporaryTree::read(tree.target());
    const std::string enabledUseFirstPass =
        TemporaryTree::read(useFirstPassTarget);
    require(enabledUseFirstPass.find(
                "pam_tcb.so shadow fork nullok use_first_pass") !=
                std::string::npos,
            "managed use_first_pass authenticator lost its native arguments");
    require(manager.enable(error), "second enable failed: " + error);
    require(TemporaryTree::read(tree.target()) == enabledPrimary &&
                TemporaryTree::read(useFirstPassTarget) == enabledUseFirstPass,
            "idempotent enable changed a managed PAM target");
    fic::identity::pam::PamConfiguration configuration(platform);
    fic::identity::pam::PamProviderInspection inspection;
    fic::identity::pam::PamProviderInspectionFailure failure;
    require(fic::identity::pam::PamProviderInspector::inspect(
                configuration,
                {"sshd"},
                fic::platform::PamCapability::AuthenticationLockout,
                fic::platform::PamProviderKind::PamFaillock,
                inspection,
                error,
                &failure),
            "enabled topology is not structurally effective for sshd: " +
                error);
    std::size_t preauth = 0;
    std::size_t authfail = 0;
    std::size_t account = 0;
    for (const auto& rule : inspection.providerRules) {
        if (fic::identity::pam::PamProviderInspector::hasArgument(
                rule, "preauth")) {
            ++preauth;
            require(rule.source == useFirstPassTarget,
                    "sshd preauth does not come from use_first_pass target");
        } else if (fic::identity::pam::PamProviderInspector::hasArgument(
                       rule, "authfail")) {
            ++authfail;
            require(rule.source == useFirstPassTarget,
                    "sshd authfail does not come from use_first_pass target");
        } else if (rule.group ==
                   fic::identity::pam::PamManagementGroup::Account) {
            ++account;
            require(rule.source == tree.target(),
                    "sshd account call does not come from normal local target");
        }
    }
    require(preauth == 1 && authfail == 1 && account == 1,
            "flattened sshd graph has an incomplete pam_faillock topology");
    require(fs::is_symlink(
                tree.root / "pam.d/system-auth-use_first_pass") &&
                fs::read_symlink(
                    tree.root / "pam.d/system-auth-use_first_pass") ==
                    "system-auth-use_first_pass-local",
            "enable replaced the native use_first_pass alias");
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) == originalPrimary &&
                TemporaryTree::read(useFirstPassTarget) ==
                    originalUseFirstPass,
            "disable did not restore both managed targets exactly");
}

void testUntrustedGraphAliasHasAccurateDiagnostic() {
    TemporaryTree tree;
    writeSshUseFirstPassGraph(tree);
    auto platform = tree.platform();
    platform.scopes.front().services = {"sshd", "system-auth"};
    const std::string original = TemporaryTree::read(tree.target());
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    AltPamFaillockTopologyManager manager(
        std::move(platform), std::move(options));
    std::string error;
    require(!manager.enable(error),
            "untrusted PAM service alias was accepted");
    require(error.find("could not inspect relevant PAM graph") !=
                std::string::npos &&
                error.find("symbolic link") != std::string::npos &&
                error.find("already exists") == std::string::npos,
            "PAM graph inspection failure was reported as external topology: " +
                error);
    require(writes == 0 && TemporaryTree::read(tree.target()) == original,
            "untrusted alias rejection happened after PAM mutation");
}

void testUseFirstPassExternalFaillockRejectedBeforeWrite() {
    TemporaryTree tree;
    writeSshUseFirstPassGraph(tree);
    auto platform = useFirstPassPlatform(tree);
    const fs::path target =
        tree.root / "pam.d/system-auth-use_first_pass-local-only";
    const std::string external =
        "#%PAM-1.0\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth required pam_tcb.so shadow fork nullok use_first_pass\n"
        "auth [default=die] pam_faillock.so authfail\n";
    TemporaryTree::write(target, external);
    const std::string originalPrimary = TemporaryTree::read(tree.target());
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    AltPamFaillockTopologyManager manager(
        std::move(platform), std::move(options));
    std::string error;
    require(!manager.enable(error) &&
                error.find("external pam_faillock topology") !=
                    std::string::npos,
            "external use_first_pass topology was accepted: " + error);
    require(writes == 0 &&
                TemporaryTree::read(tree.target()) == originalPrimary &&
                TemporaryTree::read(target) == external,
            "external use_first_pass topology was rejected after mutation");
}

void testUseFirstPassBrokenMarkersFailClosed() {
    {
        TemporaryTree tree;
        writeSshUseFirstPassGraph(tree);
        auto platform = useFirstPassPlatform(tree);
        const fs::path target =
            tree.root / "pam.d/system-auth-use_first_pass-local-only";
        const std::string partial =
            std::string(AltPamFaillockTopologyManager::PREAUTH_BEGIN) + "\n" +
            AltPamFaillockTopologyManager::PREAUTH_RULE + "\n" +
            "auth required pam_tcb.so shadow fork nullok use_first_pass\n";
        TemporaryTree::write(target, partial);
        auto options = tree.options();
        std::size_t writes = 0;
        options.writer = [&writes](const std::string& path,
                                   const std::string& content,
                                   const AtomicWriteOptions& writeOptions,
                                   std::string* error) {
            ++writes;
            return AtomicFileWriter::write(path, content, writeOptions, error);
        };
        AltPamFaillockTopologyManager manager(
            std::move(platform), std::move(options));
        std::string error;
        require(!manager.enable(error) && writes == 0 &&
                    TemporaryTree::read(target) == partial,
                "partial use_first_pass markers were not rejected pre-write");
    }
    {
        TemporaryTree tree;
        writeSshUseFirstPassGraph(tree);
        auto platform = useFirstPassPlatform(tree);
        const fs::path target =
            tree.root / "pam.d/system-auth-use_first_pass-local-only";
        AltPamFaillockTopologyManager setup(platform, tree.options());
        std::string error;
        require(setup.enable(error), error);
        std::string modified = TemporaryTree::read(target);
        const std::size_t rule = modified.find(
            AltPamFaillockTopologyManager::AUTHFAIL_RULE);
        require(rule != std::string::npos,
                "use_first_pass authfail fixture is missing");
        modified.replace(
            rule,
            std::strlen(AltPamFaillockTopologyManager::AUTHFAIL_RULE),
            "auth optional pam_faillock.so authfail");
        TemporaryTree::write(target, modified);
        auto options = tree.options();
        std::size_t writes = 0;
        options.writer = [&writes](const std::string& path,
                                   const std::string& content,
                                   const AtomicWriteOptions& writeOptions,
                                   std::string* writeError) {
            ++writes;
            return AtomicFileWriter::write(
                path, content, writeOptions, writeError);
        };
        AltPamFaillockTopologyManager manager(
            std::move(platform), std::move(options));
        require(!manager.enable(error) && writes == 0 &&
                    TemporaryTree::read(target) == modified,
                "modified use_first_pass block was not rejected pre-write");
    }
}

void testUseFirstPassUnsafeAuthTailRejectedBeforeWrite() {
    TemporaryTree tree;
    writeSshUseFirstPassGraph(tree);
    auto platform = useFirstPassPlatform(tree);
    const fs::path target =
        tree.root / "pam.d/system-auth-use_first_pass-local-only";
    const std::string unsafe = TemporaryTree::read(target) +
        "auth optional pam_env.so\n";
    TemporaryTree::write(target, unsafe);
    const std::string originalPrimary = TemporaryTree::read(tree.target());
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    AltPamFaillockTopologyManager manager(
        std::move(platform), std::move(options));
    std::string error;
    require(!manager.enable(error) &&
                error.find("unsafe") != std::string::npos,
            "unsafe use_first_pass auth tail was accepted: " + error);
    require(writes == 0 &&
                TemporaryTree::read(tree.target()) == originalPrimary &&
                TemporaryTree::read(target) == unsafe,
            "unsafe use_first_pass tail was rejected after mutation");
}

void testFaillockAndPasswordHistoryCoexistence() {
    for (const bool historyFirst : {false, true}) {
        TemporaryTree tree;
        writeSshUseFirstPassGraph(tree);
        auto platform = coexistencePlatform(tree);
        const fs::path useFirstPassTarget =
            tree.root / "pam.d/system-auth-use_first_pass-local-only";
        const std::string originalPrimary = TemporaryTree::read(tree.target());
        const std::string originalUseFirstPass =
            TemporaryTree::read(useFirstPassTarget);
        AltPamFaillockTopologyManager faillock(platform, tree.options());
        AltPamPasswordHistoryTopologyManager history(
            platform, historyOptions(tree));
        std::string error;
        if (historyFirst) {
            require(history.enable(error), error);
            require(faillock.enable(error), error);
        } else {
            require(faillock.enable(error), error);
            require(history.enable(error), error);
        }
        require(TemporaryTree::read(tree.target()).find(
                    AltPamPasswordHistoryTopologyManager::HISTORY_RULE) !=
                    std::string::npos &&
                    TemporaryTree::read(tree.target()).find(
                        AltPamFaillockTopologyManager::ACCOUNT_RULE) !=
                        std::string::npos &&
                    TemporaryTree::read(useFirstPassTarget).find(
                        AltPamFaillockTopologyManager::AUTHFAIL_RULE) !=
                        std::string::npos,
                "coexisting PAM facilities lost a managed block");
        if (historyFirst) {
            require(history.disable(error), error);
            require(TemporaryTree::read(tree.target()).find(
                        AltPamFaillockTopologyManager::ACCOUNT_RULE) !=
                        std::string::npos,
                    "disabling pwhistory removed faillock blocks");
            require(faillock.disable(error), error);
        } else {
            require(faillock.disable(error), error);
            require(TemporaryTree::read(tree.target()).find(
                        AltPamPasswordHistoryTopologyManager::HISTORY_RULE) !=
                        std::string::npos,
                    "disabling faillock removed pwhistory blocks");
            require(history.disable(error), error);
        }
        require(TemporaryTree::read(tree.target()) == originalPrimary &&
                    TemporaryTree::read(useFirstPassTarget) ==
                        originalUseFirstPass,
                "facility coexistence did not restore exact PAM bytes");
    }
}

void testSecondTargetWriteFailureRollsBackFirstTarget() {
    TemporaryTree tree;
    writeSshUseFirstPassGraph(tree);
    auto platform = useFirstPassPlatform(tree);
    const fs::path useFirstPassTarget =
        tree.root / "pam.d/system-auth-use_first_pass-local-only";
    const std::string originalPrimary = TemporaryTree::read(tree.target());
    const std::string originalUseFirstPass =
        TemporaryTree::read(useFirstPassTarget);
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        if (writes == 2) {
            if (error != nullptr) {
                *error = "injected second-target write failure";
            }
            return false;
        }
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    AltPamFaillockTopologyManager manager(
        std::move(platform), std::move(options));
    std::string error;
    require(!manager.enable(error) &&
                error.find("original PAM configuration restored") !=
                    std::string::npos,
            "second-target failure did not report verified rollback: " + error);
    require(writes == 3 &&
                TemporaryTree::read(tree.target()) == originalPrimary &&
                TemporaryTree::read(useFirstPassTarget) ==
                    originalUseFirstPass,
            "second-target failure did not restore the first target exactly");
}

void testSssModeVerifiesManagedLocalBranch() {
    TemporaryTree tree;
    TemporaryTree::write(
        tree.root / "pam.d/system-auth",
        "auth include system-check-localuser\n"
        "auth substack system-auth-local-only\n"
        "auth [default=1] pam_permit.so\n"
        "auth substack system-auth-sss-only\n"
        "auth substack system-auth-common\n"
        "account include system-check-localuser\n"
        "account substack system-auth-local-only\n"
        "account [default=1] pam_permit.so\n"
        "account substack system-auth-sss-only\n"
        "account substack system-auth-common\n");
    TemporaryTree::write(
        tree.root / "pam.d/system-check-localuser",
        "auth [success=1 perm_denied=ignore default=die] pam_localuser.so\n"
        "auth [success=2 auth_err=ignore default=bad] "
        "pam_succeed_if.so uid >= 65536 quiet\n"
        "account [success=1 perm_denied=ignore default=die] pam_localuser.so\n"
        "account [success=2 auth_err=ignore default=bad] "
        "pam_succeed_if.so uid >= 65536 quiet\n");
    TemporaryTree::write(
        tree.root / "pam.d/system-auth-sss-only",
        "auth required pam_sss.so forward_pass\n"
        "account required pam_sss.so\n");
    TemporaryTree::write(tree.root / "pam.d/system-auth-common", "# empty\n");
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    const bool enabled = manager.enable(error);
    require(enabled,
            "ALT sss mode rejected local-only faillock topology: " + error);
    AltPamFaillockTopologyState state;
    require(manager.status(state, error) &&
                state == AltPamFaillockTopologyState::Enabled,
            "ALT sss mode did not report enabled local topology: " + error);
    require(manager.disable(error), error);
    require(TemporaryTree::read(tree.target()) == kCanonical,
            "ALT sss local branch was not restored exactly");
}

void testExternalTopologyRejected() {
    TemporaryTree tree;
    const std::string external =
        "#%PAM-1.0\n"
        "auth requisite pam_faillock.so preauth\n"
        "auth sufficient pam_tcb.so shadow fork nullok\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "account required pam_faillock.so\n"
        "account required pam_tcb.so shadow fork\n";
    TemporaryTree::write(tree.target(), external);
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    AltPamFaillockTopologyManager manager(
        tree.platform(), std::move(options));
    std::string error;
    require(!manager.enable(error) &&
                error.find("external pam_faillock topology") != std::string::npos,
            "external topology was not rejected");
    require(TemporaryTree::read(tree.target()) == external,
            "external topology was modified");

    const std::string partial =
        "auth required pam_tcb.so\n"
        "auth [default=die] pam_faillock.so authfail\n"
        "account required pam_tcb.so\n";
    TemporaryTree::write(tree.target(), partial);
    require(!manager.enable(error), "partial external topology was accepted");
    require(TemporaryTree::read(tree.target()) == partial,
            "partial external topology was modified");
    require(writes == 0, "target-local external topology invoked the writer");
}

void testBrokenMarkersRejected() {
    for (const std::string& broken : {
             std::string(AltPamFaillockTopologyManager::PREAUTH_BEGIN) + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_RULE + "\n" + kCanonical,
             std::string(AltPamFaillockTopologyManager::PREAUTH_BEGIN) + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_RULE + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_END + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_BEGIN + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_RULE + "\n" +
                 AltPamFaillockTopologyManager::PREAUTH_END + "\n" + kCanonical,
             std::string(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) +
                 "00\n" + kCanonical}) {
        TemporaryTree tree;
        TemporaryTree::write(tree.target(), broken);
        AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
        std::string error;
        AltPamFaillockTopologyState state;
        require(!manager.status(state, error), "broken markers have a status");
        require(!manager.enable(error), "broken markers were enabled");
        require(!manager.disable(error), "broken markers were disabled");
        require(TemporaryTree::read(tree.target()) == broken,
                "broken managed state was modified");
    }

    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    std::string modified = TemporaryTree::read(tree.target());
    const std::size_t rule = modified.find(
        AltPamFaillockTopologyManager::AUTHFAIL_RULE);
    require(rule != std::string::npos, "authfail fixture rule is missing");
    modified.replace(rule, std::strlen(
                         AltPamFaillockTopologyManager::AUTHFAIL_RULE),
                     "auth optional pam_faillock.so authfail");
    TemporaryTree::write(tree.target(), modified);
    AltPamFaillockTopologyState state;
    require(!manager.status(state, error),
            "modified managed block has a status");
    require(!manager.enable(error), "modified managed block was enabled");
    require(!manager.disable(error), "modified managed block was disabled");
    require(TemporaryTree::read(tree.target()) == modified,
            "modified managed block was changed");
}

void testManagedPlacementChangeRejectedWithoutMutation() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    std::string moved = TemporaryTree::read(tree.target());
    const std::size_t begin = moved.find(
        AltPamFaillockTopologyManager::PREAUTH_BEGIN);
    const std::size_t endMarker = moved.find(
        AltPamFaillockTopologyManager::PREAUTH_END, begin);
    require(begin != std::string::npos && endMarker != std::string::npos,
            "managed preauth block is missing");
    const std::size_t end = endMarker + std::strlen(
        AltPamFaillockTopologyManager::PREAUTH_END) + 1;
    const std::string preauthBlock = moved.substr(begin, end - begin);
    moved.erase(begin, end - begin);
    const std::size_t accountBlock = moved.find(
        AltPamFaillockTopologyManager::ACCOUNT_BEGIN);
    require(accountBlock != std::string::npos,
            "managed account block is missing");
    moved.insert(accountBlock, preauthBlock);
    TemporaryTree::write(tree.target(), moved);
    AltPamFaillockTopologyState state;
    require(!manager.status(state, error),
            "moved managed topology has enabled status");
    require(!manager.enable(error),
            "moved managed topology was accepted by enable");
    require(!manager.disable(error),
            "moved managed topology was guessed during disable");
    require(TemporaryTree::read(tree.target()) == moved,
            "failed disable changed moved managed topology");
}

void testAtomicWriteRejectsReplacementAfterSnapshotCheck() {
    TemporaryTree tree;
    const std::string replacement =
        "auth required pam_deny.so\n"
        "account required pam_deny.so\n";
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes, &replacement](
                         const std::string& path,
                         const std::string& content,
                         const AtomicWriteOptions& writeOptions,
                         std::string* error) {
        ++writes;
        if (writes == 1) {
            const fs::path replacementPath = std::string(path) + ".replacement";
            TemporaryTree::write(replacementPath, replacement);
            fs::rename(replacementPath, path);
        }
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    AltPamFaillockTopologyManager manager(
        tree.platform(), std::move(options));
    std::string error;
    require(!manager.enable(error),
            "atomic writer overwrote a replacement target");
    require(TemporaryTree::read(tree.target()) == replacement,
            "replacement target was not preserved");
}

void testMissingAndAmbiguousAnchors() {
    for (const std::string& fixture : {
             std::string("account required pam_tcb.so\n"),
             std::string("auth required pam_tcb.so\nauth required pam_tcb.so\n") +
                 "account required pam_tcb.so\n",
             std::string("auth required pam_tcb.so\n"),
             std::string("auth optional pam_tcb.so\n") +
                 "account required pam_tcb.so\n"}) {
        TemporaryTree tree;
        TemporaryTree::write(tree.target(), fixture);
        AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
        std::string error;
        require(!manager.enable(error), "invalid anchors were accepted");
        require(TemporaryTree::read(tree.target()) == fixture,
                "invalid-anchor file was modified");
    }
}

void testDisablePostconditionRollback() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager setup(tree.platform(), tree.options());
    std::string error;
    require(setup.enable(error), error);
    const std::string enabled = TemporaryTree::read(tree.target());

    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* writeError) {
        ++writes;
        const std::string actual = writes == 1
            ? content + "# BEGIN FIC pam_faillock unexpected\n"
            : content;
        return AtomicFileWriter::write(
            path, actual, writeOptions, writeError);
    };
    AltPamFaillockTopologyManager manager(
        tree.platform(), std::move(options));
    require(!manager.disable(error) &&
                error.find("original PAM configuration restored") !=
                    std::string::npos,
            "disable postcondition failure did not trigger rollback");
    require(TemporaryTree::read(tree.target()) == enabled,
            "disable rollback did not restore enabled bytes");
    AltPamFaillockTopologyState state;
    require(manager.status(state, error) &&
                state == AltPamFaillockTopologyState::Enabled,
            "disable rollback did not restore effective enabled state: " + error);
}

void testSymlinkRejected() {
    TemporaryTree tree;
    const fs::path real = tree.root / "pam.d/real-stack";
    TemporaryTree::write(real, kCanonical);
    fs::remove(tree.target());
    fs::create_symlink(real.filename(), tree.target());
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(!manager.enable(error) && error.find("symbolic-link") != std::string::npos,
            "symlink target was accepted");
    require(TemporaryTree::read(real) == kCanonical,
            "symlink target was modified");
}

void testPostconditionRollback() {
    TemporaryTree tree;
    auto options = tree.options();
    options.semanticVerifier = [](std::string& error) {
        error = "injected semantic failure";
        return false;
    };
    AltPamFaillockTopologyManager manager(tree.platform(), std::move(options));
    std::string error;
    require(!manager.enable(error) &&
                error.find("original PAM configuration restored") !=
                    std::string::npos,
            "semantic failure did not trigger verified rollback");
    require(TemporaryTree::read(tree.target()) == kCanonical,
            "rollback did not restore original bytes");
}

void testRollbackFailureIsCritical() {
    TemporaryTree tree;
    auto options = tree.options();
    std::size_t writes = 0;
    options.writer = [&writes](const std::string& path,
                               const std::string& content,
                               const AtomicWriteOptions& writeOptions,
                               std::string* error) {
        ++writes;
        if (writes == 2) {
            if (error != nullptr) {
                *error = "injected rollback write failure";
            }
            return false;
        }
        return AtomicFileWriter::write(path, content, writeOptions, error);
    };
    options.semanticVerifier = [](std::string& error) {
        error = "injected semantic failure";
        return false;
    };
    AltPamFaillockTopologyManager manager(tree.platform(), std::move(options));
    std::string error;
    require(!manager.enable(error) && error.find("CRITICAL") != std::string::npos &&
                error.find("may be inconsistent") != std::string::npos,
            "rollback failure was not reported as critical");
}

void testDisablePreservesExternalLines() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    std::string mixed = TemporaryTree::read(tree.target());
    const std::string external = "auth optional pam_faillock.so silent\n";
    mixed += external;
    TemporaryTree::write(tree.target(), mixed);
    require(manager.disable(error), error);
    const std::string disabled = TemporaryTree::read(tree.target());
    require(disabled == kCanonical + external,
            "disable removed or changed administrator-owned faillock line");
}

void testGeneratedRulesContainNoPolicyValues() {
    const std::string enabled = enabledFixture();
    for (const char* forbidden : {
             "deny=", "fail_interval=", "unlock_time=", "even_deny_root",
             "root_unlock_time="}) {
        require(enabled.find(forbidden) == std::string::npos,
                std::string("generated topology contains policy value: ") + forbidden);
    }
    require(count(enabled, "pam_faillock.so") == 3,
            "generated topology has an unexpected faillock call count");
}

void testRoundTripPreservesNativeServiceAlias() {
    TemporaryTree tree;
    AltPamFaillockTopologyManager manager(tree.platform(), tree.options());
    std::string error;
    require(manager.enable(error), error);
    require(fs::is_symlink(tree.root / "pam.d/system-auth") &&
                fs::read_symlink(tree.root / "pam.d/system-auth") ==
                    "system-auth-local",
            "enable replaced the native system-auth alias");
    require(manager.disable(error), error);
    require(fs::is_symlink(tree.root / "pam.d/system-auth") &&
                fs::read_symlink(tree.root / "pam.d/system-auth") ==
                    "system-auth-local",
            "disable replaced the native system-auth alias");
    require(fs::is_symlink(tree.root / "pam.d/system-policy") &&
                fs::read_symlink(tree.root / "pam.d/system-policy") ==
                    "system-policy-local",
            "roundtrip replaced the native system-policy alias");
}

} // namespace

int main() {
    try {
        testCanonicalRoundTrip();
        testWhitespaceAndUnrelatedContent();
        testSssModeVerifiesManagedLocalBranch();
        testAtomicWriteRejectsReplacementAfterSnapshotCheck();
        testManagedPlacementChangeRejectedWithoutMutation();
        testIncludedExternalFaillockRejectedBeforeWrite();
        testTrustedUseFirstPassAliasInSshGraph();
        testUntrustedGraphAliasHasAccurateDiagnostic();
        testUseFirstPassExternalFaillockRejectedBeforeWrite();
        testUseFirstPassBrokenMarkersFailClosed();
        testUseFirstPassUnsafeAuthTailRejectedBeforeWrite();
        testFaillockAndPasswordHistoryCoexistence();
        testSecondTargetWriteFailureRollsBackFirstTarget();
        testExecutableAuthTailRejectedBeforeWrite();
        testExternalTopologyRejected();
        testBrokenMarkersRejected();
        testMissingAndAmbiguousAnchors();
        testSymlinkRejected();
        testPostconditionRollback();
        testDisablePostconditionRollback();
        testRollbackFailureIsCritical();
        testDisablePreservesExternalLines();
        testGeneratedRulesContainNoPolicyValues();
        testRoundTripPreservesNativeServiceAlias();
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }
}
