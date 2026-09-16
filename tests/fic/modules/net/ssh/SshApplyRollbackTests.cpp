#include "modules/net/ssh/Ssh.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/policies/NET_ssh_max_auth_tries.h"
#include "modules/net/ssh/policies/NET_ssh_port.h"
#include "modules/net/ssh/policies/NET_ssh_pubkey_auth.h"
#include "modules/net/ssh/policies/NET_ssh_root_login.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/RollbackExecutor.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <fic/policy/Policy.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>

namespace {

using namespace fic::rollback;

class TempTree {
public:
    TempTree(const std::string& pattern) {
        char* created = ::mkdtemp(const_cast<char*>(pattern.data()));
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = created;
    }

    ~TempTree() {
        std::error_code ignored;
        std::filesystem::permissions(root,
            std::filesystem::perms::owner_all, ignored);
        std::filesystem::remove_all(root, ignored);
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

class JournalOverride {
public:
    explicit JournalOverride(std::filesystem::path path) {
        DaemonMutationJournal::instance().setOverridePath(std::move(path));
    }
    ~JournalOverride() { DaemonMutationJournal::instance().resetOverride(); }
};

ProcessResult sshSuccess(const std::string& output = {}) {
    ProcessResult result;
    result.started = true;
    result.exitCode = 0;
    result.standardOutput = output;
    return result;
}

ProcessResult sshInactive() {
    ProcessResult result;
    result.started = true;
    result.exitCode = 3;
    return result;
}

ProcessResult sshFailing(const std::string& errorText) {
    ProcessResult result;
    result.started = true;
    result.exitCode = 1;
    result.standardError = errorText;
    return result;
}

// Controls the fake sshd -T output: the first call observes the state before
// the FIC mutation, later calls observe the state after it.
struct FakeSshRuntime {
    std::string preApplyPort = "22";
    std::string appliedPort = "2222";
    int tCalls = 0;
    int reloadCalls = 0;
    bool serviceActive = false;
    bool reloadFails = false;
    bool sshdFails = false;
};

} // namespace

namespace {

class SshPortPolicyUnderTest : public Ssh {
public:
    SshPortPolicyUnderTest(
        const fic::platform::SshPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables,
        const std::filesystem::path& configDirectory)
        : Ssh(platformConfig, executables) {
        moduleName = "NET";
        submoduleName = "SshEdit";
        policyName = "ssh_port";
        this->Ssh::sshParameter = "Port";
        moduleConf = std::make_unique<ModuleConfigFileHandler>(
            configDirectory, moduleName);
        moduleConf->loadConfig();
        policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 65535, 22);
    }

    void setRunner(SshCommandRunner runnerValue) {
        commandRunner_ = std::move(runnerValue);
    }
};

class SshApplyTree {
public:
    SshApplyTree()
        : tree("/tmp/fic-ssh-apply-rollback-XXXXXX"),
          runtime_(std::make_shared<FakeSshRuntime>()) {
        writeFile(tree.root / "bin" / "sshd", "#!/bin/sh\nexit 0\n");
        writeFile(tree.root / "bin" / "systemctl", "#!/bin/sh\nexit 0\n");
        for (const std::string& name : {"sshd", "systemctl"}) {
            ::chmod((tree.root / "bin" / name).c_str(), 0755);
        }
        fic::platform::PlatformExecutables registry;
        registry.entries = {
            {fic::platform::ExecutableId::Sshd, {tree.root / "bin" / "sshd"}},
            {fic::platform::ExecutableId::Systemctl,
             {tree.root / "bin" / "systemctl"}}};
        fic::platform::PlatformExecutableResolverOptions resolverOptions;
        resolverOptions.enforceTrustedOwnership = false;
        executables_ =
            std::make_unique<fic::platform::PlatformExecutableResolver>(
                std::move(registry), resolverOptions);
    }

    std::filesystem::path configPath() const { return tree.root / "sshd_config"; }
    std::filesystem::path journalPath() const { return tree.root / "journal.json"; }

    void writeConfig(const std::string& content) { writeFile(configPath(), content); }

    void writePolicyValue(const std::string& value) {
        writeFile(tree.root / "config" / "NET.conf",
                  "ssh_port.status=ENABLE\nssh_port.value=" + value + "\n");
    }

    SshCommandRunner runner() const {
        std::shared_ptr<FakeSshRuntime> runtime = runtime_;
        return [runtime](const std::string&,
                         const std::vector<std::string>& arguments,
                         const ProcessOptions&) {
            if (std::find(arguments.begin(), arguments.end(), "-T") !=
                arguments.end()) {
                if (runtime->sshdFails) {
                    return sshFailing("sshd -T refused the configuration");
                }
                ++runtime->tCalls;
                const std::string& port =
                    runtime->tCalls == 1 ? runtime->preApplyPort
                                         : runtime->appliedPort;
                return sshSuccess("port " + port + "\n"
                                  "maxauthtries 3\n"
                                  "pubkeyauthentication yes\n");
            }
            if (std::find(arguments.begin(), arguments.end(), "is-active") !=
                arguments.end()) {
                return runtime->serviceActive ? sshSuccess() : sshInactive();
            }
            if (std::find(arguments.begin(), arguments.end(), "reload") !=
                arguments.end()) {
                ++runtime->reloadCalls;
                return runtime->reloadFails
                    ? sshFailing("reload job failed")
                    : sshSuccess();
            }
            return sshInactive();
        };
    }

    fic::platform::SshPlatformConfig platformConfig() const {
        fic::platform::SshPlatformConfig value;
        value.configPath = configPath();
        value.includeBasePath = tree.root;
        value.serviceUnits = {"ssh.service", "sshd.service"};
        return value;
    }

    std::unique_ptr<SshPortPolicyUnderTest> makePolicy() {
        auto policy = std::make_unique<SshPortPolicyUnderTest>(
            platformConfig(), *executables_, tree.root / "config");
        policy->setRunner(runner());
        return policy;
    }

    RollbackExecutorDeps rollbackDeps() const {
        RollbackExecutorDeps value;
        SshRollbackOptions options;
        options.configPath = configPath();
        options.includeBasePath = tree.root;
        options.serviceUnits = {"ssh.service", "sshd.service"};
        options.executables = executables_.get();
        options.runner = runner();
        value.sshOptions = [options]() { return options; };
        return value;
    }

    std::shared_ptr<FakeSshRuntime> runtime() const { return runtime_; }
    const fic::platform::PlatformExecutableResolver& executables() const {
        return *executables_;
    }

    TempTree tree;

private:
    std::shared_ptr<FakeSshRuntime> runtime_;
    std::unique_ptr<fic::platform::PlatformExecutableResolver> executables_;
};

} // namespace

namespace {

const PolicyRef kSshPortPolicy{"NET", "SshEdit", "ssh_port"};

void testCompliantEffectiveStateCausesNoMutation() {
    SshApplyTree tree;
    const std::string original =
        "PermitRootLogin prohibit-password\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("22"); // effective sshd default already matches
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(policy->apply(), "an already compliant effective state must pass");

    require(readFile(tree.configPath()) == original,
            "a compliant effective state must not be written or owned");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(),
            "no mutation record must exist for a compliant state");
    require(tree.runtime()->tCalls == 1,
            "only the pre-check must run for a compliant state");
    require(tree.runtime()->reloadCalls == 0,
            "no reload must happen for a compliant state");
}

void testApplyFailsWhenEffectiveStateUnknown() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nMatch User backup\n    PermitRootLogin yes\n");
    tree.writePolicyValue("2222");
    tree.runtime()->sshdFails = true;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(!policy->apply(),
            "an undeterminable effective state must fail the apply closed");

    require(readFile(tree.configPath()) ==
                "Port 22\nMatch User backup\n    PermitRootLogin yes\n",
            "no file mutation must happen when the effective state is unknown");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(),
            "no mutation record must exist without a real mutation");
}

void testApplyReplacesDirectiveAndRollbackRestores() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(policy->apply(), "the apply must succeed");
    require(readFile(tree.configPath()) ==
                "Port 2222\n"
                "Match User backup\n"
                "    PermitRootLogin yes\n",
            "the apply must replace the directive");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "the committed mutation must be recorded");
    const MutationRecord& record = journal.records().front();
    require(record.policy == kSshPortPolicy &&
                record.resource ==
                    "ssh:" + tree.configPath().string() + ":Port" &&
                record.undo.backend == MutationBackend::Ssh,
            "the mutation record must identify the policy and the resource");
    const auto* undo =
        std::get_if<UndoRestoreSshDirective>(&record.undo.payload);
    require(undo != nullptr && undo->parameter == "Port" &&
                undo->appliedValue == "2222" &&
                undo->reverseEdits.size() == 1 &&
                undo->reverseEdits.front().beforeLine.has_value() &&
                *undo->reverseEdits.front().beforeLine == "Port 22" &&
                undo->reverseEdits.front().afterLine == "Port 2222" &&
                !undo->appliedGlobalSectionFingerprint.empty(),
            "the undo payload must carry the exact reverse delta");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) == original,
            "the rollback must restore the exact pre-FIC line");
}

void testApplyInsertsDirectiveAndRollbackRemovesIt() {
    SshApplyTree tree;
    const std::string original =
        "PermitRootLogin prohibit-password\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(policy->apply(), "the apply must succeed");
    require(readFile(tree.configPath()).find("Port 2222") != std::string::npos,
            "FIC must insert the missing directive before the first Match");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    const auto* undo = std::get_if<UndoRestoreSshDirective>(
        &journal.records().front().undo.payload);
    require(undo != nullptr && undo->reverseEdits.size() == 1 &&
                !undo->reverseEdits.front().beforeLine.has_value(),
            "an inserted line must be recorded without a before line");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) == original,
            "the rollback must remove exactly the FIC-inserted line");
}

void testApplyDuplicatesRestoredOnRollback() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Port 2022\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(policy->apply(), "the apply must succeed");
    const std::string applied = readFile(tree.configPath());
    require(applied.find("Port 2222") != std::string::npos &&
                applied.find("#Port 2022") != std::string::npos,
            "FIC must replace the first duplicate and comment the rest");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) == original,
            "the rollback must restore the exact pre-FIC global representation");
}

void testRepeatedApplyKeepsOriginalBaseline() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nMatch User backup\n    PermitRootLogin yes\n");
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(policy->apply(), "the first apply must succeed");

    // External drift while the policy stays enabled.
    tree.writeConfig("Port 2200\nMatch User backup\n    PermitRootLogin yes\n");
    tree.runtime()->tCalls = 0;
    tree.runtime()->preApplyPort = "2200";
    require(policy->apply(), "the refresh apply must repair the drift");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1,
            "a repeated apply must reuse the existing mutation record");
    const auto* undo = std::get_if<UndoRestoreSshDirective>(
        &journal.records().front().undo.payload);
    require(undo != nullptr && undo->reverseEdits.size() == 1 &&
                undo->reverseEdits.front().beforeLine.has_value() &&
                *undo->reverseEdits.front().beforeLine == "Port 22",
            "the original rollback baseline must not be overwritten");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) ==
                "Port 22\nMatch User backup\n    PermitRootLogin yes\n",
            "the rollback must restore the original pre-FIC baseline");
}

void testApplyReloadFailureRestoresPreAttemptState() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    tree.runtime()->serviceActive = true;
    tree.runtime()->reloadFails = true;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(!policy->apply(),
            "a failed runtime reload must fail the apply");

    require(readFile(tree.configPath()) == original,
            "the pre-attempt configuration must be restored after a failed reload");
    require(tree.runtime()->reloadCalls == 2,
            "the restored configuration must be reloaded again");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 && journal.records().front().isActive(),
            "provenance must stay active when the reload could not be undone");
}

void testCommitFailureFailsApplyAndKeepsPrepared() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nMatch User backup\n    PermitRootLogin yes\n");
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    // A previous crashed attempt left a Prepared record on disk.
    MutationId id = 0;
    std::string error;
    UndoRestoreSshDirective baseline;
    baseline.parameter = "Port";
    baseline.appliedValue = "2222";
    SshLineReverseEdit edit;
    edit.globalLineIndex = 0;
    edit.beforeLine = std::string("Port 22");
    edit.afterLine = "Port 2222";
    baseline.reverseEdits = {edit};
    baseline.appliedGlobalSectionFingerprint = "0f0f0f0f0f0f0f0f";
    require(recordPreparedMutation(
                kSshPortPolicy,
                "ssh:" + tree.configPath().string() + ":Port",
                UndoAction{MutationBackend::Ssh, baseline}, id, error),
            error);

    // Make every later journal persist fail (read-only journal directory).
    const std::filesystem::path journalDirectory =
        tree.journalPath().parent_path();
    std::error_code ec;
    std::filesystem::permissions(
        journalDirectory,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec,
        ec);
    require(!ec, "could not restrict the journal directory");

    auto policy = tree.makePolicy();
    require(!policy->apply(),
            "a failed journal commit must fail the apply");

    std::filesystem::permissions(journalDirectory,
                                 std::filesystem::perms::owner_all, ec);
    require(!ec, "could not restore the journal directory");

    MutationJournal journal(tree.journalPath());
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Prepared &&
                journal.records().front().isActive(),
            "the prepared record must remain active after a failed commit");
}

void testAllFourSshPoliciesAreRollbackWired() {
    SshApplyTree tree;
    const std::vector<std::pair<std::string, std::string>> expected = {
        {"ssh_port", "Port"},
        {"ssh_max_auth_tries", "MaxAuthTries"},
        {"ssh_root_login", "PermitRootLogin"},
        {"ssh_pubkey_auth", "PubkeyAuthentication"}};

    std::vector<std::unique_ptr<Ssh>> policies;
    policies.push_back(
        std::make_unique<NET_ssh_port>(tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_max_auth_tries>(
        tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_root_login>(
        tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_pubkey_auth>(
        tree.platformConfig(), tree.executables()));

    for (std::size_t index = 0; index < policies.size(); ++index) {
        const Ssh& policy = *policies[index];
        require(policy.submoduleName == "SshEdit",
                "every SSH policy must live in the SshEdit submodule");
        require(policy.policyName == expected[index].first,
                "unexpected SSH policy name: " + policy.policyName);
        require(policy.managedResource() == expected[index].second,
                "unexpected SSH managed resource for " + policy.policyName);
        require(rollbackEnrollment(policy.policyRef()) ==
                    RollbackEnrollment::Supported,
                "every real SSH policy must be rollback-enrolled: " +
                    policy.policyName);
    }
}

} // namespace

int main() {
    // Policy::log() requires initialized FIC runtime paths (logger output).
    TempTree runtimeTree("/tmp/fic-ssh-apply-runtime-XXXXXX");
    {
        auto paths = fic::core::FicProductPaths::production();
        paths.privateBinDir = runtimeTree.root / "bin";
        paths.configDir = runtimeTree.root / "config";
        paths.languageDir = runtimeTree.root / "lang";
        paths.logDir = runtimeTree.root / "log";
        paths.notifyDir = runtimeTree.root / "notify";
        paths.dataDir = runtimeTree.root / "data";
        paths.shareDir = runtimeTree.root / "share";
        paths.imageDir = runtimeTree.root / "image";
        paths.runtimeDir = runtimeTree.root / "run";
        paths.lockStatusFile = runtimeTree.root / "lockstatus";
        paths.commandHashFile = runtimeTree.root / "data/commandhash.txt";
        paths.deviceDatabaseFile = runtimeTree.root / "data/devices.db";
        paths.deviceDatabaseLockFile = runtimeTree.root / "log/devices.lock";
        paths.lockDebugLogFile = runtimeTree.root / "log/db-lock.log";
        std::filesystem::create_directories(paths.configDir);
        std::filesystem::create_directories(paths.logDir);
        std::filesystem::create_directories(paths.dataDir);
        writeFile(paths.configDir / "AUDIT.conf",
                  "_schema_version=1\n"
                  "log_level.status=ENABLE\n"
                  "log_level.value=ERROR\n");
        std::string error;
        if (!fic::core::FicRuntimePaths::initialize(paths, error)) {
            std::cerr << "FAIL: runtime paths initialization: " << error << '\n';
            return 1;
        }
    }

    const struct {
        const char* name;
        void (*test)();
    } tests[] = {
        {"compliant effective state causes no mutation",
         testCompliantEffectiveStateCausesNoMutation},
        {"apply fails when effective state is unknown",
         testApplyFailsWhenEffectiveStateUnknown},
        {"apply replaces directive and rollback restores",
         testApplyReplacesDirectiveAndRollbackRestores},
        {"apply inserts directive and rollback removes it",
         testApplyInsertsDirectiveAndRollbackRemovesIt},
        {"apply duplicates restored on rollback",
         testApplyDuplicatesRestoredOnRollback},
        {"repeated apply keeps the original baseline",
         testRepeatedApplyKeepsOriginalBaseline},
        {"apply reload failure restores the pre-attempt state",
         testApplyReloadFailureRestoresPreAttemptState},
        {"commit failure fails the apply and keeps prepared",
         testCommitFailureFailsApplyAndKeepsPrepared},
        {"all four ssh policies are rollback wired",
         testAllFourSshPoliciesAreRollbackWired}
    };

    std::size_t failures = 0;
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