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
// the FIC mutation, later calls observe the state after it. failTAfterCall > 0
// makes every sshd -T call after that ordinal fail (deterministic recovery
// scenarios); reloadFailuresRemaining makes the next N reload attempts fail.
struct FakeSshRuntime {
    std::string preApplyPort = "22";
    std::string appliedPort = "2222";
    int tCalls = 0;
    int reloadCalls = 0;
    bool serviceActive = false;
    bool reloadFails = false;
    bool sshdFails = false;
    int failTAfterCall = 0;
    int reloadFailuresRemaining = 0;
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

    void setBeforeWriteHook(std::function<void()> hook) {
        beforeWriteHook_ = std::move(hook);
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
                if (runtime->sshdFails ||
                    (runtime->failTAfterCall > 0 &&
                     runtime->tCalls >= runtime->failTAfterCall)) {
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
                if (runtime->reloadFails || runtime->reloadFailuresRemaining > 0) {
                    if (runtime->reloadFailuresRemaining > 0) {
                        --runtime->reloadFailuresRemaining;
                    }
                    return sshFailing("reload job failed");
                }
                return sshSuccess();
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
    require(undo != nullptr && undo->parameter == "port" &&
                undo->appliedValue == "2222" &&
                undo->occurrences.size() == 1 &&
                undo->occurrences.front().beforeLine.has_value() &&
                *undo->occurrences.front().beforeLine == "Port 22" &&
                undo->occurrences.front().afterLine == "Port 2222",
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
    require(undo != nullptr && undo->occurrences.size() == 1 &&
                !undo->occurrences.front().beforeLine.has_value(),
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
    require(undo != nullptr && undo->occurrences.size() == 1 &&
                undo->occurrences.front().beforeLine.has_value() &&
                *undo->occurrences.front().beforeLine == "Port 22",
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
    SshDirectiveOccurrenceMutation edit;
    edit.beforeLine = std::string("Port 22");
    edit.afterLine = "Port 2222";
    baseline.occurrences = {edit};
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

void testApplyConcurrentModificationRefused() {
    SshApplyTree tree;
    const std::string external =
        "Port 22\nMaxAuthTries 1\nMatch User backup\n    PermitRootLogin yes\n";
    tree.writeConfig("Port 22\nMatch User backup\n    PermitRootLogin yes\n");
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    // Deterministic race seam: an external actor changes the shared file
    // after FIC planned the mutation but before the conditional write.
    auto policy = tree.makePolicy();
    policy->setBeforeWriteHook([&tree, external]() {
        writeFile(tree.configPath(), external);
    });

    require(!policy->apply(),
            "a refused concurrent write must fail the apply");
    require(readFile(tree.configPath()) == external,
            "the concurrent external modification must be preserved");

    // The write was refused before anything was installed: a new Prepared
    // record is provably not backed by a system mutation and is discarded.
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(),
            "a refused write must not leave a prepared provenance record");
}

void testApplyCompensationFullSuccessDiscardsPrepared() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    tree.runtime()->serviceActive = true;
    // The first reload (of the FIC mutation) fails; the reload of the restored
    // original configuration succeeds: the compensation is fully confirmed.
    tree.runtime()->reloadFailuresRemaining = 1;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(!policy->apply(),
            "a failed runtime reload must fail the apply");
    require(readFile(tree.configPath()) == original,
            "the pre-attempt configuration must be restored");
    require(tree.runtime()->reloadCalls == 2,
            "the restored configuration must be reloaded again");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(),
            "a fully confirmed compensation must discard the new prepared "
            "record");
}

void testApplyRestoredValidationFailureKeepsPrepared() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    tree.runtime()->serviceActive = true;
    tree.runtime()->reloadFailuresRemaining = 1;
    // sshd -T succeeds for the pre-check and the post-write verification
    // (calls 1 and 2) and fails for the validation of the restored original
    // configuration (call 3): the compensation is incomplete.
    tree.runtime()->failTAfterCall = 2;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(!policy->apply(), "the apply must fail");

    require(readFile(tree.configPath()) == original,
            "the pre-attempt configuration must be restored on disk");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().isActive(),
            "an unconfirmed compensation must keep the prepared provenance");
}

void testApplyRestoredReloadFailureKeepsPrepared() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    tree.runtime()->serviceActive = true;
    // Both the FIC reload and the reload of the restored configuration fail:
    // the compensation is incomplete and the provenance stays active.
    tree.runtime()->reloadFailuresRemaining = 2;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(!policy->apply(), "the apply must fail");

    require(readFile(tree.configPath()) == original,
            "the pre-attempt configuration must be restored on disk");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().isActive(),
            "an unconfirmed compensation must keep the prepared provenance");
}

void testBeforeAfterCollisionRollback() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Port 2222\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(policy->apply(), "the apply must succeed");
    require(readFile(tree.configPath()) ==
                "Port 2222\n"
                "#Port 2222\n"
                "Match User backup\n"
                "    PermitRootLogin yes\n",
            "FIC must replace the first occurrence and comment the second; "
            "the before line of one occurrence may equal the after line of "
            "the other");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) == original,
            "the rollback must restore the exact original without a false "
            "conflict");
}

void testIdenticalDuplicateDirectivesSurviveRestart() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Port 22\n"
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
                "#Port 22\n"
                "#Port 22\n"
                "Match User backup\n"
                "    PermitRootLogin yes\n",
            "FIC must comment out both duplicate occurrences");

    // Daemon restart: the journal with identical afterLine values must
    // reload successfully (writer→reader invariant).
    MutationJournal reloaded(tree.journalPath());
    std::string error;
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1 &&
                reloaded.records().front().status == MutationStatus::Applied,
            "the journal with identical duplicate after lines must load");
    const auto* undo = std::get_if<UndoRestoreSshDirective>(
        &reloaded.records().front().undo.payload);
    require(undo != nullptr && undo->occurrences.size() == 3 &&
                undo->occurrences[1].afterLine == "#Port 22" &&
                undo->occurrences[2].afterLine == "#Port 22",
            "identical duplicate after lines must survive the reload");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) == original,
            "the rollback must restore all three identical originals");
}

void testRepeatedApplyRefusesUntrackedOccurrence() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nMatch User backup\n    PermitRootLogin yes\n");
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy();
    require(policy->apply(), "the first apply must succeed");

    // Structural drift: the admin added a second Port occurrence the journal
    // has no provenance for.
    const std::string drift =
        "Port 2200\nPort 2022\nMatch User backup\n    PermitRootLogin yes\n";
    tree.writeConfig(drift);
    tree.runtime()->tCalls = 0;
    tree.runtime()->preApplyPort = "2200";
    require(!policy->apply(),
            "a repeated apply must refuse to mutate untracked occurrences");

    require(readFile(tree.configPath()) == drift,
            "the untracked occurrence must not be commented or rewritten");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "the failed repeated apply must not change the journal");
    const auto* undo = std::get_if<UndoRestoreSshDirective>(
        &journal.records().front().undo.payload);
    require(undo != nullptr && undo->occurrences.size() == 1 &&
                undo->occurrences.front().beforeLine.has_value() &&
                *undo->occurrences.front().beforeLine == "Port 22" &&
                undo->occurrences.front().afterLine == "Port 2222",
            "the original rollback baseline must be preserved unchanged");

    // The unmatchable drift is reported as a conflict on disable (external
    // target drift semantics), and nothing is written.
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Conflict, report.message);
    require(readFile(tree.configPath()) == drift,
            "the rollback must not touch an unmatchable drifted resource");
}

void testApplyCompensationRacePreservesExternalEdit() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nMatch User backup\n    PermitRootLogin yes\n");
    tree.writePolicyValue("2222");
    JournalOverride overrideGuard(tree.journalPath());

    // The post-write sshd -T verification fails so the compensation path
    // runs; the external actor edits the file after FIC installed its state
    // but before the compensation write.
    const std::string external =
        "Port 2200\nMaxAuthTries 2\nMatch User backup\n    PermitRootLogin yes\n";
    tree.runtime()->failTAfterCall = 1;
    auto policy = tree.makePolicy();
    policy->setBeforeRestoreHook([&tree, external]() {
        writeFile(tree.configPath(), external);
    });

    require(!policy->apply(), "a refused compensation must fail the apply");
    require(readFile(tree.configPath()) == external,
            "the external modification made after the FIC write must be "
            "preserved");
    require(tree.runtime()->reloadCalls == 0,
            "a refused compensation must not reload anything");

    // The provenance of this attempt stays active.
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().isActive(),
            "an unconfirmed compensation must keep the provenance active");
}

void testSshWriterReaderPayloadInvariant() {
    // Every SshDirectiveMutationPlan the production planSetValue() considers
    // valid must survive journal serialize → reload → load with the same
    // semantics (writer→reader invariant).
    const struct {
        const char* name;
        std::string initial;
    } fixtures[] = {
        {"single replacement", "Port 22\n"},
        {"distinct duplicates", "Port 22\nPort 2022\n"},
        {"identical duplicates", "Port 22\nPort 22\nPort 22\n"},
        {"before/after collision", "Port 22\nPort 2222\n"},
        {"insertion case", "PermitRootLogin prohibit-password\n"},
    };
    for (const auto& fixture : fixtures) {
        SshApplyTree tree;
        tree.writeConfig(fixture.initial +
                         "Match User backup\n    PermitRootLogin yes\n");
        SshConfigFileHandler handler(tree.configPath().string());
        require(handler.loadConfig(), "sshd_config must load");
        SshDirectiveMutationPlan plan;
        require(handler.planSetValue("Port", "2222", plan),
                std::string("the production plan must build for fixture: ") +
                    fixture.name);
        require(handler.setValue("Port", "2222"), "the plan must apply");
        require(handler.saveFile(), "the mutated config must save");

        TempTree journalTree("/tmp/fic-ssh-payload-XXXXXX");
        const std::filesystem::path journalPath = journalTree.root / "journal.json";
        MutationId id = 0;
        {
            MutationJournal journal(journalPath);
            std::string error;
            require(journal.load(error), error);
            MutationRecord record;
            record.policy = kSshPortPolicy;
            record.resource = "ssh:" + tree.configPath().string() + ":Port";
            UndoRestoreSshDirective undo;
            undo.parameter = plan.parameter;
            undo.appliedValue = plan.appliedValue;
            undo.occurrences = plan.occurrences;
            record.undo = UndoAction{MutationBackend::Ssh, std::move(undo)};
            require(journal.prepareMutation(record, id, error), error);
            require(journal.setStatus(id, MutationStatus::Applied, error),
                    error);
        }
        MutationJournal reloaded(journalPath);
        std::string error;
        require(reloaded.load(error), error);
        const MutationRecord* stored = nullptr;
        for (const MutationRecord& candidate : reloaded.records()) {
            if (candidate.id == id) {
                stored = &candidate;
                break;
            }
        }
        require(stored != nullptr, "the record must survive the reload");
        const auto* undo =
            std::get_if<UndoRestoreSshDirective>(&stored->undo.payload);
        require(undo != nullptr, "the ssh payload must survive the reload");
        require(undo->parameter == plan.parameter &&
                    undo->appliedValue == plan.appliedValue &&
                    undo->occurrences.size() == plan.occurrences.size(),
                std::string("payload identity must survive reload: ") +
                    fixture.name);
        for (std::size_t index = 0; index < plan.occurrences.size(); ++index) {
            require(plan.occurrences[index].beforeLine ==
                        undo->occurrences[index].beforeLine &&
                        plan.occurrences[index].afterLine ==
                            undo->occurrences[index].afterLine,
                    std::string("occurrence lines must survive reload: ") +
                        fixture.name);
        }
    }
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
        {"repeated apply refuses untracked occurrence",
         testRepeatedApplyRefusesUntrackedOccurrence},
        {"before/after collision rollback",
         testBeforeAfterCollisionRollback},
        {"identical duplicate directives survive restart",
         testIdenticalDuplicateDirectivesSurviveRestart},
        {"ssh writer reader payload invariant",
         testSshWriterReaderPayloadInvariant},
        {"apply compensation race preserves external edit",
         testApplyCompensationRacePreservesExternalEdit},
        {"apply reload failure restores the pre-attempt state",
         testApplyReloadFailureRestoresPreAttemptState},
        {"commit failure fails the apply and keeps prepared",
         testCommitFailureFailsApplyAndKeepsPrepared},
        {"apply concurrent modification is refused",
         testApplyConcurrentModificationRefused},
        {"apply full compensation discards prepared",
         testApplyCompensationFullSuccessDiscardsPrepared},
        {"apply restored validation failure keeps prepared",
         testApplyRestoredValidationFailureKeepsPrepared},
        {"apply restored reload failure keeps prepared",
         testApplyRestoredReloadFailureKeepsPrepared},
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