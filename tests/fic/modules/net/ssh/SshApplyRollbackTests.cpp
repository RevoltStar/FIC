// Tests for the FIC-managed SSH apply path: explicit ownership via the
// FIC managed block in sshd_config, FIC_DISABLED wrappers for multi-value
// directives, transactional apply (CAS write, durability, sshd -T, reload,
// compensation) and crash-consistent journaling.
#include "modules/net/ssh/Ssh.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/policies/NET_ssh_port.h"
#include "modules/net/ssh/policies/NET_ssh_root_login.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"
#include "rollback/RollbackExecutor.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <fic/policy/Policy.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
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

// PLACEHOLDER_REST

// Content-driven fake of sshd: the -T output is derived from the actual
// sshd_config passed via -f, so the effective state always follows the file
// state the way the real daemon does (FIC markers are comments, Match
// sections are not part of the main effective configuration).
struct FakeSshRuntime {
    bool sshdFails = false;
    // When > 0 every sshd -T call with an ordinal >= this value (1-based)
    // fails; 0 means never.
    int failTAfterCall = 0;
    int tCalls = 0;
    bool serviceActive = false;
    bool reloadFails = false;
    int reloadCalls = 0;
};

std::string fakeEffectiveOutput(const std::string& configContent) {
    std::istringstream lines(configContent);
    std::string line;
    std::vector<std::string> ports;
    std::string rootLogin = "prohibit-password";
    bool rootLoginSeen = false;
    while (std::getline(lines, line)) {
        const std::size_t comment = line.find('#');
        const std::string trimmed =
            comment == std::string::npos ? line : line.substr(0, comment);
        if (trimmed.find_first_not_of(" \t") == std::string::npos) {
            continue;
        }
        std::istringstream fields(trimmed);
        std::string keyword;
        fields >> keyword;
        std::transform(keyword.begin(), keyword.end(), keyword.begin(),
                       [](unsigned char ch) { return std::tolower(ch); });
        if (keyword == "match") {
            break; // main effective configuration ends at the first Match
        }
        std::string value;
        fields >> value;
        if (keyword == "port" && !value.empty()) {
            ports.push_back(value);
        } else if (keyword == "permitrootlogin" && !value.empty() &&
                   !rootLoginSeen) {
            rootLogin = value;
            rootLoginSeen = true;
        }
    }
    std::string output;
    for (const std::string& port : ports) {
        output += "port " + port + "\n";
    }
    output += "permitrootlogin " + rootLogin + "\n";
    output += "maxauthtries 3\n";
    output += "pubkeyauthentication yes\n";
    return output;
}

} // namespace

namespace {

template <typename PolicyT>
class PolicyUnderTest : public PolicyT {
public:
    PolicyUnderTest(
        const fic::platform::SshPlatformConfig& platformConfig,
        const fic::platform::PlatformExecutableResolver& executables)
        : PolicyT(platformConfig, executables) {
        this->moduleName = "NET";
        this->submoduleName = "SshEdit";
        this->moduleConf = std::make_unique<ModuleConfigFileHandler>(
            platformConfig.configPath.parent_path() / "config",
            this->moduleName);
        this->moduleConf->loadConfig();
    }

    void setRunner(SshCommandRunner runnerValue) {
        this->commandRunner_ = std::move(runnerValue);
    }

    void setBeforeWriteHook(std::function<void()> hook) {
        this->beforeWriteHook_ = std::move(hook);
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

    void writePolicyValue(const std::string& policy, const std::string& value) {
        writeFile(tree.root / "config" / "NET.conf",
                  policy + ".status=ENABLE\n" + policy + ".value=" + value + "\n");
    }

    SshCommandRunner runner() const {
        std::shared_ptr<FakeSshRuntime> runtime = runtime_;
        const std::string configPathString = configPath().string();
        return [runtime, configPathString](const std::string&,
                         const std::vector<std::string>& arguments,
                         const ProcessOptions&) {
            if (std::find(arguments.begin(), arguments.end(), "-T") !=
                arguments.end()) {
                ++runtime->tCalls;
                if (runtime->sshdFails ||
                    (runtime->failTAfterCall > 0 &&
                     runtime->tCalls >= runtime->failTAfterCall)) {
                    return sshFailing("sshd -T refused the configuration");
                }
                std::string content;
                for (std::size_t index = 0; index + 1 < arguments.size();
                     ++index) {
                    if (arguments[index] == "-f") {
                        content = readFile(configPathString);
                    }
                }
                return sshSuccess(fakeEffectiveOutput(content));
            }
            if (std::find(arguments.begin(), arguments.end(), "is-active") !=
                arguments.end()) {
                return runtime->serviceActive ? sshSuccess() : sshInactive();
            }
            if (std::find(arguments.begin(), arguments.end(), "reload") !=
                arguments.end()) {
                ++runtime->reloadCalls;
                return runtime->reloadFails ? sshFailing("reload failed")
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

    template <typename PolicyT>
    std::unique_ptr<PolicyUnderTest<PolicyT>> makePolicy() {
        auto policy = std::make_unique<PolicyUnderTest<PolicyT>>(
            platformConfig(), *executables_);
        policy->setRunner(runner());
        return policy;
    }

    SshRollbackOptions rollbackOptions() const {
        SshRollbackOptions options;
        options.configPath = configPath();
        options.includeBasePath = tree.root;
        options.serviceUnits = {"ssh.service", "sshd.service"};
        options.executables = executables_.get();
        options.runner = runner();
        return options;
    }

    RollbackExecutorDeps rollbackDeps() const {
        RollbackExecutorDeps value;
        SshRollbackOptions options = this->rollbackOptions();
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

const PolicyRef kSshPortPolicy{"NET", "SshEdit", "ssh_port"};
const PolicyRef kSshRootLoginPolicy{"NET", "SshEdit", "ssh_root_login"};

bool fileContains(const std::filesystem::path& path,
                  const std::string& needle) {
    return readFile(path).find(needle) != std::string::npos;
}

std::vector<std::string> splitLines(const std::string& content) {
    std::vector<std::string> lines;
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    return lines;
}

bool markerOnlyFile(const std::filesystem::path& path) {
    const std::string content = readFile(path);
    return content.find("#@FIC_") == std::string::npos;
}

MutationId recordPreparedSsh(const PolicyRef& policy,
                             const std::string& resource,
                             const UndoRemoveSshManagedPolicy& undo) {
    std::string error;
    MutationId id = 0;
    require(recordPreparedMutation(
                policy, resource,
                UndoAction{MutationBackend::Ssh, undo}, id, error),
            error);
    return id;
}

void testCompliantEffectiveStateCausesNoMutation() {
    SshApplyTree tree;
    const std::string original = "Port 22\n";
    tree.writeConfig(original);
    tree.writePolicyValue("ssh_port", "22");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "an already compliant effective state must pass");

    require(readFile(tree.configPath()) == original,
            "a compliant effective state must not be written or owned");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(),
            "no mutation record must exist for a compliant state");
    require(tree.runtime()->reloadCalls == 0,
            "no reload must happen for a compliant state");
}

void testApplyFailsWhenEffectiveStateUnknown() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\n");
    tree.writePolicyValue("ssh_port", "2222");
    tree.runtime()->sshdFails = true;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(!policy->apply(),
            "an undeterminable effective state must fail the apply closed");

    require(readFile(tree.configPath()) == "Port 22\n",
            "no file mutation must happen when the effective state is unknown");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(),
            "no mutation record must exist without a real mutation");
}

void testUnsupportedPolicySemanticsIsRefused() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    policy->policyName = "ssh_unknown"; // no declared directive semantics
    require(!policy->apply(),
            "an unclassified SSH policy must fail closed");

    require(readFile(tree.configPath()) == "Port 22\n",
            "an unsupported policy must not touch sshd_config");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().empty(),
            "an unsupported policy must not record a mutation");
}

void testApplyWrapsPortOccurrencesAndRecordsPayload() {
    SshApplyTree tree;
    const std::string original =
        "# user comment\n"
        "Port 22\n"
        "Port 2022\n";
    tree.writeConfig(original);
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the apply must succeed");

    const std::string content = readFile(tree.configPath());
    require(content.find(kSshBlockBeginPrefix) != std::string::npos,
            "the FIC managed block must be present");
    require(content.find("\nPort 2222\n") != std::string::npos,
            "the managed block must carry the applied value");
    require(content.find("#@FIC_DISABLED_LINE@Port 22") != std::string::npos &&
                content.find("#@FIC_DISABLED_LINE@Port 2022") !=
                    std::string::npos,
            "both user Port lines must be disabled with FIC wrappers");
    require(content.find("# user comment") != std::string::npos,
            "user comments must be preserved");

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
    const auto* undo = std::get_if<UndoRemoveSshManagedPolicy>(
        &record.undo.payload);
    require(undo != nullptr, "the payload must be the managed-policy undo");
    require(undo->policyName == "ssh_port" && undo->directive == "Port" &&
                undo->appliedValue == "2222",
            "the payload must describe the applied ownership");
    require(undo->disabledMutationIds.size() == 2,
            "the payload must list the wrapper provenance ids");
    for (const std::string& id : undo->disabledMutationIds) {
        require(content.find("mutation=" + id) != std::string::npos,
                "every payload id must be present in the file markers");
    }
}

void testRepeatedApplyIsIdempotent() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPort 2022\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the first apply must succeed");
    const std::string afterFirst = readFile(tree.configPath());

    require(policy->apply(), "the repeated apply must succeed");
    require(readFile(tree.configPath()) == afterFirst,
            "an idempotent re-apply must not change the file");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1,
            "an idempotent re-apply must not add journal records");
    require(journal.records().front().status == MutationStatus::Applied,
            "the original record must stay applied");
}

void testValueChangeRollsBackPreviousStateAndReapplies() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPort 2022\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the initial apply must succeed");
    MutationId firstId = 0;
    {
        MutationJournal journal(tree.journalPath());
        std::string error;
        require(journal.load(error), error);
        require(journal.records().size() == 1, "one record after first apply");
        firstId = journal.records().front().id;
    }

    tree.writePolicyValue("ssh_port", "2323");
    auto changedPolicy = tree.makePolicy<NET_ssh_port>();
    require(changedPolicy->apply(), "the value change apply must succeed");

    const std::string content = readFile(tree.configPath());
    require(content.find("Port 2323") != std::string::npos,
            "the managed block must carry the new value");
    require(content.find("Port 2222") == std::string::npos,
            "the previous applied value must be gone");
    require(content.find("#@FIC_DISABLED_LINE@Port 22") != std::string::npos &&
                content.find("#@FIC_DISABLED_LINE@Port 2022") !=
                    std::string::npos,
            "the user Port lines must be disabled again after re-apply");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 2,
            "the rolled-back and the new record must be kept");
    const MutationRecord& oldRecord = journal.records().front();
    require(oldRecord.id == firstId &&
                oldRecord.status == MutationStatus::RolledBack,
            "the previous owned state must be marked rolled back");
    const MutationRecord& newRecord = journal.records().back();
    require(newRecord.status == MutationStatus::Applied,
            "the new state must be committed");
    const auto* undo = std::get_if<UndoRemoveSshManagedPolicy>(
        &newRecord.undo.payload);
    require(undo != nullptr && undo->appliedValue == "2323" &&
                undo->disabledMutationIds.size() == 2,
            "the new payload must own the fresh wrappers");
}

void testMatchSectionsArePreserved() {
    SshApplyTree tree;
    const std::string original =
        "Port 22\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the apply must succeed");

    const std::string content = readFile(tree.configPath());
    require(content.find("Match User backup") != std::string::npos,
            "the Match section must be preserved");
    require(content.find("    PermitRootLogin yes") != std::string::npos,
            "Match section content must be preserved verbatim");

    // The rollback must also restore the exact original structure.
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    const std::string restored = readFile(tree.configPath());
    require(restored == original,
            "apply+rollback must restore the original sshd_config "
            "byte-for-byte, Match section included");
}

// ---- Strict FIC marker grammar and symmetric provenance regression tests ----

void testForeignDirectiveInsideDisabledBlockIsRefused() {
    SshApplyTree tree;
    const std::string content =
        "Port 22\n"
        "#@FIC_DISABLED_BEGIN policy=ssh_port mutation=FIC-x@\n"
        "#@FIC_DISABLED_LINE@Port 2022\n"
        "X11Forwarding no\n"
        "#@FIC_DISABLED_END policy=ssh_port mutation=FIC-x@\n";
    tree.writeConfig(content);

    SshManagedModel model;
    std::string error;
    require(parseSshManagedModel(splitLines(content), model, error) ==
                SshManagedParseStatus::Malformed,
            "a foreign directive inside a FIC_DISABLED block must be malformed");

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(!rollback.ok && rollback.conflict, rollback.message);
    require(readFile(tree.configPath()) == content,
            "the malformed owned range must be left byte-for-byte unchanged");
}

void testForeignLineInsideManagedBlockIsRefused() {
    SshApplyTree tree;
    const std::string content =
        "#@FIC_SSH_BLOCK_BEGIN version=1@\n"
        "#@FIC_POLICY_BEGIN name=ssh_port@\n"
        "Port 2222\n"
        "#@FIC_POLICY_END name=ssh_port@\n"
        "Banner /etc/ssh/banner\n"
        "#@FIC_SSH_BLOCK_END@\n"
        "Port 22\n";
    tree.writeConfig(content);

    SshManagedModel model;
    std::string error;
    require(parseSshManagedModel(splitLines(content), model, error) ==
                SshManagedParseStatus::Malformed,
            "a foreign directive inside the FIC managed block must be malformed");

    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());
    auto policy = tree.makePolicy<NET_ssh_port>();
    require(!policy->apply(),
            "a malformed managed block must fail the apply closed");
    require(readFile(tree.configPath()) == content,
            "the malformed managed block must be left unchanged");
    MutationJournal journal(tree.journalPath());
    std::string journalError;
    require(journal.load(journalError), journalError);
    require(journal.records().empty(),
            "a refused apply must not record a mutation");
}

void testOrphanManagedBlockWithCompliantValueFailsClosed() {
    SshApplyTree tree;
    const std::string content =
        "#@FIC_SSH_BLOCK_BEGIN version=1@\n"
        "#@FIC_POLICY_BEGIN name=ssh_port@\n"
        "Port 2222\n"
        "#@FIC_POLICY_END name=ssh_port@\n"
        "#@FIC_SSH_BLOCK_END@\n"
        "# user comment\n";
    tree.writeConfig(content);
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(!policy->apply(),
            "orphan FIC markers must fail the apply closed even when the "
            "effective value is compliant");
    require(readFile(tree.configPath()) == content,
            "the orphan FIC state must be left unchanged");
    MutationJournal journal(tree.journalPath());
    std::string journalError;
    require(journal.load(journalError), journalError);
    require(journal.records().empty(),
            "orphan FIC markers must not produce a journal record");
    require(tree.runtime()->reloadCalls == 0,
            "orphan FIC markers must not trigger a reload");
}

void testPreparedAfterCrashIsFinishedAndCommitted() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPort 2022\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the initial apply must succeed");
    const std::string owned = readFile(tree.configPath());

    // Simulate a crash after prepare: a Prepared record whose payload
    // matches the FIC-owned file state.
    UndoRemoveSshManagedPolicy stale;
    stale.policyName = "ssh_port";
    stale.directive = "Port";
    stale.appliedValue = "2222";
    {
        SshConfigFileHandler handler(tree.configPath().string());
        require(handler.loadConfig(), "load must succeed");
        SshManagedModel model;
        std::string error;
        require(parseSshManagedModel(handler.lines(), model, error) ==
                    SshManagedParseStatus::Ok,
                error);
        for (const SshDisabledBlock& disabled : model.disabled) {
            if (disabled.policy == "ssh_port") {
                stale.disabledMutationIds.push_back(disabled.mutationId);
            }
        }
    }
    recordPreparedSsh(kSshPortPolicy,
                      "ssh:" + tree.configPath().string() + ":Port", stale);

    require(policy->apply(),
            "the apply must finish the interrupted transaction");
    require(readFile(tree.configPath()) == owned,
            "recovery must not change the already-owned state");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    for (const MutationRecord& record : journal.records()) {
        require(record.status == MutationStatus::Applied,
                "every record must be committed after recovery");
    }
}

void testStalePreparedRecordOnForeignConfigIsDiscarded() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    // A Prepared record left behind before any file mutation: the
    // configuration carries no FIC markers at all.
    UndoRemoveSshManagedPolicy stale;
    stale.policyName = "ssh_port";
    stale.directive = "Port";
    stale.appliedValue = "2222";
    recordPreparedSsh(kSshPortPolicy,
                      "ssh:" + tree.configPath().string() + ":Port", stale);

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the stale prepared record must be discarded");

    require(fileContains(tree.configPath(), kSshBlockBeginPrefix),
            "the fresh apply must own the configuration");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "only the fresh mutation must be active");
}

void testPreparedWithDriftedBlockFailsClosed() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the initial apply must succeed");
    const std::string owned = readFile(tree.configPath());

    // A Prepared record whose applied value no longer matches the file
    // block (the block was manually edited after the prepare).
    UndoRemoveSshManagedPolicy drifted;
    drifted.policyName = "ssh_port";
    drifted.directive = "Port";
    drifted.appliedValue = "9999";
    recordPreparedSsh(kSshPortPolicy,
                      "ssh:" + tree.configPath().string() + ":Port", drifted);

    require(!policy->apply(),
            "a drifted prepared mutation must fail closed");
    require(readFile(tree.configPath()) == owned,
            "the file must not be touched on drift");
}

void testApplyConcurrentModificationIsRefused() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    policy->setBeforeWriteHook([path = tree.configPath()]() {
        // An external writer replaces the file right before the atomic
        // write; the CAS write must refuse and compensate.
        writeFile(path, "Port 22\n# external concurrent edit\n");
    });
    require(!policy->apply(),
            "a concurrent modification must fail the apply");

    require(readFile(tree.configPath()) ==
                "Port 22\n# external concurrent edit\n",
            "the external edit must be preserved");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    for (const MutationRecord& record : journal.records()) {
        require(!record.isActive(),
                "a refused apply must not keep an active record");
    }
}

void testApplyReloadFailureRestoresPreAttemptState() {
    SshApplyTree tree;
    const std::string original = "Port 22\n";
    tree.writeConfig(original);
    tree.writePolicyValue("ssh_port", "2222");
    tree.runtime()->serviceActive = true;
    tree.runtime()->reloadFails = true;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(!policy->apply(), "a failed reload must fail the apply");

    require(readFile(tree.configPath()) == original,
            "the compensation must restore the pre-attempt content");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    for (const MutationRecord& record : journal.records()) {
        require(!record.isActive(),
                "a compensated apply must not keep an active record");
    }
}

void testApplyValidationFailureAfterWriteCompensates() {
    SshApplyTree tree;
    const std::string original = "Port 22\n";
    tree.writeConfig(original);
    tree.writePolicyValue("ssh_port", "2222");
    // Call 1 is the pre-check; call 2 (after the write) must fail.
    tree.runtime()->failTAfterCall = 2;
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(!policy->apply(),
            "a post-write sshd -T failure must fail the apply");

    require(readFile(tree.configPath()) == original,
            "the compensation must restore the pre-attempt content");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    for (const MutationRecord& record : journal.records()) {
        require(!record.isActive(),
                "a compensated apply must not keep an active record");
    }
}

void testMultiPolicyIsolationUnderRollback() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPermitRootLogin yes\n");
    writeFile(tree.tree.root / "config" / "NET.conf",
              "ssh_port.status=ENABLE\nssh_port.value=2222\n"
              "ssh_root_login.status=ENABLE\nssh_root_login.value=no\n");
    JournalOverride overrideGuard(tree.journalPath());

    auto port = tree.makePolicy<NET_ssh_port>();
    auto rootLogin = tree.makePolicy<NET_ssh_root_login>();
    require(port->apply(), "the port policy must apply");
    require(rootLogin->apply(), "the root login policy must apply");

    const std::string bothOwned = readFile(tree.configPath());
    require(bothOwned.find("name=ssh_port") != std::string::npos &&
                bothOwned.find("name=ssh_root_login") != std::string::npos,
            "both policies must own their sub-blocks");

    // Rolling back one policy must leave the other policy owned.
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);

    const std::string content = readFile(tree.configPath());
    require(content.find("name=ssh_port") == std::string::npos,
            "the port sub-block must be removed");
    require(content.find("name=ssh_root_login") != std::string::npos &&
                content.find("\nPermitRootLogin no\n") != std::string::npos,
            "the root login sub-block must stay intact");
    require(content.find("\nPort 22\n") != std::string::npos,
            "the user port lines must be restored");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    bool rootLoginActive = false;
    for (const MutationRecord& record : journal.records()) {
        if (record.policy == kSshRootLoginPolicy) {
            rootLoginActive = record.status == MutationStatus::Applied;
        }
    }
    require(rootLoginActive,
            "the other policy's record must remain applied");
}

void testRollbackConflictsWhenExpectedWrapperIsMissing() {
    SshApplyTree tree;
    const std::string content =
        "#@FIC_SSH_BLOCK_BEGIN version=1@\n"
        "#@FIC_POLICY_BEGIN name=ssh_port@\n"
        "Port 2222\n"
        "#@FIC_POLICY_END name=ssh_port@\n"
        "#@FIC_SSH_BLOCK_END@\n"
        "#@FIC_DISABLED_BEGIN policy=ssh_port mutation=FIC-a@\n"
        "#@FIC_DISABLED_LINE@Port 22\n"
        "#@FIC_DISABLED_END policy=ssh_port mutation=FIC-a@\n"
        "Port 2022\n";
    tree.writeConfig(content);

    // The journal payload expects wrappers A and B, but only A is present:
    // a partial owned representation must never be completed or removed.
    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    undo.disabledMutationIds = {"FIC-a", "FIC-b"};

    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(!rollback.ok && rollback.conflict, rollback.message);
    require(readFile(tree.configPath()) == content,
            "the managed policy block and wrapper A must stay untouched");
}

void testRollbackConflictsOnUnknownWrapper() {
    SshApplyTree tree;
    const std::string content =
        "#@FIC_SSH_BLOCK_BEGIN version=1@\n"
        "#@FIC_POLICY_BEGIN name=ssh_port@\n"
        "Port 2222\n"
        "#@FIC_POLICY_END name=ssh_port@\n"
        "#@FIC_SSH_BLOCK_END@\n"
        "#@FIC_DISABLED_BEGIN policy=ssh_port mutation=FIC-x@\n"
        "#@FIC_DISABLED_LINE@Port 22\n"
        "#@FIC_DISABLED_END policy=ssh_port mutation=FIC-x@\n";
    tree.writeConfig(content);

    // The payload knows no wrappers, the file has one: the wrapper must not
    // be uncommented and the block must not be removed.
    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";

    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(!rollback.ok && rollback.conflict, rollback.message);
    require(readFile(tree.configPath()) == content,
            "the unknown wrapper must be left untouched");
}

void testRollbackConflictsOnDuplicateWrapperId() {
    SshApplyTree tree;
    const std::string content =
        "#@FIC_SSH_BLOCK_BEGIN version=1@\n"
        "#@FIC_POLICY_BEGIN name=ssh_port@\n"
        "Port 2222\n"
        "#@FIC_POLICY_END name=ssh_port@\n"
        "#@FIC_SSH_BLOCK_END@\n"
        "#@FIC_DISABLED_BEGIN policy=ssh_port mutation=FIC-a@\n"
        "#@FIC_DISABLED_LINE@Port 22\n"
        "#@FIC_DISABLED_END policy=ssh_port mutation=FIC-a@\n"
        "#@FIC_DISABLED_BEGIN policy=ssh_port mutation=FIC-a@\n"
        "#@FIC_DISABLED_LINE@Port 2022\n"
        "#@FIC_DISABLED_END policy=ssh_port mutation=FIC-a@\n";
    tree.writeConfig(content);

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    undo.disabledMutationIds = {"FIC-a"};

    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(!rollback.ok && rollback.conflict, rollback.message);
    require(readFile(tree.configPath()) == content,
            "duplicated wrapper ids must be left untouched");
}

void testRollbackConflictsOnDuplicatePayloadId() {
    SshApplyTree tree;
    const std::string content =
        "#@FIC_SSH_BLOCK_BEGIN version=1@\n"
        "#@FIC_POLICY_BEGIN name=ssh_port@\n"
        "Port 2222\n"
        "#@FIC_POLICY_END name=ssh_port@\n"
        "#@FIC_SSH_BLOCK_END@\n"
        "#@FIC_DISABLED_BEGIN policy=ssh_port mutation=FIC-a@\n"
        "#@FIC_DISABLED_LINE@Port 22\n"
        "#@FIC_DISABLED_END policy=ssh_port mutation=FIC-a@\n";
    tree.writeConfig(content);

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    undo.disabledMutationIds = {"FIC-a", "FIC-a"};

    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(!rollback.ok && rollback.conflict, rollback.message);
    require(readFile(tree.configPath()) == content,
            "a corrupted journal payload must be left untouched");
}

void testApplyRollbackRestoresExactOriginalBytes() {
    SshApplyTree tree;
    const std::string original =
        "# user comment\n"
        "Port 22\n"
        "Port 2022\n"
        "\n"
        "PermitRootLogin yes\n";
    tree.writeConfig(original);
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the apply must succeed");
    require(readFile(tree.configPath()) != original,
            "the apply must actually own the configuration");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) == original,
            "apply followed by rollback must restore the original "
            "sshd_config byte-for-byte");
}

void testOtherPolicyBlockUntouchedWhenOnePolicyRolledBack() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPermitRootLogin yes\n");
    writeFile(tree.tree.root / "config" / "NET.conf",
              "ssh_port.status=ENABLE\nssh_port.value=2222\n"
              "ssh_root_login.status=ENABLE\nssh_root_login.value=no\n");
    JournalOverride overrideGuard(tree.journalPath());

    auto port = tree.makePolicy<NET_ssh_port>();
    auto rootLogin = tree.makePolicy<NET_ssh_root_login>();
    require(port->apply() && rootLogin->apply(), "both policies must apply");

    const std::string bothOwned = readFile(tree.configPath());
    const std::string rootBlockBegin = "#@FIC_POLICY_BEGIN name=ssh_root_login@";
    const std::string rootBlockEnd = "#@FIC_POLICY_END name=ssh_root_login@";
    const std::size_t beginPos = bothOwned.find(rootBlockBegin);
    const std::size_t endPos = bothOwned.find(rootBlockEnd);
    require(beginPos != std::string::npos && endPos != std::string::npos &&
                endPos > beginPos,
            "the root login sub-block must be present after both applies");
    const std::string rootBlock = bothOwned.substr(
        beginPos, endPos + rootBlockEnd.size() - beginPos);

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);

    const std::string after = readFile(tree.configPath());
    require(after.find(rootBlock) != std::string::npos,
            "the other policy's sub-block must remain byte-for-byte intact");
    require(after.find("#@FIC_DISABLED") == std::string::npos,
            "the rolled back policy's wrappers must be gone");
    require(after.find("\nPort 22\n") != std::string::npos,
            "the user Port lines must be restored");
}

void testSshPoliciesAreRollbackWired() {
    SshApplyTree tree;
    const std::vector<std::pair<std::string, std::string>> expected = {
        {"ssh_port", "Port"},
        {"ssh_root_login", "PermitRootLogin"}};

    std::vector<std::unique_ptr<Ssh>> policies;
    policies.push_back(std::make_unique<NET_ssh_port>(
        tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_root_login>(
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
            std::cerr << "FAIL: runtime paths initialization: " << error
                      << '\n';
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
        {"unsupported policy semantics is refused",
         testUnsupportedPolicySemanticsIsRefused},
        {"apply wraps port occurrences and records payload",
         testApplyWrapsPortOccurrencesAndRecordsPayload},
        {"repeated apply is idempotent", testRepeatedApplyIsIdempotent},
        {"value change rolls back previous state and reapplies",
         testValueChangeRollsBackPreviousStateAndReapplies},
        {"match sections are preserved", testMatchSectionsArePreserved},
        {"foreign directive inside disabled block is refused",
         testForeignDirectiveInsideDisabledBlockIsRefused},
        {"foreign line inside managed block is refused",
         testForeignLineInsideManagedBlockIsRefused},
        {"orphan managed block with compliant value fails closed",
         testOrphanManagedBlockWithCompliantValueFailsClosed},
        {"rollback conflicts when expected wrapper is missing",
         testRollbackConflictsWhenExpectedWrapperIsMissing},
        {"rollback conflicts on unknown wrapper",
         testRollbackConflictsOnUnknownWrapper},
        {"rollback conflicts on duplicate wrapper id",
         testRollbackConflictsOnDuplicateWrapperId},
        {"rollback conflicts on duplicate payload id",
         testRollbackConflictsOnDuplicatePayloadId},
        {"apply rollback restores exact original bytes",
         testApplyRollbackRestoresExactOriginalBytes},
        {"other policy block untouched when one policy rolled back",
         testOtherPolicyBlockUntouchedWhenOnePolicyRolledBack},
        {"prepared after crash is finished and committed",
         testPreparedAfterCrashIsFinishedAndCommitted},
        {"stale prepared record on foreign config is discarded",
         testStalePreparedRecordOnForeignConfigIsDiscarded},
        {"prepared with drifted block fails closed",
         testPreparedWithDriftedBlockFailsClosed},
        {"apply concurrent modification is refused",
         testApplyConcurrentModificationIsRefused},
        {"apply reload failure restores pre-attempt state",
         testApplyReloadFailureRestoresPreAttemptState},
        {"apply validation failure after write compensates",
         testApplyValidationFailureAfterWriteCompensates},
        {"multi-policy isolation under rollback",
         testMultiPolicyIsolationUnderRollback},
        {"ssh policies are rollback wired", testSshPoliciesAreRollbackWired}
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
