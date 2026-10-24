// Tests for the FIC-managed SSH apply path: explicit ownership via the
// FIC managed block in sshd_config, FIC_DISABLED wrappers for multi-value
// directives, transactional apply (CAS write, durability, sshd -T, reload,
// compensation) and crash-consistent journaling.
#include "modules/net/ssh/Ssh.h"
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/net/ssh/SshRollback.h"
#include "modules/net/ssh/SshRuntime.h"
#include "modules/net/ssh/SshResourceLock.h"
#include <future>
#include "modules/net/ssh/policies/NET_ssh_port.h"
#include "modules/net/ssh/policies/NET_ssh_max_auth_tries.h"
#include "modules/net/ssh/policies/NET_ssh_pubkey_auth.h"
#include "modules/net/ssh/policies/NET_ssh_root_login.h"
#include "modules/net/ssh/policies/NET_ssh_use_pam.h"
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
    std::string usePam = "no";
    bool usePamSeen = false;
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
        } else if (keyword == "usepam" && !value.empty() && !usePamSeen) {
            usePam = value;
            usePamSeen = true;
        }
    }
    std::string output;
    for (const std::string& port : ports) {
        output += "port " + port + "\n";
    }
    output += "permitrootlogin " + rootLogin + "\n";
    output += "maxauthtries 3\n";
    output += "pubkeyauthentication yes\n";
    output += "usepam " + usePam + "\n";
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
        value.pamServiceRouting =
            fic::platform::SshPamServiceRouting::LegacyExecutableName;
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
const PolicyRef kSshUsePamPolicy{"NET", "SshEdit", "ssh_use_pam"};

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

void testUsePamApplyAndRollback() {
    SshApplyTree tree;
    JournalOverride overrideGuard(tree.journalPath());
    tree.writePolicyValue("ssh_use_pam", "yes");
    const std::string original = "# vendor\nUsePAM no\nUsePAM yes\n";
    tree.writeConfig(original);
    auto policy = tree.makePolicy<NET_ssh_use_pam>();
    require(policy->apply(), "UsePAM policy must repair the first effective no");
    const std::string applied = readFile(tree.configPath());
    require(applied.find(original) != std::string::npos &&
                applied.find("UsePAM yes") < applied.find("UsePAM no"),
            "the owned first value must shadow unchanged foreign sources");
    require(applied.find("\nUsePAM yes\n") != std::string::npos,
            "the owned UsePAM yes must be present");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1 &&
                journal.records().front().status == MutationStatus::Applied,
            "UsePAM mutation must commit one journal record");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshUsePamPolicy, "UsePAM", tree.rollbackDeps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()) == original,
            "UsePAM rollback must restore only FIC-owned changes");
}

void testUsePamAlreadyCompliantIsUnowned() {
    SshApplyTree tree;
    JournalOverride overrideGuard(tree.journalPath());
    tree.writePolicyValue("ssh_use_pam", "yes");
    const std::string original = "# vendor\nUsePAM yes\n";
    tree.writeConfig(original);
    auto policy = tree.makePolicy<NET_ssh_use_pam>();
    require(policy->apply(), "foreign UsePAM yes must be compliant");
    require(readFile(tree.configPath()) == original,
            "compliant foreign UsePAM must stay untouched");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error) && journal.records().empty(),
            "compliant foreign UsePAM must not be journaled");
}

void testUsePamShadowsEarlierIncludeWithoutEditingIt() {
    SshApplyTree tree;
    JournalOverride overrideGuard(tree.journalPath());
    tree.writePolicyValue("ssh_use_pam", "yes");
    const std::string original = "Include vendor.conf\n# vendor comment\n";
    tree.writeConfig(original);
    writeFile(tree.tree.root / "vendor.conf", "UsePAM no\n");
    auto policy = tree.makePolicy<NET_ssh_use_pam>();
    require(policy->apply(), "UsePAM must be placed before an earlier Include");
    const std::string applied = readFile(tree.configPath());
    require(applied.find("UsePAM yes") < applied.find("Include vendor.conf") &&
                readFile(tree.tree.root / "vendor.conf") == "UsePAM no\n",
            "FIC must shadow, not rewrite, the vendor Include");
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
            "failed post-write validation must conditionally restore original bytes");
    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size()==1 && journal.records()[0].status==MutationStatus::Prepared,
            "a restored file is not proof that no install/runtime effect happened");
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

// Partial disappearance plus a value change: the old rollback releases only
// the remaining owned artifacts, and the new value is applied to the actual
// current configuration. The historically disappeared line is never
// reconstructed.
void testValueChangeReleasesOnlyRemainingOwnedWrappers() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPort 2022\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the initial apply must succeed");

    // Externally remove the second wrapper entirely (its disabled line goes
    // away with it); the managed block and the first wrapper stay.
    const std::string owned = readFile(tree.configPath());
    std::string releasedId;
    {
        SshConfigFileHandler handler(tree.configPath().string());
        require(handler.loadConfig(), "load must succeed");
        SshManagedModel model;
        std::string error;
        require(parseSshManagedModel(handler.lines(), model, error) ==
                    SshManagedParseStatus::Ok,
                error);
        require(model.disabled.size() == 2, "two wrappers after the apply");
        releasedId = model.disabled.back().mutationId;
    }
    {
        std::vector<std::string> kept;
        bool skipping = false;
        for (const std::string& line : splitLines(owned)) {
            if (!skipping && line.rfind(kSshDisabledBeginPrefix, 0) == 0 &&
                line.find("mutation=" + releasedId) != std::string::npos) {
                skipping = true;
                continue;
            }
            if (skipping) {
                if (line.rfind(kSshDisabledEndPrefix, 0) == 0) {
                    skipping = false;
                }
                continue;
            }
            kept.push_back(line);
        }
        std::string joined;
        for (const std::string& line : kept) {
            joined += line;
            joined += '\n';
        }
        tree.writeConfig(joined);
    }

    tree.writePolicyValue("ssh_port", "2323");
    auto changedPolicy = tree.makePolicy<NET_ssh_port>();
    require(changedPolicy->apply(), "the value change must succeed");

    const std::string content = readFile(tree.configPath());
    require(content.find("Port 2323") != std::string::npos,
            "the managed block must carry the new value");
    require(content.find("Port 2222") == std::string::npos,
            "the previous applied value must be gone");
    require(content.find("#@FIC_DISABLED_LINE@Port 22") != std::string::npos,
            "the surviving conflicting line must be wrapped again");
    require(content.find("Port 2022") == std::string::npos,
            "the externally removed historical line must not be reconstructed");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 2,
            "the rolled-back and the new record must be kept");
    require(journal.records().front().status == MutationStatus::RolledBack,
            "the previous owned state must be marked rolled back");
    const auto* undo = std::get_if<UndoRemoveSshManagedPolicy>(
        &journal.records().back().undo.payload);
    require(undo != nullptr && undo->appliedValue == "2323" &&
                undo->disabledMutationIds.size() == 1,
            "the new payload must own only the fresh wrapper");
}

// Full external cleanup plus a value change: the previous mutation is
// NothingToDo (already released), the old record is resolved, and the new
// value is applied to the actual current configuration.
void testValueChangeAfterExternalCleanupAppliesFromCurrentState() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPort 2022\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(policy->apply(), "the initial apply must succeed");

    // Externally strip every FIC marker: FIC no longer owns anything.
    tree.writeConfig("Port 22\nPort 2022\n");

    tree.writePolicyValue("ssh_port", "2323");
    auto changedPolicy = tree.makePolicy<NET_ssh_port>();
    require(changedPolicy->apply(),
            "the value change must succeed from the current actual state");

    const std::string content = readFile(tree.configPath());
    require(content.find("Port 2323") != std::string::npos,
            "the managed block must carry the new value");
    require(content.find("#@FIC_DISABLED_LINE@Port 22") != std::string::npos &&
                content.find("#@FIC_DISABLED_LINE@Port 2022") !=
                    std::string::npos,
            "the current conflicting lines must be wrapped again");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 2,
            "the rolled-back and the new record must be kept");
    require(journal.records().front().status == MutationStatus::RolledBack,
            "the externally released mutation must be marked rolled back");
    require(journal.records().back().status == MutationStatus::Applied,
            "the new state must be committed");
}

// Helper-level proof of the subset semantics with no wrappers in the file:
// well-formed payload ids whose wrappers disappeared are already released
// (never an error), a duplicate payload id is corruption (always an error),
// regardless of the presence of FIC-owned artifacts.
void testProvenanceSubsetSemanticsWithoutWrappers() {
    const std::vector<std::string> lines = {"Port 2222"}; // no FIC markers
    SshManagedModel model;
    std::string error;
    require(parseSshManagedModel(lines, model, error) ==
                SshManagedParseStatus::Ok,
            error);

    const SshDisabledProvenanceCheck released =
        checkSshDisabledProvenance(model, "ssh_port", {"FIC-a", "FIC-b"});
    require(released.safeToRelease(),
            "released wrappers must not fail the provenance check");
    require(released.releasedIds.size() == 2,
            "both absent wrapper ids must be reported as released");

    const SshDisabledProvenanceCheck corrupted =
        checkSshDisabledProvenance(model, "ssh_port", {"FIC-a", "FIC-a"});
    require(!corrupted.safeToRelease() && corrupted.payloadMalformed,
            "a duplicate journal payload id must fail the provenance check");
}

// A corrupted active payload (duplicate wrapper ids) must fail the apply
// closed even when every FIC-owned artifact has externally disappeared and
// the effective state is already compliant: the compliance fast-path must
// never silently accept a damaged active record.
void testApplyFailsClosedOnCorruptedActivePayloadWithCompliantState() {
    SshApplyTree tree;
    tree.writeConfig("Port 2222\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    undo.disabledMutationIds = {"FIC-a", "FIC-a"};
    const MutationId id = recordPreparedSsh(
        kSshPortPolicy, "ssh:" + tree.configPath().string() + ":Port", undo);
    std::string commitError;
    require(commitMutation(id, commitError), commitError);

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(!policy->apply(),
            "a corrupted active payload must fail the apply closed even "
            "when the effective state is compliant");
    require(readFile(tree.configPath()) == "Port 2222\n",
            "the file must not be modified");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1,
            "no new mutation record may be created");
    require(tree.runtime()->reloadCalls == 0, "no reload may happen");
}

// The same corrupted active payload with a non-compliant effective state:
// FIC must not plan a new managed mutation on top of a damaged active
// record.
void testApplyFailsClosedOnCorruptedActivePayloadWithNonCompliantState() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\n");
    tree.writePolicyValue("ssh_port", "2222");
    JournalOverride overrideGuard(tree.journalPath());

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    undo.disabledMutationIds = {"FIC-a", "FIC-a"};
    const MutationId id = recordPreparedSsh(
        kSshPortPolicy, "ssh:" + tree.configPath().string() + ":Port", undo);
    std::string commitError;
    require(commitMutation(id, commitError), commitError);

    auto policy = tree.makePolicy<NET_ssh_port>();
    require(!policy->apply(),
            "a corrupted active payload must fail the apply closed even "
            "when the effective state is not compliant");
    require(readFile(tree.configPath()) == "Port 22\n",
            "the file must not be modified");
    require(readFile(tree.configPath()).find("#@FIC_") == std::string::npos,
            "no managed block and no wrappers may be created");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    require(journal.records().size() == 1,
            "no fresh mutation record may be recorded");
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

void testPreparedAfterCrashRequiresResolution() {
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

    const int calls=tree.runtime()->tCalls, reloads=tree.runtime()->reloadCalls;
    const auto journalBefore=readFile(tree.journalPath());
    require(!policy->apply(), "schema 2 Prepared requires explicit resolution, not blind recovery");
    require(tree.runtime()->tCalls==calls && tree.runtime()->reloadCalls==reloads &&
            readFile(tree.journalPath())==journalBefore,"Prepared recovery changed runtime/provenance");
    require(readFile(tree.configPath()) == owned,
            "recovery must not change the already-owned state");

    MutationJournal journal(tree.journalPath());
    std::string error;
    require(journal.load(error), error);
    for (const MutationRecord& record : journal.records()) {
        require(record.status == MutationStatus::Prepared,
                "unresolved crash record must stay Prepared");
    }
}

void testStalePreparedRecordOnForeignConfigRequiresResolution() {
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
    const auto journalBefore=readFile(tree.journalPath());
    require(!policy->apply(), "absent artifacts do not prove runtime/compensation resolution");
    require(readFile(tree.configPath())=="Port 22\n" && tree.runtime()->reloadCalls==0 &&
            tree.runtime()->tCalls==0 && readFile(tree.journalPath())==journalBefore,
            "ambiguous absent-artifact Prepared was discarded or reactivated");
    for (const auto& blockedPolicy : {kSshPortPolicy,kSshRootLoginPolicy,kSshUsePamPolicy}) {
        const auto report=rollbackPolicyBeforeDisable(blockedPolicy,"",tree.rollbackDeps());
        require(report.status==RollbackStatus::Failed && report.message.find("Prepared")!=std::string::npos,
                "disable must gate the shared SSH resource, including other policies");
        require(readFile(tree.configPath())=="Port 22\n" && tree.runtime()->reloadCalls==0 &&
                readFile(tree.journalPath())==journalBefore,"disable changed unresolved resource/provenance");
    }
    MutationJournal journal(tree.journalPath()); std::string error;
    require(journal.load(error),error);
    require(journal.records().size()==1 && journal.records()[0].status==MutationStatus::Prepared,
            "stale Prepared provenance not preserved on disk");
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

// Always reload a separate journal object: provenance must survive on disk.
std::vector<MutationRecord> diskRecords(const SshApplyTree& tree) {
    MutationJournal journal(tree.journalPath()); std::string error;
    require(journal.load(error), error); return journal.records();
}
void requireSameSshRecord(const MutationRecord& a, const MutationRecord& b) {
    const auto* x=std::get_if<UndoRemoveSshManagedPolicy>(&a.undo.payload);
    const auto* y=std::get_if<UndoRemoveSshManagedPolicy>(&b.undo.payload);
    require(a.id==b.id && a.policy==b.policy && a.resource==b.resource && a.status==b.status &&
            a.undo.backend==b.undo.backend && x && y && x->policyName==y->policyName &&
            x->directive==y->directive && x->appliedValue==y->appliedValue &&
            x->disabledMutationIds==y->disabledMutationIds, "SSH record identity/status/full payload changed");
}
// R5: an unchanged owned line is not an effective-compliance proof.
template <typename PolicyT>
void unchangedOwnedComplianceCase(const std::string& policyName,
                                  const std::string& directive,
                                  const std::string& expected,
                                  const std::string& initial,
                                  const std::string& external,
                                  const std::string& badOutput = {},
                                  bool unknown = false,
                                  bool unavailableProof = false) {
    SshApplyTree tree;
    tree.writeConfig(initial);
    tree.writePolicyValue(policyName, expected);
    JournalOverride guard(tree.journalPath());
    auto policy = tree.makePolicy<PolicyT>();
    const auto delegate = tree.runner();
    // Supply real directive values omitted by the small fixture's default -T.
    const auto goodRunner = [&](const auto& path, const auto& args, const auto& options) {
        auto result = delegate(path, args, options);
        if (result.exitCode == 0 && std::find(args.begin(), args.end(), "-T") != args.end()) {
            if (directive == "PubkeyAuthentication")
                result.standardOutput = "pubkeyauthentication " +
                    std::string(readFile(tree.configPath()).find("PubkeyAuthentication yes") != std::string::npos ? "yes" : "no") + "\n";
            if (directive == "MaxAuthTries")
                result.standardOutput = "maxauthtries " +
                    std::string(readFile(tree.configPath()).find("MaxAuthTries 3") != std::string::npos ? "3" : "6") + "\n";
        }
        return result;
    };
    policy->setRunner(goodRunner);
    require(policy->apply(), "R5 initial owned apply");
    const auto owned = readFile(tree.configPath());
    const auto record = diskRecords(tree).at(0);
    require(record.status == MutationStatus::Applied, "R5 requires Applied ownership");
    const auto journalBytes = readFile(tree.journalPath());
    const auto include = tree.tree.root / "extra.conf";
    writeFile(include, "Port 2200\n");
    tree.writeConfig(owned + external);
    const auto drifted = readFile(tree.configPath());
    const auto includeBytes = readFile(include);
    const auto negativeRunner = [&](const auto& path, const auto& args, const auto& options) {
        if (std::find(args.begin(), args.end(), "-T") != args.end()) {
            if (unknown) return sshFailing("deterministic unavailable sshd -T");
            if (!badOutput.empty()) return sshSuccess(badOutput);
        }
        return goodRunner(path, args, options);
    };
    SshRuntimeOptions options;
    options.configPath = tree.configPath();
    options.includeBasePath = tree.tree.root;
    SshRuntime runtime(options, tree.executables(), negativeRunner);
    const auto negative = runtime.policyValueCompliance(directive, expected);
    require(!negative.error.empty(), "negative compliance must retain diagnostic reason");
    require(negative.compliance ==
                ((unknown || unavailableProof) ? SshCompliance::Unknown : SshCompliance::NonCompliant),
            "R5 negative runtime premise must be independently established");
    int writes = 0;
    int saves = 0;
    policy->setBeforeWriteHook([&] { ++writes; });
    setSshSaveOutcomeHookForTests([&](auto&) { ++saves; });
    struct ResetHook { ~ResetHook() { setSshSaveOutcomeHookForTests({}); } } reset;
    policy->setRunner(negativeRunner);
    const int reloads = tree.runtime()->reloadCalls;
    for (int attempt = 0; attempt < 2; ++attempt) {
        require(!policy->apply(), "R5 unchanged noncompliant/unknown ownership must fail");
        require(readFile(tree.configPath()) == drifted, "R5 changed configuration");
        require(readFile(include) == includeBytes, "R5 changed Include");
        require(readFile(tree.journalPath()) == journalBytes, "R5 changed journal bytes");
        const auto records = diskRecords(tree);
        require(records.size() == 1, "R5 created Prepared ownership");
        requireSameSshRecord(record, records.at(0));
        require(writes == 0 && saves == 0 && tree.runtime()->reloadCalls == reloads,
                "R5 performed write/compensation/reload");
    }
    tree.writeConfig(owned);
    policy->setRunner(goodRunner);
    SshRuntime restored(options, tree.executables(), goodRunner);
    require(restored.policyValueCompliance(directive, expected).compliance == SshCompliance::Compliant,
            "external repair must establish compliance");
    require(policy->apply(), "repaired owned state must allow compliant no-op");
    require(policy->apply(), "compliant idempotent no-op");
    require(readFile(tree.configPath()) == owned && readFile(tree.journalPath()) == journalBytes,
            "compliant no-op changed persistent state");
    requireSameSshRecord(record, diskRecords(tree).at(0));
    require(writes == 0 && saves == 0 && tree.runtime()->reloadCalls == reloads,
            "compliant no-op performed effects");
}
void testR5RootMatch() {
    unchangedOwnedComplianceCase<NET_ssh_root_login>("ssh_root_login", "PermitRootLogin", "no",
        "PermitRootLogin yes\n", "Match all\n PermitRootLogin yes\n");
}
void testR5PubkeyMatch() {
    unchangedOwnedComplianceCase<NET_ssh_pubkey_auth>("ssh_pubkey_auth", "PubkeyAuthentication", "yes",
        "PubkeyAuthentication no\n", "Match all\n PubkeyAuthentication no\n");
}
void testR5MaxTriesMatch() {
    unchangedOwnedComplianceCase<NET_ssh_max_auth_tries>("ssh_max_auth_tries", "MaxAuthTries", "3",
        "MaxAuthTries 6\n", "Match all\n MaxAuthTries 6\n");
}
void testR5PamEffectiveMismatch() {
    // UsePAM is global-only in OpenSSH: use incompatible effective output,
    // not an invalid Match/UsePAM construction.
    unchangedOwnedComplianceCase<NET_ssh_use_pam>("ssh_use_pam", "UsePAM", "yes",
        "UsePAM no\n", "# effective oracle reports incompatible UsePAM\n", "usepam no\n");
}
void testR5IncludedPort() {
    unchangedOwnedComplianceCase<NET_ssh_port>("ssh_port", "Port", "2222",
        "Port 22\n", "Include extra.conf\n", "port 2222\nport 2200\n");
}
void testR5Unknown() {
    unchangedOwnedComplianceCase<NET_ssh_root_login>("ssh_root_login", "PermitRootLogin", "no",
        "PermitRootLogin yes\n", "", "", true);
}

void testR5MissingEffectiveParameter() {
    unchangedOwnedComplianceCase<NET_ssh_root_login>("ssh_root_login", "PermitRootLogin", "no",
        "PermitRootLogin yes\n", "", "usepam yes\n", false, true);
}
void testR5InvalidEffectivePort() {
    unchangedOwnedComplianceCase<NET_ssh_port>("ssh_port", "Port", "2222",
        "Port 22\n", "", "port invalid\n", false, true);
}
void testR5UnavailableAudit() {
    unchangedOwnedComplianceCase<NET_ssh_root_login>("ssh_root_login", "PermitRootLogin", "no",
        "PermitRootLogin yes\n", "Include sshd_config\n", "", false, true);
}

void testFailedCompensationRetainsFreshPrepared() {
    SshApplyTree tree; tree.writeConfig("Port 22\n"); tree.writePolicyValue("ssh_port","2222");
    JournalOverride guard(tree.journalPath()); auto policy=tree.makePolicy<NET_ssh_port>();
    tree.runtime()->failTAfterCall=2;
    const auto delegate=tree.runner();
    policy->setRunner([&](const auto& path,const auto& args,const auto& options) {
        auto r=delegate(path,args,options);
        if (tree.runtime()->tCalls==2 && std::find(args.begin(),args.end(),"-T")!=args.end())
            writeFile(tree.configPath(),readFile(tree.configPath())+"# external edit preserved\n");
        return r;
    });
    require(!policy->apply(),"failed compensation must fail apply");
    require(fileContains(tree.configPath(),kSshBlockBeginPrefix) &&
            fileContains(tree.configPath(),"external edit preserved"),"owned markers/external edit lost");
    const auto records=diskRecords(tree);
    require(records.size()==1 && records[0].status==MutationStatus::Prepared,"R1: unresolved durable Prepared was discarded");
    const auto& undo=std::get<UndoRemoveSshManagedPolicy>(records[0].undo.payload);
    require(undo.policyName=="ssh_port" && undo.directive=="Port" && undo.appliedValue=="2222" &&
            undo.disabledMutationIds.size()==1,"full fresh ownership payload missing");
    const auto content=readFile(tree.configPath()); const auto journal=readFile(tree.journalPath());
    tree.runtime()->failTAfterCall=0; tree.runtime()->serviceActive=true;
    const int calls=tree.runtime()->tCalls, reloads=tree.runtime()->reloadCalls;
    require(!policy->apply(),"unresolved Prepared must not auto-commit");
    tree.writePolicyValue("ssh_port","2223");
    require(!tree.makePolicy<NET_ssh_port>()->apply(),"changed desired value bypassed Prepared recovery gate");
    tree.writePolicyValue("ssh_root_login","no");
    require(!tree.makePolicy<NET_ssh_root_login>()->apply(),"another SSH policy bypassed unresolved file gate");
    require(readFile(tree.configPath())==content && readFile(tree.journalPath())==journal &&
            tree.runtime()->tCalls==calls && tree.runtime()->reloadCalls==reloads,"recovery performed blind runtime/file mutation");
    requireSameSshRecord(records[0],diskRecords(tree).at(0));
}
void testAppliedRefreshRefusesBeforeMutation(bool postInstallFault) {
    SshApplyTree tree; tree.writeConfig("Port 22\n"); tree.writePolicyValue("ssh_port","2222");
    JournalOverride guard(tree.journalPath()); auto policy=tree.makePolicy<NET_ssh_port>();
    require(policy->apply(),"initial apply"); const auto original=diskRecords(tree).at(0);
    require(original.status==MutationStatus::Applied,"initial ownership not Applied");
    writeFile(tree.configPath(),readFile(tree.configPath())+"Port 3333\n# foreign refresh input\n");
    const auto content=readFile(tree.configPath()), journal=readFile(tree.journalPath());
    bool faultReached=false;
    if (postInstallFault) {
        const int failingCall=tree.runtime()->tCalls+2;
        const auto delegate=tree.runner();
        policy->setRunner([&,failingCall,delegate](const auto& path,const auto& args,const auto& options) {
            auto r=delegate(path,args,options);
            if (tree.runtime()->tCalls==failingCall && std::find(args.begin(),args.end(),"-T")!=args.end()) {
                faultReached=true;
                writeFile(tree.configPath(),readFile(tree.configPath())+"# external post-install edit\n");
                return sshFailing("deterministic post-install failure");
            }
            return r;
        });
    } else policy->setBeforeWriteHook([&]{faultReached=true; writeFile(tree.configPath(),content+"# CAS conflict\n");});
    const int reloads=tree.runtime()->reloadCalls;
    require(!policy->apply(),"unproven REFRESH must fail closed");
    const auto records=diskRecords(tree);
    require(records.size()==1,"R1b: failed REFRESH discarded original record");
    requireSameSshRecord(original,records[0]);
    require(!faultReached && readFile(tree.configPath())==content && readFile(tree.journalPath())==journal &&
            tree.runtime()->reloadCalls==reloads,"REFRESH must refuse before re-prepare/write/activation");
}
void testAppliedRefreshPreinstallFailure() {testAppliedRefreshRefusesBeforeMutation(false);}
void testAppliedRefreshPostinstallFailure() {testAppliedRefreshRefusesBeforeMutation(true);}

struct Stage1FaultReset {
    ~Stage1FaultReset() {
        setSshSaveOutcomeHookForTests({});
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
    }
};
void testVerifiedTransactionRetainsFacts() {
    for(const bool offline:{false,true}) for(const std::string fault:{"success","admission","activation","postcondition","durability","drift"}) {
        Stage1FaultReset reset;SshApplyTree tree;tree.writeConfig("Port 22\n");
        JournalOverride guard(tree.journalPath());
        UndoRemoveSshManagedPolicy undo;undo.policyName="ssh_port";undo.directive="Port";undo.appliedValue="2222";
        recordPreparedSsh(kSshPortPolicy,"ssh:"+tree.configPath().string()+":Port",undo);
        const auto before=diskRecords(tree).at(0);
        SshConfigFileHandler handler(tree.configPath().string());require(handler.loadConfig(),"verified snapshot");
        SshRuntimeOptions opts;opts.configPath=tree.configPath();opts.includeBasePath=tree.tree.root;opts.serviceUnits={"ssh.service"};
        SshRuntime runtime(opts,tree.executables(),tree.runner());SshConfigTransactionHooks hooks;
        hooks.offlineOwnershipRelease=offline;
        int activations=0,restores=0;
        hooks.verifiedAdmission=[&](std::string&){return fault!="admission";};
        hooks.verifiedActivation=[&](const AtomicTargetState& installed,std::string&){
            ++activations;require(AtomicFileWriter::targetStateMatches(tree.configPath(),installed),"wrong verified receipt");
            if(fault=="drift")writeFile(tree.configPath(),"# foreign after verified runtime\nPort 2233\n");
            return fault!="activation";
        };
        hooks.beforeRestore=[&]{++restores;};
        if(fault=="durability")AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& p){return p!=tree.configPath().string();});
        const auto result=runSshConfigTransaction(handler,runtime,hooks,[&](std::string& error){
            bool changed=false;return upsertSshManagedPolicyBlock(handler.lines(),"ssh_port","Port 2222",changed,error);
        },[&](std::string&){return fault!="postcondition";},"verified test");
        require(result.ok==(fault=="success"),fault+": wrong verified result");
        if(offline) {
            require(result.activation==SshRuntimeReconciliation::NotAttempted,"offline release claimed runtime activation");
            require(result.message.find("verified SSH runtime observed")==std::string::npos && result.message.find("verified activation unproven")==std::string::npos,"offline failure claimed attempted runtime proof");
            if(result.ok)require(result.message.find("runtime NOT activated")!=std::string::npos,"offline success omitted runtime boundary");
        }
        require(restores==0&&tree.runtime()->reloadCalls==0,fault+": legacy compensation/reload invoked");
        requireSameSshRecord(before,diskRecords(tree).at(0));
        if(fault=="admission") {
            require(readFile(tree.configPath())=="Port 22\n"&&activations==0&&result.mayDiscardPrepared(true),"admission changed persistent state");
        } else {
            require(!result.mayDiscardPrepared(true)&&result.installedTargetState.has_value(),"post-save failure lost provenance");
            require(result.compensation==SshCompensationEffect::NotAttempted,"post-save compensation occurred");
            if(fault=="drift")require(readFile(tree.configPath()).find("foreign after verified")!=std::string::npos,"foreign drift overwritten");
            else require(readFile(tree.configPath()).find("Port 2222")!=std::string::npos,"saved bytes restored unexpectedly");
        }
    }
}

void testTypedTransactionFaultMatrix() {
    using P=SshPersistentEffect; using C=SshCompensationEffect; using R=SshRuntimeReconciliation;
    for (const std::string fault : {"success","CAS","restore-CAS","rename-fsync","restore-fsync",
             "fsync-once","missing-receipt","unknown-write","writer-exception","runtime-invalid",
             "reload-unknown","reload-fails-once","before-restore-exception","legacy-restore"}) {
        Stage1FaultReset reset;
        SshApplyTree tree; tree.writeConfig("Port 22\n");
        JournalOverride guard(tree.journalPath());
        UndoRemoveSshManagedPolicy undo;undo.policyName="ssh_port";undo.directive="Port";undo.appliedValue="2222";
        const auto id=recordPreparedSsh(kSshPortPolicy,"ssh:"+tree.configPath().string()+":Port",undo);
        const auto originalRecord=diskRecords(tree).at(0);
        SshConfigFileHandler handler(tree.configPath().string());require(handler.loadConfig(),"transaction snapshot");
        SshRuntimeOptions opts;opts.configPath=tree.configPath();opts.includeBasePath=tree.tree.root;opts.serviceUnits={"ssh.service"};
        auto runner=tree.runner(); SshConfigTransactionHooks hooks;
        int barriers=0;
        if (fault=="CAS") hooks.beforeWrite=[&]{writeFile(tree.configPath(),"Port 22\n# external CAS\n");};
        if (fault=="restore-CAS") hooks.beforeRestore=[&]{writeFile(tree.configPath(),readFile(tree.configPath())+"# external restore\n");};
        if (fault=="before-restore-exception") hooks.beforeRestore=[] {throw std::runtime_error("restore outcome unknown");};
        if (fault=="rename-fsync" || fault=="restore-fsync" || fault=="fsync-once")
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){
                if (path!=tree.configPath().string()) return true;
                ++barriers;
                return fault=="restore-fsync" ? barriers==1 : fault=="fsync-once" ? barriers!=1 : false;
            });
        if (fault=="missing-receipt") setSshSaveOutcomeHookForTests([](auto& saved){saved.installedTargetState.reset();});
        if (fault=="unknown-write") setSshSaveOutcomeHookForTests([](auto& saved){
            saved.installed=false;saved.durabilityConfirmed=false;saved.installedTargetState.reset();
        });
        if (fault=="writer-exception") AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){
            if (path==tree.configPath().string()) throw std::runtime_error("writer result lost after rename");return true;
        });
        if (fault=="runtime-invalid") tree.runtime()->failTAfterCall=2;
        if (fault=="reload-unknown" || fault=="reload-fails-once") {
            tree.runtime()->serviceActive=true;
            const auto delegate=runner;
            runner=[&,delegate](const auto& path,const auto& args,const auto& options){
                auto r=delegate(path,args,options);
                if (std::find(args.begin(),args.end(),"reload")!=args.end() && tree.runtime()->reloadCalls==1) {
                    if (fault=="reload-unknown") throw std::runtime_error("reload reply lost");
                    return sshFailing("first reload failed");
                }
                return r;
            };
        }
        SshRuntime runtime(opts,tree.executables(),runner);
        const auto result=runSshConfigTransaction(handler,runtime,hooks,[&](std::string& error){
            bool changed=false;return upsertSshManagedPolicyBlock(handler.lines(),"ssh_port","Port 2222",changed,error);
        },[&](std::string&){return fault=="success" || fault=="reload-unknown" || fault=="reload-fails-once";},"test write");
        require(result.ok==(fault=="success"),fault+": wrong legacy bool projection");
        require(result.mayDiscardPrepared(true)==(fault=="CAS") && !result.mayDiscardPrepared(false),fault+": unsafe abort predicate");
        requireSameSshRecord(originalRecord,diskRecords(tree).at(0));
        require(diskRecords(tree).size()==1 && diskRecords(tree)[0].id==id,"transaction erased journal ownership");
        if (fault=="CAS") {
            require(result.persistentEffect==P::NotInstalled && result.conflict && !result.installedTargetState &&
                    result.compensation==C::NotAttempted && tree.runtime()->tCalls==0 && tree.runtime()->reloadCalls==0 &&
                    readFile(tree.configPath())=="Port 22\n# external CAS\n","CAS no-effect facts wrong");
        } else if (fault=="missing-receipt" || fault=="unknown-write" || fault=="writer-exception") {
            require(!result.installedTargetState && result.compensation==C::NotAttempted &&
                    result.persistentEffect==(fault=="missing-receipt" ? P::DurableInstalled : P::Unknown) &&
                    fileContains(tree.configPath(),kSshBlockBeginPrefix) && tree.runtime()->reloadCalls==0,
                    fault+": missing/unknown installed evidence accepted");
        } else {
            require(result.installedTargetState && result.installedTargetState->content.find("Port 2222")!=std::string::npos,
                    fault+": writer-issued target state missing");
            require(result.persistentEffect==((fault=="rename-fsync" || fault=="fsync-once") ? P::Installed : P::DurableInstalled),
                    fault+": rename/durability conflated");
            if (fault=="restore-CAS") require(result.compensation==C::RefusedByCAS &&
                fileContains(tree.configPath(),"external restore") && fileContains(tree.configPath(),kSshBlockBeginPrefix) &&
                result.installedTargetState->content.find("external restore")==std::string::npos,"CAS restore adopted external state");
            else if (fault=="before-restore-exception") require(result.compensation==C::FailedOrUnknown &&
                fileContains(tree.configPath(),kSshBlockBeginPrefix),"unknown compensation effect lost");
            else if (fault=="rename-fsync" || fault=="restore-fsync") require(result.compensation==C::FailedOrUnknown &&
                result.restoredTargetState && readFile(tree.configPath())=="Port 22\n" &&
                result.restoredRuntime==R::NotAttempted,"restore rename was treated as durable");
            else if (fault=="reload-unknown") require(result.activation==R::FailedOrUnknown && result.compensation==C::NotAttempted &&
                fileContains(tree.configPath(),kSshBlockBeginPrefix),"lost reload reply treated as no effect");
            else if (fault!="success") {
                require(result.compensation==C::RestoredDurably && result.restoredTargetState &&
                        readFile(tree.configPath())=="Port 22\n" &&
                        result.restoredTargetState->identity.inode!=result.installedTargetState->identity.inode,
                        fault+": original/restore receipts conflated");
                require(result.restoredRuntime==(fault=="runtime-invalid" ? R::FailedOrUnknown : R::LegacyAccepted),
                        fault+": runtime outcome lost");
                if (fault=="reload-fails-once") require(result.activation==R::FailedOrUnknown && tree.runtime()->reloadCalls==2,
                        "legacy accepted reconciliation erased first reload uncertainty");
            }
        }
        std::cout<<"FAULT "<<fault<<" PASS\n";
    }
}
void testPolicyInstalledReceiptUnknownRetainsPrepared() {
    for (bool receiptMissing : {true,false}) {
        Stage1FaultReset reset; SshApplyTree tree;
        tree.writeConfig("Port 22\n");tree.writePolicyValue("ssh_port","2222");JournalOverride guard(tree.journalPath());
        setSshSaveOutcomeHookForTests([&](auto& saved){saved.installedTargetState.reset();
            if (!receiptMissing) {saved.installed=false;saved.durabilityConfirmed=false;}
        });
        require(!tree.makePolicy<NET_ssh_port>()->apply(),"unknown writer result succeeded");
        const auto records=diskRecords(tree);
        require(records.size()==1 && records[0].status==MutationStatus::Prepared &&
                std::get<UndoRemoveSshManagedPolicy>(records[0].undo.payload).disabledMutationIds.size()==1 &&
                fileContains(tree.configPath(),kSshBlockBeginPrefix),"unknown installed state discarded provenance");
    }
}
void testJournalPersistFaultsPreserveEffects() {
    for (const std::string phase : {"prepare","discard","commit"}) {
        Stage1FaultReset reset; SshApplyTree tree;
        tree.writeConfig("Port 22\n");tree.writePolicyValue("ssh_port","2222");JournalOverride guard(tree.journalPath());
        std::string error;require(DaemonMutationJournal::instance().tryGet(error)!=nullptr,error);
        auto failJournal=[&] {AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){return path!=tree.journalPath().string();});};
        auto policy=tree.makePolicy<NET_ssh_port>();
        if (phase=="prepare") failJournal();
        if (phase=="discard") policy->setBeforeWriteHook([&]{
            writeFile(tree.configPath(),"Port 22\n# external journal abort\n");failJournal();
        });
        if (phase=="commit") {
            const auto delegate=tree.runner();policy->setRunner([&,delegate](const auto& path,const auto& args,const auto& options){
                auto r=delegate(path,args,options);
                if (tree.runtime()->tCalls==3 && std::find(args.begin(),args.end(),"-T")!=args.end()) failJournal();
                return r;
            });
        }
        require(!policy->apply(),phase+": indeterminate journal returned success");
        require(DaemonMutationJournal::instance().tryGet(error)==nullptr && !error.empty(),"indeterminate journal became usable");
        const auto bytes=readFile(tree.configPath()), journal=readFile(tree.journalPath());
        const int reloads=tree.runtime()->reloadCalls;
        require(!policy->apply() && readFile(tree.configPath())==bytes && readFile(tree.journalPath())==journal &&
                tree.runtime()->reloadCalls==reloads,"unusable journal allowed mutation/discard");
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        const auto records=diskRecords(tree);
        if (phase=="discard") require(records.empty() && bytes=="Port 22\n# external journal abort\n",
            "no-effect discard persist did not retain external bytes");
        else {
            require(records.size()==1 && records[0].status==(phase=="prepare" ? MutationStatus::Prepared : MutationStatus::Applied),
                    "post-rename journal document lost actual provenance/status");
            const auto& payload=std::get<UndoRemoveSshManagedPolicy>(records[0].undo.payload);
            require(payload.policyName=="ssh_port" && payload.directive=="Port" && payload.appliedValue=="2222" &&
                    payload.disabledMutationIds.size()==1,"journal persist lost complete undo payload");
            require((bytes.find(kSshBlockBeginPrefix)!=std::string::npos)==(phase=="commit"),"prepare failure wrote config / commit lost config");
        }
        std::cout<<"FAULT journal-"<<phase<<" PASS\n";
    }
}
void testPolicyDurabilityFailureRetainsPrepared() {
    for (bool initialBarrierFails : {true,false}) {
        Stage1FaultReset reset; SshApplyTree tree;
        tree.writeConfig("Port 22\n");tree.writePolicyValue("ssh_port","2222");JournalOverride guard(tree.journalPath());
        auto policy=tree.makePolicy<NET_ssh_port>(); std::optional<MutationRecord> prepared;
        policy->setBeforeWriteHook([&]{prepared=diskRecords(tree).at(0);});
        if (!initialBarrierFails) tree.runtime()->failTAfterCall=2;
        int calls=0;
        AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){
            if (path!=tree.configPath().string()) return true;
            ++calls; return !initialBarrierFails && calls==1;
        });
        require(!policy->apply() && prepared.has_value(),"durability fault did not fail installed attempt");
        require(readFile(tree.configPath())=="Port 22\n" && tree.runtime()->reloadCalls==0 && calls>=3,
                "restore fsync was not attempted/refused, or unsafe reload happened");
        const auto records=diskRecords(tree);
        require(records.size()==1 && records[0].status==MutationStatus::Prepared,"undurable compensation discarded ownership");
        requireSameSshRecord(*prepared,records[0]);
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        const auto journal=readFile(tree.journalPath());const int runtimeCalls=tree.runtime()->tCalls;
        require(!policy->apply() && readFile(tree.journalPath())==journal && tree.runtime()->tCalls==runtimeCalls &&
                tree.runtime()->reloadCalls==0,"undurable restore auto-resolved on retry");
    }
}

void testMalformedJournalRefusesBeforeWrite() {
    SshApplyTree tree;tree.writeConfig("Port 22\n");tree.writePolicyValue("ssh_port","2222");
    writeFile(tree.journalPath(),"not a journal\n");JournalOverride guard(tree.journalPath());
    require(!tree.makePolicy<NET_ssh_port>()->apply() && readFile(tree.configPath())=="Port 22\n" &&
            readFile(tree.journalPath())=="not a journal\n" && tree.runtime()->tCalls==0 && tree.runtime()->reloadCalls==0,
            "damaged journal permitted system mutation");
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
    require(journal.records().size()==1 && journal.records()[0].status==MutationStatus::Prepared,
            "file restore alone cannot resolve legacy runtime effects; retain provenance");
    const auto& payload=std::get<UndoRemoveSshManagedPolicy>(journal.records()[0].undo.payload);
    require(payload.policyName=="ssh_port" && payload.directive=="Port" && payload.appliedValue=="2222" &&
            payload.disabledMutationIds.size()==1,"compensated attempt lost ownership permissions");
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
    require(journal.records().size()==1 && journal.records()[0].status==MutationStatus::Prepared,
            "file restore alone cannot resolve legacy runtime effects; retain provenance");
    const auto& payload=std::get<UndoRemoveSshManagedPolicy>(journal.records()[0].undo.payload);
    require(payload.policyName=="ssh_port" && payload.directive=="Port" && payload.appliedValue=="2222" &&
            payload.disabledMutationIds.size()==1,"compensated attempt lost ownership permissions");
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

// Ownership-release semantics: the journal payload expects wrappers A and B,
// but wrapper B has already disappeared externally. Only A must be restored;
// B is treated as already released and is never reconstructed.
void testRollbackReleasesPartiallyDisappearedWrappers() {
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

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    undo.disabledMutationIds = {"FIC-a", "FIC-b"};

    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(rollback.ok && !rollback.conflict, rollback.message);
    require(readFile(tree.configPath()) == "Port 22\nPort 2022\n",
            "wrapper A must be restored, the managed block removed, and "
            "wrapper B must not be reconstructed");
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

// Ownership-release semantics: every FIC-owned artifact of the mutation has
// disappeared externally. Nothing is left to release; the journal payload is
// not a backup manifest, so nothing is reconstructed and the rollback is
// NothingToDo with runtime reconciliation.
void testRollbackNothingToDoWhenAllOwnedArtifactsGone() {
    SshApplyTree tree;
    tree.writeConfig("Port 22\nPort 2022\n");

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    undo.disabledMutationIds = {"FIC-a", "FIC-b"};

    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(rollback.nothingToDo && !rollback.conflict && !rollback.ok,
            rollback.message);
    require(readFile(tree.configPath()) == "Port 22\nPort 2022\n",
            "the file must not be modified by a NothingToDo rollback");
}

// A payload-proven wrapper and an unproven wrapper coexist: even the proven
// wrapper must not be restored — no transaction may start on an unproven
// owned artifact.
void testRollbackConflictsOnKnownAndUnknownWrapper() {
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
        "#@FIC_DISABLED_BEGIN policy=ssh_port mutation=FIC-x@\n"
        "#@FIC_DISABLED_LINE@Port 2022\n"
        "#@FIC_DISABLED_END policy=ssh_port mutation=FIC-x@\n";
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
            "neither the proven nor the unknown wrapper may be touched");
}

// The managed sub-block exists but its directive line differs from the
// recorded applied value: the block was manually edited and FIC refuses to
// remove or rewrite it by guesswork.
void testRollbackConflictsOnManuallyModifiedBlock() {
    SshApplyTree tree;
    const std::string content =
        "#@FIC_SSH_BLOCK_BEGIN version=1@\n"
        "#@FIC_POLICY_BEGIN name=ssh_port@\n"
        "Port 3333\n"
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
    undo.disabledMutationIds = {"FIC-a"};

    const SshRollbackResult rollback =
        undoSshManagedPolicyMutation(tree.rollbackOptions(), undo);
    require(!rollback.ok && rollback.conflict, rollback.message);
    require(readFile(tree.configPath()) == content,
            "the manually modified block must be left untouched");
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
        {"ssh_max_auth_tries", "MaxAuthTries"},
        {"ssh_root_login", "PermitRootLogin"},
        {"ssh_pubkey_auth", "PubkeyAuthentication"},
        {"ssh_use_pam", "UsePAM"}};

    std::vector<std::unique_ptr<Ssh>> policies;
    policies.push_back(std::make_unique<NET_ssh_port>(
        tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_max_auth_tries>(
        tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_root_login>(
        tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_pubkey_auth>(
        tree.platformConfig(), tree.executables()));
    policies.push_back(std::make_unique<NET_ssh_use_pam>(
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

void testPlatformApplyBoundary() {
    const auto profile=fic::platform::makeBuildPlatformProfile();
    using Contract=fic::platform::SshApplyContract;
    if(profile.id=="debian-12"||profile.id=="debian-13")
        require(profile.ssh.applyContract==Contract::DebianVerified,"Debian must use verified apply");
    else if(profile.id=="ubuntu-24.04"||profile.id=="ubuntu-26.04")
        require(profile.ssh.applyContract==Contract::UbuntuSocketVerified,"Ubuntu must not fall back to legacy");
    else if(profile.id=="alt-p11") require(profile.ssh.applyContract==Contract::Legacy,"ALT legacy contract changed");
    SshApplyTree tree; tree.writeConfig("Port 22\n");tree.writePolicyValue("ssh_port","2222");
    JournalOverride guard(tree.journalPath());std::string error;
    require(DaemonMutationJournal::instance().tryGet(error)!=nullptr,error);
    const auto journal=readFile(tree.journalPath());
    auto config=tree.platformConfig();config.applyContract=Contract::UbuntuSocketVerified;
    PolicyUnderTest<NET_ssh_port> policy(config,tree.executables());policy.setRunner(tree.runner());
    require(!policy.apply(),"socket profile on unsupported test environment returned success");
    require(readFile(tree.configPath())=="Port 22\n"&&readFile(tree.journalPath())==journal&&
            tree.runtime()->tCalls==0&&tree.runtime()->reloadCalls==0,"unsupported platform mutated configuration/journal/runtime");
}

void testSharedApplyDisableResourceLock() {
    SshApplyTree tree;
    tree.writeConfig("UsePAM no\n"); tree.writePolicyValue("ssh_use_pam","yes");
    JournalOverride overrideGuard(tree.journalPath());
    const auto probe=[] {
        const bool acquired=std::async(std::launch::async,[] {
            if(!sshResourceMutex().try_lock()) return false;
            sshResourceMutex().unlock(); return true;
        }).get();
        require(!acquired,"shared SSH resource lock not held across mutation");
    };
    auto policy=tree.makePolicy<NET_ssh_use_pam>();
    policy->setBeforeWriteHook(probe);
    require(policy->apply(),"lock fixture apply");
    auto deps=tree.rollbackDeps(); auto options=tree.rollbackOptions();
    options.beforeWrite=probe; deps.sshOptions=[options] { return options; };
    const auto result=rollbackPolicyBeforeDisable(kSshUsePamPolicy,"UsePAM",deps);
    require(result.status==RollbackStatus::Success,result.message);
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
        {"platform apply boundary",testPlatformApplyBoundary},
        {"shared apply/disable lock",testSharedApplyDisableResourceLock},
        {"R5 root Match", testR5RootMatch},
        {"R5 pubkey Match", testR5PubkeyMatch},
        {"R5 max tries Match", testR5MaxTriesMatch},
        {"R5 PAM effective mismatch", testR5PamEffectiveMismatch},
        {"R5 included port", testR5IncludedPort},
        {"R5 unknown", testR5Unknown},
        {"R5 missing effective parameter", testR5MissingEffectiveParameter},
        {"R5 invalid effective port", testR5InvalidEffectivePort},
        {"R5 unavailable audit", testR5UnavailableAudit},
        {"compliant effective state causes no mutation",
         testCompliantEffectiveStateCausesNoMutation},
        {"UsePAM apply and rollback", testUsePamApplyAndRollback},
        {"UsePAM compliant no-op", testUsePamAlreadyCompliantIsUnowned},
        {"UsePAM shadows earlier Include", testUsePamShadowsEarlierIncludeWithoutEditingIt},
        {"apply fails when effective state is unknown",
         testApplyFailsWhenEffectiveStateUnknown},
        {"unsupported policy semantics is refused",
         testUnsupportedPolicySemanticsIsRefused},
        {"apply wraps port occurrences and records payload",
         testApplyWrapsPortOccurrencesAndRecordsPayload},
        {"repeated apply is idempotent", testRepeatedApplyIsIdempotent},
        {"value change rolls back previous state and reapplies",
         testValueChangeRollsBackPreviousStateAndReapplies},
        {"value change releases only remaining owned wrappers",
         testValueChangeReleasesOnlyRemainingOwnedWrappers},
        {"value change after external cleanup applies from current state",
         testValueChangeAfterExternalCleanupAppliesFromCurrentState},
        {"provenance subset semantics without wrappers",
         testProvenanceSubsetSemanticsWithoutWrappers},
        {"apply fails closed on corrupted active payload with compliant state",
         testApplyFailsClosedOnCorruptedActivePayloadWithCompliantState},
        {"apply fails closed on corrupted active payload with non-compliant state",
         testApplyFailsClosedOnCorruptedActivePayloadWithNonCompliantState},
        {"match sections are preserved", testMatchSectionsArePreserved},
        {"foreign directive inside disabled block is refused",
         testForeignDirectiveInsideDisabledBlockIsRefused},
        {"foreign line inside managed block is refused",
         testForeignLineInsideManagedBlockIsRefused},
        {"orphan managed block with compliant value fails closed",
         testOrphanManagedBlockWithCompliantValueFailsClosed},
        {"rollback releases partially disappeared wrappers",
         testRollbackReleasesPartiallyDisappearedWrappers},
        {"rollback nothing to do when all owned artifacts are gone",
         testRollbackNothingToDoWhenAllOwnedArtifactsGone},
        {"rollback conflicts on known and unknown wrapper",
         testRollbackConflictsOnKnownAndUnknownWrapper},
        {"rollback conflicts on manually modified block",
         testRollbackConflictsOnManuallyModifiedBlock},
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
        {"prepared after crash requires explicit resolution",
         testPreparedAfterCrashRequiresResolution},
        {"stale prepared on foreign config requires resolution",
         testStalePreparedRecordOnForeignConfigRequiresResolution},
        {"prepared with drifted block fails closed",
         testPreparedWithDriftedBlockFailsClosed},
        {"apply concurrent modification is refused",
         testApplyConcurrentModificationIsRefused},
        {"R1 fresh failed compensation retains provenance", testFailedCompensationRetainsFreshPrepared},
        {"R1b refresh preinstall failure retains Applied", testAppliedRefreshPreinstallFailure},
        {"R1b refresh postinstall failure retains Applied", testAppliedRefreshPostinstallFailure},
        {"typed SSH transaction fault matrix", testTypedTransactionFaultMatrix},
        {"verified SSH transaction preserves facts without compensation",testVerifiedTransactionRetainsFacts},
        {"unknown installed receipt keeps Prepared", testPolicyInstalledReceiptUnknownRetainsPrepared},
        {"journal prepare/discard/commit faults preserve effects", testJournalPersistFaultsPreserveEffects},
        {"install/restore durability fault retains Prepared", testPolicyDurabilityFailureRetainsPrepared},
        {"malformed journal refuses before SSH write", testMalformedJournalRefusesBeforeWrite},
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
