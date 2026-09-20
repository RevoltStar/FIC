#include "rollback/DaemonMutationJournal.h"
#include "rollback/RollbackExecutor.h"
#include "rollback/PamRollback.h"

#include "modules/dac/mode_and_owner/policies/DAC_systemcommandlock.h"
#include "modules/dac/sudo/SudoersConfiguration.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlRuntime.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>

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

// RAII guard for the daemon journal override.
class JournalOverride {
public:
    explicit JournalOverride(std::filesystem::path path) {
        DaemonMutationJournal::instance().setOverridePath(std::move(path));
    }
    ~JournalOverride() { DaemonMutationJournal::instance().resetOverride(); }
};

class TempJournal {
public:
    TempJournal()
        : tree("/tmp/fic-rollback-journal-XXXXXX") {
        std::filesystem::create_directories(tree.root);
    }
    TempTree tree;
};

// Records a committed Applied mutation for the given policy.
MutationId recordApplied(const PolicyRef& policy,
                         const std::string& resource,
                         const UndoAction& undo) {
    MutationId id = 0;
    std::string error;
    require(fic::rollback::recordPreparedMutation(policy, resource, undo, id, error),
            error);
    require(fic::rollback::commitMutation(id, error), error);
    return id;
}

// ---------------------------------------------------------------- sysctl ----

class SysctlTree {
public:
    SysctlTree()
        : tree("/tmp/fic-rollback-sysctl-XXXXXX") {
        for (const char* directory : {"etc/sysctl.d", "run/sysctl.d",
                                      "usr/local/lib/sysctl.d",
                                      "usr/lib/sysctl.d", "lib/sysctl.d",
                                      "proc/sys/vm"}) {
            std::filesystem::create_directories(tree.root / directory);
        }
    }

    SysctlConfigurationOptions options() const {
        SysctlConfigurationOptions value;
        value.platform.loader = fic::platform::SysctlLoaderKind::SystemdSysctl;
        value.platform.managedConfigPath = tree.root / "etc/sysctl.d/zzzz-fic.conf";
        value.directories = {
            tree.root / "etc/sysctl.d",
            tree.root / "run/sysctl.d",
            tree.root / "usr/local/lib/sysctl.d",
            tree.root / "usr/lib/sysctl.d",
            tree.root / "lib/sysctl.d"
        };
        value.procpsMainPath = tree.root / "etc/sysctl.conf";
        value.enforceOwnership = false;
        return value;
    }

    void createManagedValue(const std::string& key, const std::string& value) const {
        SysctlConfiguration configuration(options());
        std::string error;
        require(configuration.load(error), error);
        const SysctlOperationResult operation =
            configuration.ensureManagedValue(key, value);
        require(operation.ok && operation.changed, operation.message);
    }

    RollbackExecutorDeps deps() const {
        RollbackExecutorDeps value;
        SysctlConfigurationOptions options = this->options();
        value.sysctlOptions = [options]() { return options; };
        value.sysctlRuntimeRoot = tree.root / "proc/sys";
        return value;
    }

    TempTree tree;
};

const PolicyRef kSysctlPolicy{"SYSCTL", "Global", "swappiness_policy"};

UndoAction sysctlUndo(const std::string& value) {
    return UndoAction{MutationBackend::Sysctl,
                      UndoRemoveManagedSetting{"vm.swappiness", value}};
}

// ----------------------------------------------------------------- sudo -----

class SudoersTree {
public:
    SudoersTree()
        : tree("/tmp/fic-rollback-sudoers-XXXXXX") {
        std::filesystem::create_directories(tree.root / "sudoers.d");
    }

    SudoersConfigurationOptions options(const std::string& mainContent) const {
        SudoersConfigurationOptions value;
        value.mainPath = tree.root / "sudoers";
        value.managedPath = tree.root / "sudoers.d" / "zzzz-fic";
        value.validatorPath.clear();
        value.verifyValidatorHash = false;
        value.enforceOwnership = false;
        writeFile(value.mainPath,
                  mainContent +
                  "\n@includedir " + (tree.root / "sudoers.d").string() + "\n");
        return value;
    }

    RollbackExecutorDeps deps(const std::string& mainContent) const {
        RollbackExecutorDeps value;
        SudoersConfigurationOptions options = this->options(mainContent);
        value.sudoersOptions = [options]() { return options; };
        return value;
    }

    TempTree tree;
};

const PolicyRef kSudoPolicy{"DAC", "SudoEdit", "sudo_passwd_tries"};

// ---------------------------------------------------------------- tests -----

void testEnrollmentMatrix() {
    for (const std::string& name : {"enable_authentication_lockout",
                                    "enable_password_history",
                                    "enable_password_quality"}) {
        require(rollbackEnrollment({"IDENTITY_ACCESS", "PAM", name}) ==
                    RollbackEnrollment::Supported,
                "PAM capability topology policy must be enrolled");
    }
    require(rollbackEnrollment({"IDENTITY_ACCESS", "PAM",
                                "future_pam_policy"}) ==
                RollbackEnrollment::Unsupported,
            "future PAM policy must not be auto-enrolled");
    require(rollbackEnrollment({"SYSCTL", "Global", "anything"}) ==
                RollbackEnrollment::Supported,
            "all SYSCTL policies must be enrolled");
    require(rollbackEnrollment({"DAC", "SudoEdit", "sudo_passwd_tries"}) ==
                RollbackEnrollment::Supported,
            "SudoEdit must be enrolled");
    require(rollbackEnrollment({"DAC", "SudoEdit", "sudo_env_reset"}) ==
                RollbackEnrollment::Supported,
            "known supported sudo policies stay enrolled");
    require(rollbackEnrollment({"DAC", "SudoEdit",
                                "sudo_require_authentication"}) ==
                RollbackEnrollment::Unsupported,
            "sudo_require_authentication must refuse automatic rollback");
    require(rollbackEnrollment({"DAC", "SudoEdit", "sudo_future_policy"}) ==
                RollbackEnrollment::Unsupported,
            "unknown future sudo policy must not be auto-enrolled");
    require(rollbackEnrollment({"FIREWALL", "HostFiltering", "block_rdp"}) ==
                RollbackEnrollment::Supported,
            "HostFiltering policies must be enrolled");
    require(rollbackEnrollment({"FIREWALL", "HostFiltering", "custom_rules"}) ==
                RollbackEnrollment::Supported,
            "known supported firewall policies stay enrolled");
    require(rollbackEnrollment({"FIREWALL", "HostFiltering",
                                "exclusive_firewall_control"}) ==
                RollbackEnrollment::Unsupported,
            "exclusive_firewall_control must refuse automatic rollback");
    require(rollbackEnrollment({"FIREWALL", "HostFiltering", "future_firewall"}) ==
                RollbackEnrollment::Unsupported,
            "unknown future firewall policy must not be auto-enrolled");
    require(rollbackEnrollment({"DC", "DeviceControl", "block_usb_storage"}) ==
                RollbackEnrollment::Supported,
            "DC category features must be enrolled");
    require(rollbackEnrollment({"DC", "DeviceControl", "unknown_feature"}) ==
                RollbackEnrollment::Unsupported,
            "unknown DC features must refuse automatic rollback");
    require(rollbackEnrollment({"NET", "SshEdit", "ssh_port"}) ==
                RollbackEnrollment::Supported,
            "NET/SshEdit ssh_port must be enrolled");
    require(rollbackEnrollment({"NET", "SshEdit", "ssh_max_auth_tries"}) ==
                RollbackEnrollment::Supported,
            "NET/SshEdit ssh_max_auth_tries must be enrolled");
    require(rollbackEnrollment({"NET", "SshEdit", "ssh_root_login"}) ==
                RollbackEnrollment::Supported,
            "NET/SshEdit ssh_root_login must be enrolled");
    require(rollbackEnrollment({"NET", "SshEdit", "ssh_pubkey_auth"}) ==
                RollbackEnrollment::Supported,
            "NET/SshEdit ssh_pubkey_auth must be enrolled");
    require(rollbackEnrollment({"NET", "SshEdit", "ssh_future_policy"}) ==
                RollbackEnrollment::Unsupported,
            "unknown future SSH policy must not be auto-enrolled");
    require(rollbackEnrollment({"OSS", "Grub", "grub_timeout"}) ==
                RollbackEnrollment::Supported,
            "whitelisted GRUB policies are rollback-supported");
    require(rollbackEnrollment({"OSS", "Grub", "grub_cmdline_linux"}) ==
                RollbackEnrollment::Supported,
            "grub_cmdline_linux must be enrolled");
    require(rollbackEnrollment({"OSS", "Grub", "grub_disable_recovery"}) ==
                RollbackEnrollment::Supported,
            "grub_disable_recovery must be enrolled");
    require(rollbackEnrollment({"OSS", "Grub", "grub_future_policy"}) ==
                RollbackEnrollment::Unsupported,
            "unknown future GRUB policies must not be auto-enrolled");
    require(rollbackEnrollment({"IDENTITY_ACCESS", "SSSD",
                                "sssd_offline_credentials_expiration"}) ==
                RollbackEnrollment::Supported,
            "sssd_offline_credentials_expiration must be enrolled");
    require(rollbackEnrollment(
                {"IDENTITY_ACCESS", "SSSD", "sssd_future_policy"}) ==
                RollbackEnrollment::Unsupported,
            "unknown future SSSD policies must not be auto-enrolled");
    require(rollbackEnrollment({"IDENTITY_ACCESS", "KERBEROS",
                                "kerberos_ticket_lifetime"}) ==
                RollbackEnrollment::Supported,
            "kerberos_ticket_lifetime must be enrolled");
    require(rollbackEnrollment(
                {"IDENTITY_ACCESS", "KERBEROS", "kerberos_future_policy"}) ==
                RollbackEnrollment::Unsupported,
            "unknown future Kerberos policies must not be auto-enrolled");
    require(rollbackEnrollment(
                {"IDENTITY_ACCESS", "Pam", "pam_future_policy"}) ==
                RollbackEnrollment::NotEnrolled,
            "other IDENTITY_ACCESS submodules stay outside the rollback "
            "system");
}

struct FakePamState {
    fic::identity::pam::PamTopologyState state =
        fic::identity::pam::PamTopologyState::Enabled;
    bool manageable = true;
    bool disableSucceeds = true;
    int disableCalls = 0;
};

class FakePamManager final : public fic::identity::pam::PamTopologyManager {
public:
    bool confirmDurable(std::string& error) const override {
        error.clear(); return true;
    }
    explicit FakePamManager(std::shared_ptr<FakePamState> state)
        : state_(std::move(state)) {}
    bool inspect(fic::identity::pam::PamTopologyStatus& status,
                 std::string& error) override {
        status = {state_->state, state_->manageable, {}, {}};
        error.clear();
        return true;
    }
    bool canEnable(std::string& error) const override {
        error.clear(); return true;
    }
    bool enable(std::string& error) override {
        error.clear(); return true;
    }
    bool disable(std::string& error) override {
        ++state_->disableCalls;
        if (!state_->disableSucceeds) {
            error = "injected PAM disable failure";
            return false;
        }
        state_->state = fic::identity::pam::PamTopologyState::Disabled;
        error.clear();
        return true;
    }
private:
    std::shared_ptr<FakePamState> state_;
};

void testPamOwnershipRelease() {
    using namespace fic::platform;
    PamRollbackOptions options;
    options.platform.scopes = {{PamScope::EffectivePasswordStack, {"passwd"}}};
    PamCapabilityConfig capability;
    capability.capability = PamCapability::PasswordHistory;
    capability.scope = PamScope::EffectivePasswordStack;
    capability.topology = PamTopologyStrategyKind::PamAuthUpdate;
    capability.activationIdentifiers = {"fic-pwhistory"};
    options.platform.capabilities = {capability};
    auto state = std::make_shared<FakePamState>();
    options.managerFactory = [state](const auto&, const auto&,
                                     std::string& error) {
        error.clear();
        return std::make_unique<FakePamManager>(state);
    };
    const UndoDisablePamCapability undo{
        "enable_password_history", PamTopologyKind::PamAuthUpdate,
        {"fic-pwhistory"}};
    const auto orphan = inspectUnrecordedPamCapability(
        options, "enable_password_history");
    require(orphan.state == PamRollbackState::Conflict,
            "FIC marker without provenance must fail closed");
    auto mismatched = undo;
    mismatched.activationIdentifiers = {"foreign"};
    require(undoPamCapability(options, mismatched).state ==
                PamRollbackState::Conflict,
            "recorded selection domain must match current profile");
    require(state->disableCalls == 0,
            "mismatched provenance must not invoke native disable");
    state->manageable = false;
    require(undoPamCapability(options, undo).state ==
                PamRollbackState::AlreadyReleased,
            "external equivalent topology must not be disabled");
    state->manageable = true;
    require(undoPamCapability(options, undo).state ==
                PamRollbackState::Released,
            "owned topology must be released");
    require(state->disableCalls == 1, "native disable must run exactly once");
    require(undoPamCapability(options, undo).state ==
                PamRollbackState::AlreadyReleased,
            "released topology must be idempotent");
    PamRollbackOptions staticOptions;
    staticOptions.platform.scopes = {
        {PamScope::EffectivePasswordStack, {"passwd"}}};
    PamCapabilityConfig staticCapability;
    staticCapability.capability = PamCapability::PasswordQuality;
    staticCapability.scope = PamScope::EffectivePasswordStack;
    staticCapability.topology = PamTopologyStrategyKind::StaticVerifyOnly;
    staticOptions.platform.capabilities = {staticCapability};
    require(inspectUnrecordedPamCapability(staticOptions,
                "enable_password_quality").state ==
                PamRollbackState::AlreadyReleased,
            "StaticVerifyOnly must not require a native deactivation manager");

    PamRollbackOptions sharedOptions;
    sharedOptions.platform.scopes = {
        {PamScope::EffectivePasswordStack, {"passwd"}}};
    PamCapabilityConfig shared = capability;
    shared.capability = PamCapability::PasswordQuality;
    shared.activationIdentifiers = {"pwquality"};
    shared.activationOwnershipRequiresJournal = true;
    sharedOptions.platform.capabilities = {shared};
    auto sharedState = std::make_shared<FakePamState>();
    sharedState->manageable = false;
    sharedOptions.managerFactory = [sharedState](const auto&, const auto&,
                                                 std::string& error) {
        error.clear();
        return std::make_unique<FakePamManager>(sharedState);
    };
    const UndoDisablePamCapability sharedUndo{
        "enable_password_quality", PamTopologyKind::PamAuthUpdate,
        {"pwquality"}};
    require(inspectUnrecordedPamCapability(sharedOptions,
                "enable_password_quality").state ==
                PamRollbackState::AlreadyReleased &&
                sharedState->disableCalls == 0,
            "unrecorded distro pwquality must remain enabled");
    require(undoPamCapability(sharedOptions, sharedUndo).state ==
                PamRollbackState::Conflict &&
                sharedState->disableCalls == 0,
            "intent-only journal cannot claim a shared distro profile");
    sharedState->manageable = true;
    auto provenSharedUndo = sharedUndo;
    provenSharedUndo.confirmedNativeOwnership = true;
    require(undoPamCapability(sharedOptions, provenSharedUndo).state ==
                PamRollbackState::Released &&
                sharedState->disableCalls == 1,
            "confirmed native shared-profile provenance must permit release");
}

void testPamExecutorJournalLifecycle() {
    using namespace fic::platform;
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    RollbackExecutorDeps deps;
    deps.pamPlatform.scopes = {{PamScope::EffectivePasswordStack, {"passwd"}}};
    PamCapabilityConfig capability;
    capability.capability = PamCapability::PasswordHistory;
    capability.scope = PamScope::EffectivePasswordStack;
    capability.topology = PamTopologyStrategyKind::PamAuthUpdate;
    capability.activationIdentifiers = {"fic-pwhistory"};
    deps.pamPlatform.capabilities = {capability};
    auto state = std::make_shared<FakePamState>();
    deps.pamManagerFactory = [state](const auto&, const auto&,
                                     std::string& error) {
        error.clear();
        return std::make_unique<FakePamManager>(state);
    };
    const PolicyRef policy{"IDENTITY_ACCESS", "PAM",
                           "enable_password_history"};
    const std::string resource = "capability/enable_password_history";
    const UndoAction undo{MutationBackend::Pam, UndoDisablePamCapability{
        "enable_password_history", PamTopologyKind::PamAuthUpdate,
        {"fic-pwhistory"}}};
    require(rollbackPolicyBeforeDisable(policy, resource, deps).status ==
                RollbackStatus::Conflict,
            "unrecorded FIC-owned PAM topology must refuse disable");
    const MutationId id = recordApplied(policy, resource, undo);
    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, resource, deps);
    require(report.status == RollbackStatus::Success &&
                state->disableCalls == 1,
            "journal-backed PAM rollback must release owned topology");
    std::string error;
    auto* persisted = DaemonMutationJournal::instance().tryGet(error);
    require(persisted != nullptr, error);
    require(persisted->records().front().id == id &&
                persisted->records().front().status ==
                    MutationStatus::RolledBack,
            "successful PAM release must close its journal record");
    require(rollbackPolicyBeforeDisable(policy, resource, deps).status ==
                RollbackStatus::NothingToDo && state->disableCalls == 1,
            "repeated PAM disable must not re-run native mutation");
    state->state = fic::identity::pam::PamTopologyState::Enabled;
    state->manageable = false;
    recordApplied(policy, resource, undo);
    require(rollbackPolicyBeforeDisable(policy, resource, deps).status ==
                RollbackStatus::NothingToDo && state->disableCalls == 1,
            "external equivalent PAM topology must remain untouched");
    state->manageable = true;
    state->disableSucceeds = false;
    recordApplied(policy, resource, undo);
    require(rollbackPolicyBeforeDisable(policy, resource, deps).status ==
                RollbackStatus::Failed,
            "native PAM rollback failure must refuse disable");
    require(persisted->activeRecords(policy).front().status ==
                MutationStatus::RollbackFailed,
            "failed PAM release must retain active provenance");
}

void testNotEnrolledPolicyKeepsLegacyDisable() {
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        {"TCB", "Unknown", "legacy_policy"}, "", RollbackExecutorDeps{});
    require(report.status == RollbackStatus::Success,
            "not enrolled policy must allow legacy disable");
    require(report.rollbackCompleted(), "legacy disable must not be refused");
}

void testUnsupportedPolicyRefusesDisable() {
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        {"DAC", "SudoEdit", "sudo_require_authentication"}, "",
        RollbackExecutorDeps{});
    require(report.status == RollbackStatus::Unsupported,
            "enrolled but unsupported policy must refuse disable");
    require(!report.rollbackCompleted(),
            "unsupported rollback must refuse the disable");
}

void testSysctlRollbackRemovesManagedKeyAndMovesRuntime() {
    SysctlTree tree;
    tree.createManagedValue("vm.swappiness", "10");
    writeFile(tree.tree.root / "etc/sysctl.d/10-base.conf",
              "vm.swappiness = 30\n");
    writeFile(tree.tree.root / "proc/sys/vm/swappiness", "10\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId id = recordApplied(
        kSysctlPolicy, "vm.swappiness", sysctlUndo("10"));

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);
    require(report.rollbackCompleted(), "successful rollback must allow disable");
    require(report.outcomes.size() == 1 &&
                report.outcomes.front().status == RollbackStatus::Success,
            report.message);

    // The managed override must be gone; the base configuration value stays.
    SysctlConfiguration verification(tree.options());
    std::string error;
    require(verification.load(error), error);
    const SysctlValueObservation after = verification.inspect("vm.swappiness");
    require(after.found && after.value == "30", report.message);
    require(after.source.path.filename() == "10-base.conf",
            "rollback must leave the non-FIC source in place");

    // Runtime must be moved to the recomputed effective value, never guessed.
    SysctlRuntime runtime({tree.tree.root / "proc/sys"});
    std::string runtimeValue;
    require(runtime.readValue("vm.swappiness", runtimeValue, error), error);
    require(runtimeValue == "30",
            "runtime sysctl must follow the remaining configuration value");

    // Journal must record the rollback.
    MutationJournal stored(journal.tree.root / "journal.json");
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status == MutationStatus::RolledBack,
            "rollback must be persisted as rolled_back");
}

void testSysctlRollbackConflictOnDrift() {
    SysctlTree tree;
    // The managed value drifted from the recorded applied value.
    tree.createManagedValue("vm.swappiness", "20");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kSysctlPolicy, "vm.swappiness", sysctlUndo("10"));

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Conflict,
            "drifted managed value must fail closed as conflict: " +
                report.message);
    require(!report.rollbackCompleted(),
            "conflict must refuse the disable");

    // The drifted value must be left untouched.
    SysctlConfiguration verification(tree.options());
    std::string error;
    require(verification.load(error), error);
    const SysctlValueObservation after = verification.inspect("vm.swappiness");
    require(after.found && after.value == "20",
            "conflicting managed value must not be modified");
}

void testSysctlRollbackRemovesShadowedManagedEntry() {
    SysctlTree tree;
    tree.createManagedValue("vm.swappiness", "10");
    // A later external source shadows the FIC entry: the effective value is
    // not FIC-owned anymore, but the FIC-owned persistent entry must still be
    // removed so it cannot become effective again after the override is gone.
    writeFile(tree.tree.root / "etc/sysctl.d/zzzzz-external.conf",
              "vm.swappiness = 1\n");
    writeFile(tree.tree.root / "proc/sys/vm/swappiness", "1\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId id = recordApplied(
        kSysctlPolicy, "vm.swappiness", sysctlUndo("10"));

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);
    require(report.rollbackCompleted(), "successful rollback must allow disable");

    // The FIC entry is gone from the managed artifact.
    SysctlConfiguration verification(tree.options());
    std::string error;
    require(verification.load(error), error);
    const SysctlValueObservation managedAfter =
        verification.inspectManagedValue("vm.swappiness");
    require(!managedAfter.found,
            "shadowed FIC managed entry must still be removed by rollback");

    // The external source keeps ownership of the effective value.
    const SysctlValueObservation after = verification.inspect("vm.swappiness");
    require(after.found && after.value == "1" &&
                after.source.path.filename() == "zzzzz-external.conf",
            "external override must remain the effective source");

    // Runtime follows the recomputed external value.
    SysctlRuntime runtime({tree.tree.root / "proc/sys"});
    std::string runtimeValue;
    require(runtime.readValue("vm.swappiness", runtimeValue, error), error);
    require(runtimeValue == "1",
            "runtime sysctl must follow the remaining external value");

    // Journal must record the rollback.
    MutationJournal stored(journal.tree.root / "journal.json");
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status == MutationStatus::RolledBack,
            "shadowed entry rollback must be persisted as rolled_back");
}

void testSysctlProvenanceUnavailableWithoutJournal() {
    SysctlTree tree;
    // The FIC managed file owns the resource, but no journal records exist
    // (legacy apply before the rollback system): disable must be refused.
    tree.createManagedValue("vm.swappiness", "10");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Unsupported,
            "unprovenanced FIC-owned sysctl change must refuse disable: " +
                report.message);
    require(!report.rollbackCompleted(),
            "provenance failure must refuse the disable");
}

void testSysctlLegacyProvenanceRefusedWhenShadowed() {
    SysctlTree tree;
    // Legacy state: the FIC managed file contains the key, but an external
    // source currently shadows it and no journal records exist. The hidden
    // FIC-owned state must refuse the disable (fail closed), not be ignored.
    tree.createManagedValue("vm.swappiness", "10");
    writeFile(tree.tree.root / "etc/sysctl.d/zzzzz-external.conf",
              "vm.swappiness = 1\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Unsupported,
            "unprovenanced FIC-owned sysctl state must refuse disable even "
            "when shadowed by an external source: " + report.message);
    require(!report.rollbackCompleted(),
            "provenance failure must refuse the disable");

    // The shadowed FIC entry must be left untouched.
    SysctlConfiguration verification(tree.options());
    std::string error;
    require(verification.load(error), error);
    const SysctlValueObservation managed =
        verification.inspectManagedValue("vm.swappiness");
    require(managed.found && managed.value == "10",
            "refused rollback must not remove the FIC managed entry");
}

void testSysctlNoRecordsAndNotOwnedIsNothingToDo() {
    SysctlTree tree;
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::NothingToDo,
            "no records and no FIC-owned resource must allow legacy disable: " +
                report.message);
    require(report.rollbackCompleted(), "nothing to do must allow disable");
}


void testSudoRollbackRemovesManagedDefault() {
    SudoersTree tree;
    const auto options = tree.options("Defaults passwd_tries=2");
    {
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        const SudoersOperationResult operation = configuration
            .ensureManagedGlobalDefault("passwd_tries",
                                        "Defaults passwd_tries=3", "3");
        require(operation.ok && operation.changed, operation.message);
    }

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId id = recordApplied(
        kSudoPolicy, "passwd_tries",
        UndoAction{MutationBackend::Sudo,
                   UndoRemoveManagedSetting{"passwd_tries", "3"}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSudoPolicy, "passwd_tries", tree.deps("Defaults passwd_tries=2"));
    require(report.status == RollbackStatus::Success, report.message);
    require(report.outcomes.size() == 1 &&
                report.outcomes.front().status == RollbackStatus::Success,
            report.message);

    require(!std::filesystem::exists(options.managedPath),
            "empty FIC managed sudoers file must be removed by rollback");

    MutationJournal stored(journal.tree.root / "journal.json");
    std::string error;
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status == MutationStatus::RolledBack,
            "sudo rollback must be persisted as rolled_back");
}

void testSudoRollbackConflictOnDrift() {
    SudoersTree tree;
    const auto options = tree.options("Defaults passwd_tries=2");
    {
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        const SudoersOperationResult operation = configuration
            .ensureManagedGlobalDefault("passwd_tries",
                                        "Defaults passwd_tries=5", "5");
        require(operation.ok && operation.changed, operation.message);
    }

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(
        kSudoPolicy, "passwd_tries",
        UndoAction{MutationBackend::Sudo,
                   UndoRemoveManagedSetting{"passwd_tries", "3"}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSudoPolicy, "passwd_tries", tree.deps("Defaults passwd_tries=2"));
    require(report.status == RollbackStatus::Conflict,
            "drifted sudoers value must fail closed as conflict: " +
                report.message);
    require(!report.rollbackCompleted(), "conflict must refuse the disable");
    require(readFile(options.managedPath).find("passwd_tries=5") !=
                std::string::npos,
            "conflicting managed value must not be modified");
}

void testSudoRollbackMissingManagedEntryIsNothingToDo() {
    SudoersTree tree;
    // The journal proves a FIC mutation, but the FIC managed entry is already
    // gone (e.g. a previous rollback): nothing FIC-owned persists, so the
    // external sudoers value must not be touched and disable may proceed.
    const std::string mainSudoers = "Defaults passwd_tries=7";
    const auto options = tree.options(mainSudoers);
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(
        kSudoPolicy, "passwd_tries",
        UndoAction{MutationBackend::Sudo,
                   UndoRemoveManagedSetting{"passwd_tries", "3"}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSudoPolicy, "passwd_tries", tree.deps(mainSudoers));
    require(report.status == RollbackStatus::NothingToDo,
            "absent FIC managed entry must be an idempotent nothing-to-do: " +
                report.message);
    require(report.rollbackCompleted(),
            "nothing-to-do rollback must allow the disable");
    require(readFile(options.mainPath).find("passwd_tries=7") !=
                std::string::npos,
            "external sudoers content must not be touched");
}

void testSudoRollbackRemovesShadowedManagedEntry() {
    SudoersTree tree;
    const auto options = tree.options("Defaults timestamp_timeout=2");
    // An external fragment sorts after the FIC managed file and shadows its
    // entry: the effective value is 10, but the FIC-owned entry still exists
    // and must be removed by the rollback.
    const std::filesystem::path external =
        tree.tree.root / "sudoers.d" / "zzzzz-external";
    writeFile(external, "Defaults timestamp_timeout=10\n");
    writeFile(options.managedPath, "Defaults timestamp_timeout=5\n");

    {
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        const SudoersValueObservation effective =
            configuration.inspectGlobalDefault("timestamp_timeout");
        require(effective.found && effective.value == "10" &&
                    effective.source.path == external,
            "fixture precondition: external source must be effective");
        const SudoersValueObservation managed =
            configuration.inspectManagedGlobalDefault("timestamp_timeout");
        require(managed.found && managed.value == "5",
            "fixture precondition: managed entry must be visible");
    }

    const PolicyRef policy{"DAC", "SudoEdit", "sudo_timeout"};
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId id = recordApplied(
        policy, "timestamp_timeout",
        UndoAction{MutationBackend::Sudo,
                   UndoRemoveManagedSetting{"timestamp_timeout", "5"}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        policy, "timestamp_timeout", tree.deps("Defaults timestamp_timeout=2"));
    require(report.status == RollbackStatus::Success, report.message);
    require(report.outcomes.size() == 1 &&
                report.outcomes.front().status == RollbackStatus::Success,
            report.message);

    require(!std::filesystem::exists(options.managedPath),
            "shadowed FIC managed entry must still be removed by rollback");
    require(readFile(external).find("timestamp_timeout=10") !=
                std::string::npos,
            "external overriding source must survive the rollback");

    SudoersConfiguration verification(options);
    std::string error;
    require(verification.load(error), error);
    const SudoersValueObservation after =
        verification.inspectGlobalDefault("timestamp_timeout");
    require(after.found && after.value == "10" && after.source.path == external,
            "effective value must stay owned by the external source");

    MutationJournal stored(journal.tree.root / "journal.json");
    std::string storedError;
    require(stored.load(storedError), storedError);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status == MutationStatus::RolledBack,
            "shadowed rollback must be persisted as rolled_back");
}

void testSudoLegacyProvenanceRefusedWhenShadowed() {
    SudoersTree tree;
    const auto options = tree.options("Defaults timestamp_timeout=2");
    const std::filesystem::path external =
        tree.tree.root / "sudoers.d" / "zzzzz-external";
    const std::string externalContent = "Defaults timestamp_timeout=10\n";
    const std::string managedContent = "Defaults timestamp_timeout=5\n";
    writeFile(external, externalContent);
    writeFile(options.managedPath, managedContent);

    // No journal records: the managed entry may be a legacy FIC mutation and
    // its provenance cannot be proven, even though an external source
    // currently shadows it.
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");

    const PolicyRef policy{"DAC", "SudoEdit", "sudo_timeout"};
    const RollbackReport report = rollbackPolicyBeforeDisable(
        policy, "timestamp_timeout", tree.deps("Defaults timestamp_timeout=2"));
    require(report.status == RollbackStatus::Unsupported,
            "shadowed legacy managed entry must refuse the disable: " +
                report.message);
    require(!report.rollbackCompleted(),
            "provenance unavailable must refuse the disable");
    require(readFile(options.managedPath) == managedContent,
            "legacy managed entry must not be modified");
    require(readFile(external) == externalContent,
            "external source must not be modified");
}

void testSysctlRollbackKeepsOtherPolicySetting() {
    SysctlTree tree;
    tree.createManagedValue("vm.swappiness", "10");
    tree.createManagedValue("kernel.dmesg_restrict", "1");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kSysctlPolicy, "vm.swappiness", sysctlUndo("10"));
    // A second policy owns another key of the same FIC managed file.
    const PolicyRef other{"SYSCTL", "Global", "dmesg_policy"};
    recordApplied(other, "kernel.dmesg_restrict",
                  UndoAction{MutationBackend::Sysctl,
                             UndoRemoveManagedSetting{"kernel.dmesg_restrict", "1"}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);

    const std::string managed =
        readFile(tree.options().platform.managedConfigPath);
    require(managed.find("vm.swappiness") == std::string::npos,
            "rolled back key must be removed from the managed file");
    require(managed.find("kernel.dmesg_restrict") != std::string::npos,
            "another policy setting in the same managed file must survive");

    MutationJournal stored(journal.tree.root / "journal.json");
    std::string error;
    require(stored.load(error), error);
    for (const MutationRecord& record : stored.records()) {
        if (record.resource == "vm.swappiness") {
            require(record.status == MutationStatus::RolledBack,
                    "first policy mutation must be rolled back");
        } else if (record.resource == "kernel.dmesg_restrict") {
            require(record.status == MutationStatus::Applied,
                    "other policy mutation must stay applied");
        }
    }
}

void testSudoRollbackVisudoFailureFailsClosed() {
    SudoersTree tree;
    SudoersConfigurationOptions options = tree.options("Defaults passwd_tries=2");
    // Validator accepts the state while the FIC managed file exists and fails
    // once the rollback removes it, emulating a visudo rejection.
    const std::filesystem::path validator = tree.tree.root / "validator";
    writeFile(validator,
              "#!/bin/sh\n[ -f '" + options.managedPath.string() + "' ]\n");
    require(::chmod(validator.c_str(), 0700) == 0,
            "failed to make validator executable");
    options.validatorPath = validator;
    options.verifyValidatorHash = false;

    writeFile(options.managedPath, "Defaults passwd_tries=3\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId id = recordApplied(
        kSudoPolicy, "passwd_tries",
        UndoAction{MutationBackend::Sudo,
                   UndoRemoveManagedSetting{"passwd_tries", "3"}});

    RollbackExecutorDeps deps;
    deps.sudoersOptions = [options]() { return options; };
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSudoPolicy, "passwd_tries", deps);
    require(report.status == RollbackStatus::Failed,
            "visudo failure must fail the rollback closed: " + report.message);
    require(!report.rollbackCompleted(),
            "failed rollback must refuse the disable");
    require(std::filesystem::exists(options.managedPath) &&
                readFile(options.managedPath).find("passwd_tries=3") !=
                    std::string::npos,
            "managed entry must be restored after validation failure");

    MutationJournal stored(journal.tree.root / "journal.json");
    std::string storedError;
    require(stored.load(storedError), storedError);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status != MutationStatus::RolledBack,
            "failed rollback must not mark the mutation as rolled back");
}

void testSudoRepeatedDisableIsIdempotent() {
    SudoersTree tree;
    const auto options = tree.options("Defaults passwd_tries=2");
    {
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        const SudoersOperationResult first = configuration
            .ensureManagedGlobalDefault("passwd_tries",
                                        "Defaults passwd_tries=3", "3");
        require(first.ok && first.changed, first.message);
        const SudoersOperationResult second = configuration
            .ensureManagedGlobalDefault(
                "secure_path",
                "Defaults secure_path=/usr/sbin:/usr/bin",
                "/usr/sbin:/usr/bin");
        require(second.ok && second.changed, second.message);
    }

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kSudoPolicy, "passwd_tries",
                  UndoAction{MutationBackend::Sudo,
                             UndoRemoveManagedSetting{"passwd_tries", "3"}});

    const RollbackReport first = rollbackPolicyBeforeDisable(
        kSudoPolicy, "passwd_tries", tree.deps("Defaults passwd_tries=2"));
    require(first.status == RollbackStatus::Success, first.message);

    const RollbackReport second = rollbackPolicyBeforeDisable(
        kSudoPolicy, "passwd_tries", tree.deps("Defaults passwd_tries=2"));
    require(second.status == RollbackStatus::NothingToDo,
            "repeated disable after a completed rollback must be idempotent: " +
                second.message);
    require(second.rollbackCompleted(),
            "repeated nothing-to-do must still allow the disable");
    require(std::filesystem::exists(options.managedPath) &&
                readFile(options.managedPath).find("secure_path") !=
                    std::string::npos,
            "other managed sudo defaults must survive repeated disables");
}

void testSysctlRollbackRetryIsIdempotent() {
    SysctlTree tree;
    tree.createManagedValue("vm.swappiness", "10");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kSysctlPolicy, "vm.swappiness", sysctlUndo("10"));

    const RollbackReport first = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(first.status == RollbackStatus::Success, first.message);

    // Retry (e.g. after daemon restart): the record is already rolled back
    // and the managed file is gone, the retry must be nothing-to-do.
    const RollbackReport retry = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(retry.status == RollbackStatus::NothingToDo, retry.message);
    require(retry.rollbackCompleted(), "retry must allow the disable");
}

void testSysctlRepeatedApplyRepairsDriftThenRollback() {
    SysctlTree tree;
    tree.createManagedValue("vm.swappiness", "10");
    writeFile(tree.tree.root / "proc/sys/vm/swappiness", "10\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId originalId = recordApplied(
        kSysctlPolicy, "vm.swappiness", sysctlUndo("10"));

    // Repairable drift appears after the initial apply: the FIC managed
    // entry itself is changed externally to 20.
    writeFile(tree.tree.root / "etc/sysctl.d/zzzz-fic.conf",
              "vm.swappiness = 20\n");

    // Repeated apply at the configuration/journal level: the managed content
    // drifted, so the single active record is refreshed (Applied -> Prepared
    // -> Applied) and the managed value is repaired without duplicating
    // provenance.
    MutationId refreshedId = 0;
    std::string error;
    require(recordPreparedMutation(kSysctlPolicy, "vm.swappiness",
                                   sysctlUndo("10"), refreshedId, error),
            error);
    require(refreshedId == originalId,
            "repeated apply must refresh the existing active record");
    {
        SysctlConfiguration configuration(tree.options());
        require(configuration.load(error), error);
        const SysctlOperationResult operation =
            configuration.ensureManagedValue("vm.swappiness", "10");
        require(operation.ok, operation.message);
        require(operation.changed,
                "repeated apply must repair the drifted managed value");
    }
    require(commitMutation(refreshedId, error), error);

    MutationJournal stored(journal.tree.root / "journal.json");
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().id == originalId &&
                stored.records().front().status == MutationStatus::Applied,
            "repeated apply must keep a single refreshed active record");

    // Disable after the drift repair must still roll back correctly: the
    // recorded undo value must match the repaired managed value.
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);

    SysctlConfiguration verification(tree.options());
    require(verification.load(error), error);
    const SysctlValueObservation managedAfter =
        verification.inspectManagedValue("vm.swappiness");
    require(!managedAfter.found,
            "repaired-state rollback must remove the FIC managed entry");
    // No remaining persistent source exists: the runtime value is left as is
    // (never guessed), and the last applied runtime value was 10.
    SysctlRuntime runtime({tree.tree.root / "proc/sys"});
    std::string runtimeValue;
    require(runtime.readValue("vm.swappiness", runtimeValue, error), error);
    require(runtimeValue == "10",
            "rollback must not guess a new runtime value without a "
            "remaining persistent source");
}

void testExecutorResolvesPreparedRecordAfterFailedCommit() {
    SysctlTree tree;
    tree.createManagedValue("vm.swappiness", "10");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    // Backend invariant scenario: the system mutation succeeded, the
    // Prepared -> Applied commit failed, and the Prepared record stays
    // active on disk. The disable must still resolve this state safely.
    MutationId id = 0;
    std::string error;
    require(recordPreparedMutation(kSysctlPolicy, "vm.swappiness",
                                   sysctlUndo("10"), id, error),
            error);

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);
    require(report.rollbackCompleted(),
            "prepared provenance must be resolvable by the rollback executor");

    SysctlConfiguration verification(tree.options());
    require(verification.load(error), error);
    const SysctlValueObservation managedAfter =
        verification.inspectManagedValue("vm.swappiness");
    require(!managedAfter.found,
            "prepared provenance must still lead to managed entry removal");

    MutationJournal stored(journal.tree.root / "journal.json");
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status == MutationStatus::RolledBack,
            "prepared record resolution must be persisted as rolled_back");
}

void testSudoRollbackKeepsOtherManagedDefault() {
    SudoersTree tree;
    const auto options = tree.options("Defaults passwd_tries=2");
    {
        SudoersConfiguration configuration(options);
        std::string error;
        require(configuration.load(error), error);
        const SudoersOperationResult first = configuration
            .ensureManagedGlobalDefault("passwd_tries",
                                        "Defaults passwd_tries=3", "3");
        require(first.ok && first.changed, first.message);
        const SudoersOperationResult second = configuration
            .ensureManagedGlobalDefault("secure_path",
                                        "Defaults secure_path=/usr/sbin:/usr/bin",
                                        "/usr/sbin:/usr/bin");
        require(second.ok && second.changed, second.message);
    }

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kSudoPolicy, "passwd_tries",
                  UndoAction{MutationBackend::Sudo,
                             UndoRemoveManagedSetting{"passwd_tries", "3"}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSudoPolicy, "passwd_tries", tree.deps("Defaults passwd_tries=2"));
    require(report.status == RollbackStatus::Success, report.message);

    const std::string managed = readFile(options.managedPath);
    require(managed.find("passwd_tries") == std::string::npos,
            "rolled back sudo default must be removed");
    require(managed.find("secure_path") != std::string::npos,
            "another FIC managed sudo default must survive");
    require(std::filesystem::exists(options.managedPath),
            "non-empty managed sudoers file must not be removed");
}


void testFirewallUndoInvokesBackend() {
    const PolicyRef policy{"FIREWALL", "HostFiltering", "block_rdp"};
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(policy, "block_rdp",
                  UndoAction{MutationBackend::Firewall,
                             UndoRemoveFirewallPolicy{"fic_block_rdp"}});

    std::string undonePolicy;
    RollbackExecutorDeps deps;
    deps.undoFirewallPolicy = [&undonePolicy](const std::string& policyName,
                                              std::string&) {
        undonePolicy = policyName;
        return true;
    };

    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "block_rdp", deps);
    require(report.status == RollbackStatus::Success, report.message);
    require(undonePolicy == "fic_block_rdp",
            "firewall undo must call the reconciliation backend with the "
            "recorded policy name");

    MutationJournal stored(journal.tree.root / "journal.json");
    std::string error;
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().status == MutationStatus::RolledBack,
            "firewall rollback must be persisted");
}

void testFirewallUndoFailureFailsClosed() {
    const PolicyRef policy{"FIREWALL", "HostFiltering", "block_ftp"};
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId id = recordApplied(
        policy, "block_ftp",
        UndoAction{MutationBackend::Firewall,
                   UndoRemoveFirewallPolicy{"fic_block_ftp"}});

    RollbackExecutorDeps deps;
    deps.undoFirewallPolicy = [](const std::string&, std::string& error) {
        error = "nft reconciliation failed";
        return false;
    };

    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "block_ftp", deps);
    require(report.status == RollbackStatus::Failed,
            "failed firewall undo must fail closed: " + report.message);
    require(!report.rollbackCompleted(), "failed rollback must refuse disable");

    MutationJournal stored(journal.tree.root / "journal.json");
    std::string error;
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status == MutationStatus::RollbackFailed,
            "failed rollback must be persisted as rollback_failed");
}

void testDeviceFeatureUndoInvokesBackend() {
    const PolicyRef policy{"DC", "DeviceControl", "block_usb_storage"};
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(policy, "block_usb_storage",
                  UndoAction{MutationBackend::DeviceControl,
                             UndoDisableDeviceFeature{"block_usb_storage"}});

    std::string disabledFeature;
    RollbackExecutorDeps deps;
    deps.disableDeviceFeature = [&disabledFeature](const std::string& feature,
                                                   std::string&) {
        disabledFeature = feature;
        return true;
    };

    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "block_usb_storage", deps);
    require(report.status == RollbackStatus::Success, report.message);
    require(disabledFeature == "block_usb_storage",
            "DC undo must disable the recorded feature");
}

void testDeviceFeatureUndoUnknownFeatureIsUnsupported() {
    const PolicyRef policy{"DC", "DeviceControl", "future_feature"};
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(policy, "future_feature",
                  UndoAction{MutationBackend::DeviceControl,
                             UndoDisableDeviceFeature{"future_feature"}});

    RollbackExecutorDeps deps;
    deps.disableDeviceFeature = [](const std::string&, std::string&) {
        return true;
    };

    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "future_feature", deps);
    require(report.status == RollbackStatus::Unsupported,
            "unknown DC feature undo must be unsupported: " + report.message);
    require(!report.rollbackCompleted(), "unsupported undo must refuse disable");
}


// ------------------------------------------------------------------ dac ----

// Writes a file with the given mode (owner/group = test user, like the
// ModeAndOwner tests, so the suite runs unprivileged).
void writeDacFile(const std::filesystem::path& path, mode_t mode) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    require(stream.is_open(), "could not create " + path.string());
    stream << "data";
    stream.close();
    require(stream.good(), "could not write " + path.string());
    require(::chmod(path.c_str(), mode) == 0,
            "could not chmod " + path.string());
}

mode_t dacFileMode(const std::filesystem::path& path) {
    struct stat info {};
    require(::stat(path.c_str(), &info) == 0,
            "could not stat " + path.string());
    return info.st_mode & 07777;
}

std::string dacOwner() {
    const struct passwd* owner = ::getpwuid(::geteuid());
    require(owner != nullptr, "could not resolve test owner");
    return owner->pw_name;
}

std::string dacGroup() {
    const struct group* group = ::getgrgid(::getegid());
    require(group != nullptr, "could not resolve test group");
    return group->gr_name;
}

RollbackExecutorDeps dacDeps(const std::filesystem::path& managedFile) {
    DacBaselineRollbackOptions options;
    options.platform.protectedSystemCommands = {
        {managedFile,
         {dacOwner(), dacGroup(), 0750},
         {dacOwner(), dacGroup(), 0755}}};
    RollbackExecutorDeps deps;
    deps.dacOptions = [options]() { return options; };
    return deps;
}

void testDacBaselineRollbackTransitionsToBaseline() {
    const PolicyRef policy{"DAC", "Mode_and_Owner", "systemcommandlock"};
    TempTree tree("/tmp/fic-rollback-dac-XXXXXX");
    const std::filesystem::path managed = tree.root / "managed-binary";
    // Simulates the post-apply state with an admin drift afterwards.
    writeDacFile(managed, 0700);

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(policy, "systemcommandlock",
                  UndoAction{MutationBackend::Dac,
                             UndoApplyDacPlatformBaseline{
                                 "systemcommandlock"}});

    const RollbackExecutorDeps deps = dacDeps(managed);
    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(report.status == RollbackStatus::Success, report.message);
    require(dacFileMode(managed) == 0755,
            "disable rollback must transition to the platform baseline");
    std::string journalError;
    MutationJournal* journalPtr =
        DaemonMutationJournal::instance().tryGet(journalError);
    require(journalPtr != nullptr, journalError);
    require(journalPtr->activeRecords(policy).empty(),
            "a completed baseline rollback must resolve the journal record");
}

void testDacBaselineRollbackIsIdempotent() {
    const PolicyRef policy{"DAC", "Mode_and_Owner", "systemcommandlock"};
    TempTree tree("/tmp/fic-rollback-dac-XXXXXX");
    const std::filesystem::path managed = tree.root / "managed-binary";
    writeDacFile(managed, 0750);

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(policy, "systemcommandlock",
                  UndoAction{MutationBackend::Dac,
                             UndoApplyDacPlatformBaseline{
                                 "systemcommandlock"}});

    const RollbackExecutorDeps deps = dacDeps(managed);
    const RollbackReport first =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(first.status == RollbackStatus::Success, first.message);
    require(dacFileMode(managed) == 0755, first.message);

    // A repeated disable (baseline -> baseline) must stay a no-op: the
    // executor reports NothingToDo explicitly, which still completes the
    // disable (rollbackCompleted()).
    recordApplied(policy, "systemcommandlock",
                  UndoAction{MutationBackend::Dac,
                             UndoApplyDacPlatformBaseline{
                                 "systemcommandlock"}});
    const RollbackReport second =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(second.status == RollbackStatus::NothingToDo, second.message);
    require(second.rollbackCompleted(),
            "idempotent no-op rollback must allow the disable");
    require(dacFileMode(managed) == 0755,
            "repeated rollback must keep the baseline mode");
}

void testDacUnrecordedLegacyProvenanceRollsBackEnforcedState() {
    const PolicyRef policy{"DAC", "Mode_and_Owner", "systemcommandlock"};
    TempTree tree("/tmp/fic-rollback-dac-XXXXXX");
    const std::filesystem::path managed = tree.root / "managed-binary";
    // Enforced state without any journal record (legacy apply).
    writeDacFile(managed, 0750);

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");

    const RollbackExecutorDeps deps = dacDeps(managed);
    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(report.status == RollbackStatus::Success,
            "proven enforced state must roll back to baseline: " +
                report.message);
    require(dacFileMode(managed) == 0755,
            "legacy proven rollback must land on the platform baseline");
}

void testDacUnrecordedForeignStateRefusesDisable() {
    const PolicyRef policy{"DAC", "Mode_and_Owner", "systemcommandlock"};
    TempTree tree("/tmp/fic-rollback-dac-XXXXXX");
    const std::filesystem::path managed = tree.root / "managed-binary";
    // Neither the enforced (0750) nor the baseline (0755) state.
    writeDacFile(managed, 0777);

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");

    const RollbackExecutorDeps deps = dacDeps(managed);
    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(report.status == RollbackStatus::Unsupported,
            "foreign state without provenance must refuse disable: " +
                report.message);
    require(!report.rollbackCompleted(), "disable must be refused");
    require(dacFileMode(managed) == 0777,
            "refused rollback must not touch the foreign state");
}

void testDacUnrecordedAtBaselineIsNothingToDo() {
    const PolicyRef policy{"DAC", "Mode_and_Owner", "systemcommandlock"};
    TempTree tree("/tmp/fic-rollback-dac-XXXXXX");
    const std::filesystem::path managed = tree.root / "managed-binary";
    writeDacFile(managed, 0755);

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");

    const RollbackExecutorDeps deps = dacDeps(managed);
    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(report.status == RollbackStatus::NothingToDo,
            "baseline state without provenance is nothing to do: " +
                report.message);
    require(dacFileMode(managed) == 0755,
            "nothing-to-do rollback must not change the mode");
}

void testDacBlockingPolicyRollbackUsesProfileBaseline() {
    const PolicyRef policy{
        "DAC", "Mode_and_Owner", "blocking_user_access_to_system_files"};
    TempTree tree("/tmp/fic-rollback-dac-XXXXXX");
    const std::filesystem::path managed = tree.root / "system-file";
    writeDacFile(managed, 0600);

    DacBaselineRollbackOptions options;
    options.platform.protectedSystemFiles = {
        {managed,
         {dacOwner(), dacGroup(), 0600},
         {dacOwner(), dacGroup(), 0644}}};
    RollbackExecutorDeps deps;
    deps.dacOptions = [options]() { return options; };

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(policy, "blocking_user_access_to_system_files",
                  UndoAction{MutationBackend::Dac,
                             UndoApplyDacPlatformBaseline{
                                 "blocking_user_access_to_system_files"}});

    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(report.status == RollbackStatus::Success, report.message);
    require(dacFileMode(managed) == 0644,
            "blocking files rollback must restore the crontab-style baseline");
}

void testDacBaselineRollbackConflictOnDirectorySubstitution() {
    const PolicyRef policy{"DAC", "Mode_and_Owner", "systemcommandlock"};
    TempTree tree("/tmp/fic-rollback-dac-XXXXXX");
    const std::filesystem::path managed = tree.root / "managed-dir";
    std::filesystem::create_directories(managed);
    require(::chmod(managed.c_str(), 0750) == 0,
            "could not prepare substituted directory fixture");
    struct stat before {};
    require(::stat(managed.c_str(), &before) == 0,
            "could not stat the substituted directory");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(policy, "systemcommandlock",
                  UndoAction{MutationBackend::Dac,
                             UndoApplyDacPlatformBaseline{
                                 "systemcommandlock"}});

    const RollbackExecutorDeps deps = dacDeps(managed);
    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(report.status == RollbackStatus::Conflict,
            "directory substitution must conflict during rollback: " +
                report.message);
    require(!report.rollbackCompleted(), "conflict must refuse the disable");

    // The unexpected object must remain exactly as it was.
    struct stat after {};
    require(::stat(managed.c_str(), &after) == 0,
            "substituted directory disappeared");
    require(std::filesystem::is_directory(managed),
            "managed object is no longer a directory");
    require((after.st_mode & 07777) == (before.st_mode & 07777),
            "conflicted rollback must not change the directory mode");
    require(after.st_uid == before.st_uid && after.st_gid == before.st_gid,
            "conflicted rollback must not change the directory owner/group");

    // Conflict keeps the provenance active: a later disable retries.
    std::string journalError;
    MutationJournal* journalPtr =
        DaemonMutationJournal::instance().tryGet(journalError);
    require(journalPtr != nullptr, journalError);
    require(!journalPtr->activeRecords(policy).empty(),
            "conflicted rollback must keep the journal record active");
}

// The DAC apply path (journal provenance wrapper) requires initialized FIC
// runtime paths; redirect them into a test-local tree.
void initializeDacRuntimePaths(const std::filesystem::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.defaultConfigDir = root / "share/default-config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";

    std::filesystem::create_directories(paths.configDir);
    std::filesystem::create_directories(paths.logDir);
    std::filesystem::create_directories(paths.dataDir);
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

// The provenance wrapper (ModeAndOwner::applyWithBaselineJournalProvenance)
// must keep its Prepared record after a failed apply that partially mutated
// the system, and the executor must resolve it once the rollback completes.
void testDacWrapperPartialApplyResolvesAfterRollback() {
    const PolicyRef policy{"DAC", "Mode_and_Owner", "systemcommandlock"};
    TempTree tree("/tmp/fic-rollback-dac-partial-XXXXXX");
    // The DAC policy base requires initialized runtime paths from its
    // constructor on.
    initializeDacRuntimePaths(tree.root);
    const std::filesystem::path good = tree.root / "a-managed";
    const std::filesystem::path bad = tree.root / "z-invalid";
    // Lexicographic processing order: the remediable file is remediated
    // before the fail-closed directory substitution fails the apply.
    writeFile(good, "binary");
    require(::chmod(good.c_str(), 0777) == 0,
            "could not prepare the drift fixture");
    std::filesystem::create_directories(bad);

    DacBaselineRollbackOptions options;
    options.platform.protectedSystemCommands = {
        {good, {dacOwner(), dacGroup(), 0750}, {dacOwner(), dacGroup(), 0755}},
        {bad,  {dacOwner(), dacGroup(), 0750}, {dacOwner(), dacGroup(), 0755}}};
    RollbackExecutorDeps deps;
    deps.dacOptions = [options]() { return options; };

    DAC_systemcommandlock policyObject(options.platform);
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");

    // Failed apply with a real partial mutation: Prepared stays active.
    require(!policyObject.apply(), "partial failure must fail apply");
    require(dacFileMode(good) == 0750,
            "the remediable object must be remediated before the failure");
    std::string journalError;
    MutationJournal* journalPtr =
        DaemonMutationJournal::instance().tryGet(journalError);
    require(journalPtr != nullptr, journalError);
    const std::vector<MutationRecord> activeRecords =
        journalPtr->activeRecords(policy);
    require(activeRecords.size() == 1,
            "partial mutation must keep exactly one active record");
    require(activeRecords.front().status == MutationStatus::Prepared,
            "partial mutation provenance must stay Prepared");

    const RollbackReport report =
        rollbackPolicyBeforeDisable(policy, "", deps);
    // The DAC backend undoes the whole record in one pass: object A reaches
    // the baseline while B conflicts, so the aggregated undo outcome is
    // partial and the executor refuses the disable (a per-object Partial
    // outcome of a single record is reported as Failed, not Success).
    require(!report.rollbackCompleted(),
            "rollback with an unfixable object must refuse the disable: " +
                report.message);
    require(dacFileMode(good) == 0755,
            "the mutated object must reach the platform baseline");
    require(!journalPtr->activeRecords(policy).empty(),
            "partial rollback must keep the provenance active");

    // Fix the substituted object: the retry completes and resolves the
    // wrapper's Prepared record.
    std::filesystem::remove(bad);
    writeFile(bad, "binary");
    require(::chmod(bad.c_str(), 0700) == 0,
            "could not fix the substituted object");
    const RollbackReport retry =
        rollbackPolicyBeforeDisable(policy, "", deps);
    require(retry.status == RollbackStatus::Success, retry.message);
    require(retry.rollbackCompleted(),
            "completed rollback must allow the disable");
    require(dacFileMode(bad) == 0755,
            "the fixed object must reach the platform baseline");
    require(journalPtr->activeRecords(policy).empty(),
            "completed rollback must resolve the journal record");
}


void testJournalUpdateFailureFailsClosed() {
    // A successful backend undo with a journal that can no longer be written
    // must still fail closed: provenance must reflect the actual state.
    SysctlTree tree;
    tree.createManagedValue("vm.swappiness", "10");

    TempJournal journal;
    {
        JournalOverride overrideGuard(journal.tree.root / "journal.json");
        recordApplied(kSysctlPolicy, "vm.swappiness", sysctlUndo("10"));
    }
    // Simulate a journal that cannot be updated anymore (broken content).
    const std::filesystem::path journalPath = journal.tree.root / "journal.json";
    writeFile(journalPath, "{ broken");

    JournalOverride overrideGuard(journalPath);
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::Failed,
            "broken journal must fail closed: " + report.message);
    require(!report.rollbackCompleted(),
            "unprovenanced rollback must refuse the disable");
}

void testEmptyJournalWithSysctlHintAndNoManagedOwnership() {
    // No records at all and the resource hint points to a key that is not
    // owned by the FIC managed file: legacy disable must proceed.
    SysctlTree tree;
    writeFile(tree.tree.root / "etc/sysctl.d/10-base.conf",
              "vm.swappiness = 30\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSysctlPolicy, "vm.swappiness", tree.deps());
    require(report.status == RollbackStatus::NothingToDo,
            "resource not owned by FIC must allow legacy disable: " +
                report.message);
    require(report.rollbackCompleted(), "legacy disable must proceed");
}

// ------------------------------------------------------------------ ssh -----

const PolicyRef kSshPolicy{"NET", "SshEdit", "ssh_port"};

ProcessResult sshFailing(const std::string& errorText) {
    ProcessResult result;
    result.started = true;
    result.exitCode = 1;
    result.standardError = errorText;
    return result;
}

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

struct FakeSshCommands {
    ProcessResult sshdT = sshSuccess();
    ProcessResult isActive = sshInactive();
    ProcessResult reload = sshSuccess();
    int reloadCalls = 0;
};

class SshTree {
public:
    SshTree()
        : tree("/tmp/fic-rollback-ssh-XXXXXX"),
          commands_(std::make_shared<FakeSshCommands>()) {
        createExecutable("sshd");
        createExecutable("systemctl");
        fic::platform::PlatformExecutables registry;
        registry.entries = {
            {fic::platform::ExecutableId::Sshd, {tree.root / "sshd"}},
            {fic::platform::ExecutableId::Systemctl, {tree.root / "systemctl"}}};
        fic::platform::PlatformExecutableResolverOptions resolverOptions;
        resolverOptions.enforceTrustedOwnership = false;
        executables_ =
            std::make_unique<fic::platform::PlatformExecutableResolver>(
                std::move(registry), resolverOptions);
    }

    std::filesystem::path configPath() const { return tree.root / "sshd_config"; }

    void writeConfig(const std::string& content) { writeFile(configPath(), content); }

    SshCommandRunner runner() const {
        std::shared_ptr<FakeSshCommands> commands = commands_;
        return [commands](const std::string&,
                          const std::vector<std::string>& arguments,
                          const ProcessOptions&) {
            for (const std::string& argument : arguments) {
                if (argument == "-T") {
                    return commands->sshdT;
                }
                if (argument == "is-active") {
                    return commands->isActive;
                }
                if (argument == "reload") {
                    ++commands->reloadCalls;
                    return commands->reload;
                }
            }
            return commands->isActive;
        };
    }

    SshRollbackOptions options() const {
        SshRollbackOptions value;
        value.configPath = configPath();
        value.includeBasePath = tree.root;
        value.serviceUnits = {"ssh.service", "sshd.service"};
        value.executables = executables_.get();
        value.runner = runner();
        value.beforeRestore = beforeRestore;
        value.beforeWrite = beforeWrite;
        return value;
    }

    RollbackExecutorDeps deps() const {
        RollbackExecutorDeps value;
        SshRollbackOptions options = this->options();
        value.sshOptions = [options]() { return options; };
        return value;
    }

    // Simulates the explicit FIC ownership mutation Ssh::apply performs and
    // returns the undo payload the backend would record in the journal.
    UndoRemoveSshManagedPolicy applyMutation(const std::string& policyName,
                                             const std::string& directive,
                                             const std::string& value) {
        SshConfigFileHandler handler(configPath().string());
        require(handler.loadConfig(), "sshd_config must load");
        std::string error;
        bool changed = false;
        require(upsertSshManagedPolicyBlock(
                    handler.lines(), policyName,
                    sshManagedDirectiveLine(directive, value), changed, error),
                error);
        SshManagedModel model;
        require(parseSshManagedModel(handler.lines(), model, error) ==
                    SshManagedParseStatus::Ok,
                error);
        UndoRemoveSshManagedPolicy undo;
        undo.policyName = policyName;
        undo.directive = directive;
        undo.appliedValue = value;
        if (directive == "Port") {
            std::vector<bool> covered(handler.lines().size(), false);
            if (model.blockPresent) {
                for (std::size_t i = model.blockBegin; i <= model.blockEnd;
                     ++i) {
                    covered[i] = true;
                }
            }
            for (const SshDisabledBlock& disabled : model.disabled) {
                for (std::size_t i = disabled.beginLine;
                     i <= disabled.endLine; ++i) {
                    covered[i] = true;
                }
            }
            int ordinal = 1;
            for (std::size_t i = handler.lines().size(); i-- > 0;) {
                if (covered[i]) {
                    continue;
                }
                const SshLineParseResult parsed =
                    parseSshConfigLine(handler.lines()[i]);
                if (!parsed.ok || !parsed.hasDirective ||
                    normalizeSshKeyword(parsed.directive.keyword) !=
                        normalizeSshKeyword("Port")) {
                    continue;
                }
                const std::string wrapperId =
                    generateSshDisabledMutationId(ordinal++);
                disableSshLine(handler.lines(), i, policyName, wrapperId);
                undo.disabledMutationIds.push_back(wrapperId);
            }
        }
        require(handler.saveFileIfUnchanged(error).installed,
                "sshd_config must save");
        return undo;
    }

    // Records an applied mutation for an arbitrary SSH policy/resource pair
    // (multi-policy scenarios need more than the fixed Port resource).
    MutationId recordMutation(const PolicyRef& policy,
                        const std::string& resource,
                        const UndoRemoveSshManagedPolicy& undo) {
        return recordApplied(policy, resource, UndoAction{MutationBackend::Ssh, undo});
    }

    std::string sshResource(const std::string& parameter) const {
        return "ssh:" + configPath().string() + ":" + parameter;
    }

    std::string sshResource() const {
        return sshResource("Port");
    }

    // Deterministic seams: beforeWrite fires before the conditional atomic
    // write, beforeRestore before the compensation restore.
    std::function<void()> beforeWrite;
    std::function<void()> beforeRestore;

    TempTree tree;
    std::shared_ptr<FakeSshCommands> commands_;

private:
    void createExecutable(const std::string& name) {
        writeFile(tree.root / name, "#!/bin/sh\nexit 0\n");
        std::error_code ignored;
        std::filesystem::permissions(
            tree.root / name,
            std::filesystem::perms::owner_all |
                std::filesystem::perms::group_exec |
                std::filesystem::perms::others_exec,
            ignored);
    }

    std::unique_ptr<fic::platform::PlatformExecutableResolver> executables_;
};
// ------------------------------------------------------------ ssh rollback ----
//
// The rollback backend owns only explicit FIC state: the managed policy
// sub-block (ownership proven by the exact recorded directive line) and the
// FIC_DISABLED wrappers whose mutation ids are listed in the journal payload.

const PolicyRef kSshPortPolicy{"NET", "SshEdit", "ssh_port"};
const PolicyRef kSshRootLoginPolicy{"NET", "SshEdit", "ssh_root_login"};

MutationId recordPrepared(const PolicyRef& policy, const std::string& resource,
                          const UndoAction& undo) {
    MutationId id = 0;
    std::string error;
    require(fic::rollback::recordPreparedMutation(policy, resource, undo, id,
                                                  error),
            error);
    return id;
}

std::string markerLine(const std::string& directive, const std::string& value) {
    return sshManagedDirectiveLine(directive, value);
}

bool fileContains(const std::filesystem::path& path,
                  const std::string& needle) {
    return readFile(path).find(needle) != std::string::npos;
}



void testSshRollbackRemovesScalarManagedBlock() {
    SshTree tree;
    tree.writeConfig("PermitRootLogin prohibit-password\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_root_login", "PermitRootLogin", "no");
    require(undo.disabledMutationIds.empty(),
            "scalar semantics must never disable lines");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshRootLoginPolicy,
                        tree.sshResource("PermitRootLogin"), undo);

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshRootLoginPolicy, "PermitRootLogin", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);
    const std::string content = readFile(tree.configPath());
    require(content.find("PermitRootLogin prohibit-password\n") !=
                    std::string::npos,
            "the user directive must be untouched");
    require(content.find("#@FIC_") == std::string::npos,
            "the FIC policy block must be removed");
}

void testSshRollbackConflictOnManagedBlockDrift() {
    SshTree tree;
    tree.writeConfig("PermitRootLogin prohibit-password\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_root_login", "PermitRootLogin", "no");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshRootLoginPolicy,
                        tree.sshResource("PermitRootLogin"), undo);

    // Manual edit of the FIC-owned block line destroys the ownership proof.
    SshConfigFileHandler drift(tree.configPath().string());
    require(drift.loadConfig(), "drift load must succeed");
    for (std::string& line : drift.lines()) {
        if (line == markerLine("PermitRootLogin", "no")) {
            line = "PermitRootLogin yes";
        }
    }
    std::string error;
    require(drift.saveFileIfUnchanged(error).installed, error);

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshRootLoginPolicy, "PermitRootLogin", tree.deps());
    require(report.status == RollbackStatus::Conflict, report.message);
    require(fileContains(tree.configPath(), "PermitRootLogin yes"),
            "the drifted state must be preserved (fail closed)");
    require(fileContains(tree.configPath(), kSshPolicyBeginPrefix),
            "nothing may be removed on conflict");
}

void testSshRollbackConflictOnUnknownDisabledId() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");
    undo.disabledMutationIds.clear(); // payload "loses" the wrapper id

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"), undo);

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Conflict, report.message);
    require(fileContains(tree.configPath(), kSshDisabledLinePrefix),
            "the unproven disabled block must not be uncommented");
}



void testSshRollbackRemovesManagedBlockAndRestoresDisabled() {
    SshTree tree;
    tree.writeConfig("# user comment\nPort 22\nPort 2022\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");
    require(undo.disabledMutationIds.size() == 2,
            "both user Port lines must be disabled");
    require(fileContains(tree.configPath(), kSshDisabledLinePrefix),
            "the disabled wrapper must be present before rollback");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const MutationId id = tree.recordMutation(
        kSshPortPolicy, tree.sshResource("Port"), undo);

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);
    require(report.rollbackCompleted(), "successful rollback must allow disable");

    const std::string content = readFile(tree.configPath());
    require(content.find("Port 22\n") != std::string::npos &&
                content.find("Port 2022\n") != std::string::npos,
            "the exact user lines must be restored byte-exact");
    require(content.find("#@FIC_") == std::string::npos,
            "no FIC markers of the rolled back policy may remain");
    require(content.find("# user comment\n") != std::string::npos,
            "user content must be preserved");

    MutationJournal stored(journal.tree.root / "journal.json");
    std::string error;
    require(stored.load(error), error);
    require(stored.records().size() == 1 &&
                stored.records().front().id == id &&
                stored.records().front().status == MutationStatus::RolledBack,
            "rollback must be persisted as rolled_back");
}

void testSshRollbackValidationFailureRestoresPreRollbackState() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"), undo);

    const std::string rollbackInput = readFile(tree.configPath());
    tree.commands_->sshdT = sshFailing("sshd -t failed");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Failed, report.message);
    require(readFile(tree.configPath()) == rollbackInput,
            "compensation must restore the exact pre-rollback content");
    require(fileContains(tree.configPath(), kSshDisabledLinePrefix),
            "the FIC-owned state must be intact after compensation");
}

void testSshRollbackReloadFailureRestoresPreRollbackState() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"), undo);

    const std::string rollbackInput = readFile(tree.configPath());
    tree.commands_->isActive = sshSuccess();
    tree.commands_->reload = sshFailing("sshd -t failed");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Failed, report.message);
    require(readFile(tree.configPath()) == rollbackInput,
            "reload failure must trigger the compensation restore");
}

void testSshRollbackMalformedMarkersFailClosed() {
    SshTree tree;
    tree.writeConfig("Port 22\nMatch User admin\n#@FIC_POLICY_BEGIN x\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"),
                        UndoRemoveSshManagedPolicy{"ssh_port", "Port",
                                                   "2222", {}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    // Malformed FIC markers are a drifted FIC ownership state: the rollback
    // reports a conflict (manual resolution required), not a transient
    // failure, and never rewrites the file.
    require(report.status == RollbackStatus::Conflict, report.message);
    require(fileContains(tree.configPath(), "Match User admin"),
            "the malformed file must not be rewritten");
}

void testSshRollbackKeepsOtherPolicyState() {
    SshTree tree;
    tree.writeConfig("Port 22\nPermitRootLogin prohibit-password\n");
    const UndoRemoveSshManagedPolicy portUndo =
        tree.applyMutation("ssh_port", "Port", "2222");
    const UndoRemoveSshManagedPolicy rootUndo =
        tree.applyMutation("ssh_root_login", "PermitRootLogin", "no");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"), portUndo);
    tree.recordMutation(kSshRootLoginPolicy,
                        tree.sshResource("PermitRootLogin"), rootUndo);

    const RollbackReport portReport = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(portReport.status == RollbackStatus::Success,
            portReport.message);
    require(fileContains(tree.configPath(), kSshPolicyBeginPrefix),
            "the other policy block must survive");
    require(fileContains(tree.configPath(),
                         markerLine("PermitRootLogin", "no")),
            "the other policy directive must survive");
    require(!fileContains(tree.configPath(), kSshDisabledLinePrefix),
            "the rolled back policy wrappers must be restored");

    const RollbackReport rootReport = rollbackPolicyBeforeDisable(
        kSshRootLoginPolicy, "PermitRootLogin", tree.deps());
    require(rootReport.status == RollbackStatus::Success, rootReport.message);
    require(readFile(tree.configPath()).find("#@FIC_") == std::string::npos,
            "both policies rolled back: no FIC markers remain");
}

void testSshRollbackNothingToDoAfterCrash() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    tree.commands_->isActive = sshSuccess();

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    // Crash scenario: the journal record exists, but the file state was
    // already factually rolled back (no FIC markers at all).
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"),
                        UndoRemoveSshManagedPolicy{"ssh_port", "Port",
                                                   "2222", {}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::NothingToDo, report.message);
    require(report.rollbackCompleted(), "nothing-to-do must allow disable");
    require(tree.commands_->reloadCalls > 0,
            "runtime reconciliation must reload the active service");
    require(readFile(tree.configPath()) == "Port 22\n",
            "nothing may be written");
}

void testSshRollbackNothingToDoReloadFailureRefusesDisable() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    tree.commands_->isActive = sshSuccess();
    tree.commands_->reload = sshFailing("sshd -t failed");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"),
                        UndoRemoveSshManagedPolicy{"ssh_port", "Port",
                                                   "2222", {}});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Failed, report.message);
    require(!report.rollbackCompleted(),
            "unconfirmed runtime reconciliation must refuse the disable");
}

void testSshRepeatedDisableIsIdempotent() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"), undo);

    const RollbackReport first = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(first.status == RollbackStatus::Success, first.message);

    // A retry must not guess anything: no markers, no ownership, no writes.
    const RollbackReport second = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(second.status == RollbackStatus::NothingToDo, second.message);
    require(readFile(tree.configPath()).find("#@FIC_") == std::string::npos,
            "the retried rollback must not write anything");
}

void testSshProvenanceRefusedWhenMarkersPresentWithoutRecords() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    (void)tree.applyMutation("ssh_port", "Port", "2222");
    // No journal records at all: the markers cannot be attributed.
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Unsupported,
            "unrecorded FIC markers must fail closed");
    require(fileContains(tree.configPath(), kSshPolicyBeginPrefix),
            "nothing may be removed without provenance");
}

void testSshNoRecordsNoMarkersIsNothingToDo() {
    SshTree tree;
    tree.writeConfig("Port 22\n");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::NothingToDo, report.message);
    require(readFile(tree.configPath()) == "Port 22\n",
            "a foreign configuration must not be touched");
}

void testSshPreparedRecordResolvedByDisable() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    // Crash after prepare, before commit: the record stays Prepared while
    // the file already carries the FIC-owned state.
    recordPrepared(kSshPortPolicy, tree.sshResource("Port"),
                   UndoAction{MutationBackend::Ssh, undo});

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Success, report.message);
    require(readFile(tree.configPath()).find("#@FIC_") == std::string::npos,
            "the prepared mutation must be rolled back");
}

void testSshRollbackCompensationRacePreservesExternalEdit() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"), undo);

    const std::string rollbackInput = readFile(tree.configPath());
    // External edit racing with the compensation restore: the restore must
    // refuse to overwrite the foreign state.
    tree.commands_->sshdT = sshFailing("sshd -t failed");
    tree.beforeRestore = [&tree]() {
        SshConfigFileHandler external(tree.configPath().string());
        require(external.loadConfig(), "external load must succeed");
        external.lines().push_back("# external concurrent edit");
        std::string error;
        require(external.saveFileIfUnchanged(error).installed, error);
    };

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Failed, report.message);
    require(fileContains(tree.configPath(), "# external concurrent edit"),
            "the external edit must be preserved");
    require(readFile(tree.configPath()) == rollbackInput ||
                !fileContains(tree.configPath(), kSshDisabledBeginPrefix),
            "either the compensation succeeded exactly or it was refused");
}

void testSshRollbackRefusedOnConcurrentModification() {
    SshTree tree;
    tree.writeConfig("Port 22\n");
    const UndoRemoveSshManagedPolicy undo =
        tree.applyMutation("ssh_port", "Port", "2222");

    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    tree.recordMutation(kSshPortPolicy, tree.sshResource("Port"), undo);

    // Concurrent external modification between snapshot and write: the
    // conditional write must refuse and nothing may be changed.
    tree.beforeWrite = [&tree]() {
        SshConfigFileHandler external(tree.configPath().string());
        require(external.loadConfig(), "external load must succeed");
        external.lines().push_back("# external concurrent edit");
        std::string error;
        require(external.saveFileIfUnchanged(error).installed, error);
    };

    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSshPortPolicy, "Port", tree.deps());
    require(report.status == RollbackStatus::Conflict ||
                report.status == RollbackStatus::Failed,
            report.message);
    require(fileContains(tree.configPath(), "# external concurrent edit"),
            "the external edit must be preserved");
    require(fileContains(tree.configPath(), kSshDisabledLinePrefix),
            "the FIC-owned state must be intact");
}

} // namespace

// An Indeterminate journal must fail the rollback closed BEFORE any backend
// runs: read-based ownership decisions (including "no active records →
// NothingToDo") must never be made on ambiguous provenance.
void testIndeterminateJournalFailsRollbackClosed() {
    TempJournal file;
    JournalOverride overrideGuard(file.tree.root / "journal.json");

    std::string error;
    MutationId id = 0;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    require(recordPreparedMutation(
                PolicyRef{"NET", "SshEdit", "ssh_port"},
                "ssh:/etc/ssh/sshd_config:Port",
                UndoAction{MutationBackend::Ssh, undo}, id, error),
            error);

    // Poison the open singleton journal: the post-rename durability of the
    // journal update cannot be confirmed.
    const std::string journalPath = (file.tree.root / "journal.json").string();
    auto remaining = std::make_shared<int>(1000);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [journalPath, remaining](const std::string& targetPath) {
            if (targetPath != journalPath) {
                return true;
            }
            if (*remaining > 0) {
                --*remaining;
                return false;
            }
            return true;
        });
    struct HookReset {
        ~HookReset() { AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr); }
    } hookReset;

    std::string poisonError;
    require(!journal->setStatus(id, MutationStatus::Applied, poisonError),
            poisonError);
    require(journal->health() == JournalHealth::Indeterminate, poisonError);

    // The rollback executor must refuse the journal-backed decision instead
    // of consulting the ambiguous in-memory state (which no longer contains
    // an active record the executor could reason about).
    const RollbackExecutorDeps deps;
    const RollbackReport report = rollbackPolicyBeforeDisable(
        PolicyRef{"NET", "SshEdit", "ssh_port"}, "Port", deps);
    require(report.status == RollbackStatus::Failed, report.message);
    require(report.message.find("Indeterminate") != std::string::npos,
            report.message);
    require(report.status != RollbackStatus::NothingToDo &&
                report.status != RollbackStatus::Success,
            report.message);
}

// Same poisoning scenario as above, but the journal file additionally
// disappears before the rollback: the lazy recovery must not heal the
// Indeterminate singleton into an empty Healthy journal, and the executor
// must not run any backend (especially not resolve the inactive in-memory
// record into NothingToDo) on vanished provenance.
void testIndeterminateMissingJournalFailsRollbackClosed() {
    TempJournal file;
    const std::filesystem::path journalPath = file.tree.root / "journal.json";
    JournalOverride overrideGuard(journalPath);

    std::string error;
    MutationId id = 0;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);

    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
    require(recordPreparedMutation(
                PolicyRef{"NET", "SshEdit", "ssh_port"},
                "ssh:/etc/ssh/sshd_config:Port",
                UndoAction{MutationBackend::Ssh, undo}, id, error),
            error);

    // Poison: rename succeeds, journal durability cannot be confirmed.
    const std::string journalPathStr = journalPath.string();
    auto remaining = std::make_shared<int>(1000);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [journalPathStr, remaining](const std::string& targetPath) {
            if (targetPath != journalPathStr) {
                return true;
            }
            if (*remaining > 0) {
                --*remaining;
                return false;
            }
            return true;
        });
    {
        std::string poisonError;
        require(!journal->setStatus(id, MutationStatus::Applied, poisonError),
                poisonError);
        require(journal->health() == JournalHealth::Indeterminate, poisonError);
    }
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);

    // The journal file disappears externally.
    std::error_code ec;
    require(std::filesystem::remove(journalPath, ec), ec.message());

    const RollbackExecutorDeps deps;
    const RollbackReport report = rollbackPolicyBeforeDisable(
        PolicyRef{"NET", "SshEdit", "ssh_port"}, "Port", deps);
    require(report.status == RollbackStatus::Failed, report.message);
    require(report.status != RollbackStatus::NothingToDo &&
                report.status != RollbackStatus::Success,
            report.message);
    // With the persistent initialization witness present, a fresh object over
    // the now-missing path fails closed too (provenance loss, not a virgin
    // bootstrap); the poisoned live singleton must have stayed unusable.
    require(journal->health() == JournalHealth::Indeterminate, report.message);
    require(!journal->usable(), report.message);
    require(!journal->records().empty(),
            "the inactive in-memory record must be preserved for diagnostics");
}

void testProvenanceLossAfterRestartFailsRollbackClosed() {
    TempJournal file;
    const std::filesystem::path journalPath = file.tree.root / "journal.json";
    const PolicyRef policy{"NET", "SshEdit", "ssh_port"};

    // Bootstrap with a real committed SSH provenance record.
    {
        JournalOverride overrideGuard(journalPath);
        std::string error;
        MutationId id = 0;
    UndoRemoveSshManagedPolicy undo;
    undo.policyName = "ssh_port";
    undo.directive = "Port";
    undo.appliedValue = "2222";
        require(recordPreparedMutation(policy,
                                       "ssh:/etc/ssh/sshd_config:Port",
                                       UndoAction{MutationBackend::Ssh, undo},
                                       id, error),
                error);
        require(commitMutation(id, error), error);
        require(std::filesystem::exists(journalPath), "journal must exist");
        require(std::filesystem::exists(journalPath.string() +
                                        ".initialized"),
                "the bootstrap must create the witness");
    }

    // Journal deletion + daemon restart (fresh singleton state, fresh
    // journal object): the witness alone proves the lifecycle was
    // initialized, so provenance is lost.
    std::error_code ec;
    require(std::filesystem::remove(journalPath, ec), ec.message());
    JournalOverride overrideGuard(journalPath);

    const RollbackExecutorDeps deps;
    const RollbackReport report = rollbackPolicyBeforeDisable(
        policy, "Port", deps);
    require(report.status == RollbackStatus::Failed,
            "provenance loss must fail rollback closed after a restart: " +
                report.message);
    require(report.status != RollbackStatus::NothingToDo &&
                report.status != RollbackStatus::Success,
            report.message);

    // A new baseline can no longer be recorded either.
    std::string error;
    MutationId newId = 0;
    UndoRemoveSshManagedPolicy freshUndo;
    freshUndo.policyName = "ssh_port";
    freshUndo.directive = "Port";
    freshUndo.appliedValue = "22";
    require(!recordPreparedMutation(policy, "ssh:/etc/ssh/sshd_config:Port",
                                    UndoAction{MutationBackend::Ssh, freshUndo},
                                    newId, error),
            "a new baseline must be impossible after provenance loss");
    require(error.find("provenance may have been lost") != std::string::npos,
            error);
}

// ----------------------------------------------------- sssd / kerberos ------

const PolicyRef kSssdPolicy{
    "IDENTITY_ACCESS", "SSSD", "sssd_offline_credentials_expiration"};
const PolicyRef kKerberosPolicy{
    "IDENTITY_ACCESS", "KERBEROS", "kerberos_ticket_lifetime"};

class IdentityConfigTree {
public:
    IdentityConfigTree()
        : tree("/tmp/fic-rollback-identity-XXXXXX") {
        std::filesystem::create_directories(sssdConfd());
        std::filesystem::create_directories(tree.root / "bin");
        writeFile(tree.root / "bin/systemctl", "test executable\n");
        ::chmod((tree.root / "bin/systemctl").c_str(), 0755);
    }

    std::filesystem::path sssdMain() const {
        return tree.root / "etc/sssd/sssd.conf";
    }
    std::filesystem::path sssdConfd() const {
        return tree.root / "etc/sssd/conf.d";
    }
    std::filesystem::path sssdDropIn() const {
        return sssdConfd() / "zzzz-fic.conf";
    }
    std::filesystem::path krb5Main() const {
        return tree.root / "etc/krb5.conf";
    }

    const fic::platform::PlatformExecutableResolver& resolver() const {
        if (!resolver_) {
            fic::platform::PlatformExecutables executables;
            executables.entries.push_back(
                {fic::platform::ExecutableId::Systemctl,
                 {tree.root / "bin/systemctl"}});
            fic::platform::PlatformExecutableResolverOptions options;
            options.enforceTrustedOwnership = false;
            resolver_ = std::make_unique<fic::platform::PlatformExecutableResolver>(
                std::move(executables), options);
        }
        return *resolver_;
    }

    SssdRollbackOptions sssdOptions() const {
        SssdRollbackOptions options;
        options.configuration.mainFile.path = sssdMain();
        options.configuration.mainFile.expectedOwner = ::geteuid();
        options.configuration.mainFile.expectedGroup = ::getegid();
        options.configuration.mainFile.exactMode = 0600;
        options.configuration.mainFile.forbiddenMode = 0022;
        options.configuration.snippetDirectories = {sssdConfd()};
        options.configuration.managedSnippetFile = sssdDropIn();
        options.executables = &resolver();
        options.runner = [](const std::string&,
                            const std::vector<std::string>&,
                            const ProcessOptions&) {
            ProcessResult result;
            result.started = true;
            result.exitCode = 0;
            return result;
        };
        return options;
    }

    KerberosRollbackOptions kerberosOptions() const {
        KerberosRollbackOptions options;
        options.configuration.mainFile.path = krb5Main();
        options.configuration.mainFile.expectedOwner = ::geteuid();
        options.configuration.mainFile.expectedGroup = ::getegid();
        options.configuration.mainFile.forbiddenMode = 0022;
        return options;
    }

    RollbackExecutorDeps sssdDeps() const {
        RollbackExecutorDeps deps;
        SssdRollbackOptions options = sssdOptions();
        deps.sssdOptions = [options]() { return options; };
        return deps;
    }

    RollbackExecutorDeps kerberosDeps() const {
        RollbackExecutorDeps deps;
        KerberosRollbackOptions options = kerberosOptions();
        deps.kerberosOptions = [options]() { return options; };
        return deps;
    }

    TempTree tree;
    mutable std::unique_ptr<fic::platform::PlatformExecutableResolver> resolver_;
};

void testSssdExecutorRollbackRemovesManagedSetting() {
    IdentityConfigTree env;
    writeFile(env.sssdMain(), "[pam]\noffline_credentials_expiration = 7\n");
    ::chmod(env.sssdMain().c_str(), 0600);
    writeFile(env.sssdDropIn(),
              "# FIC managed configuration\n[pam]\n"
              "offline_credentials_expiration = 30\n");
    ::chmod(env.sssdDropIn().c_str(), 0600);
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kSssdPolicy, "pam/offline_credentials_expiration",
                  UndoAction{MutationBackend::Sssd,
                             UndoRemoveSssdManagedSetting{
                                 "pam", "offline_credentials_expiration",
                                 "30"}});
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSssdPolicy, "pam/offline_credentials_expiration", env.sssdDeps());
    require(report.status == RollbackStatus::Success,
            "sssd executor rollback must succeed: " + report.message);
    require(!std::filesystem::exists(env.sssdDropIn()),
            "the semantically empty FIC drop-in must be removed");
    require(readFile(env.sssdMain()) ==
                "[pam]\noffline_credentials_expiration = 7\n",
            "the foreign sssd.conf must remain byte-for-byte unchanged");
}

void testSssdExecutorDriftConflictRefusesDisable() {
    IdentityConfigTree env;
    writeFile(env.sssdMain(), "[pam]\noffline_credentials_expiration = 7\n");
    ::chmod(env.sssdMain().c_str(), 0600);
    writeFile(env.sssdDropIn(),
              "# FIC managed configuration\n[pam]\n"
              "offline_credentials_expiration = 40\n");
    ::chmod(env.sssdDropIn().c_str(), 0600);
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kSssdPolicy, "pam/offline_credentials_expiration",
                  UndoAction{MutationBackend::Sssd,
                             UndoRemoveSssdManagedSetting{
                                 "pam", "offline_credentials_expiration",
                                 "30"}});
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kSssdPolicy, "pam/offline_credentials_expiration", env.sssdDeps());
    require(report.status == RollbackStatus::Conflict,
            "sssd executor drift must Conflict");
    require(!report.rollbackCompleted(),
            "a Conflict must refuse the policy disable");
    require(readFile(env.sssdDropIn()).find(
                "offline_credentials_expiration = 40") !=
                std::string::npos,
            "the drifted drop-in must never be overwritten");
}

void testKerberosExecutorRollbackRestoresExactLine() {
    IdentityConfigTree env;
    writeFile(env.krb5Main(), "[libdefaults]\n    ticket_lifetime = 36000s\n");
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kKerberosPolicy, "libdefaults/ticket_lifetime",
                  UndoAction{MutationBackend::Kerberos,
                             UndoRestoreKerberosScalar{
                                 "libdefaults", "ticket_lifetime", "36000s",
                                 KerberosBeforeKind::Present,
                                 "    ticket_lifetime = 8h", true}});
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kKerberosPolicy, "libdefaults/ticket_lifetime", env.kerberosDeps());
    require(report.status == RollbackStatus::Success,
            "kerberos executor rollback must succeed: " + report.message);
    require(readFile(env.krb5Main()) ==
                "[libdefaults]\n    ticket_lifetime = 8h\n",
            "the exact original raw line must be restored");
}

void testKerberosExecutorDriftConflictRefusesDisable() {
    IdentityConfigTree env;
    writeFile(env.krb5Main(), "[libdefaults]\nticket_lifetime = 2h\n");
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    recordApplied(kKerberosPolicy, "libdefaults/ticket_lifetime",
                  UndoAction{MutationBackend::Kerberos,
                             UndoRestoreKerberosScalar{
                                 "libdefaults", "ticket_lifetime", "36000s",
                                 KerberosBeforeKind::Present,
                                 "ticket_lifetime = 8h", true}});
    const RollbackReport report = rollbackPolicyBeforeDisable(
        kKerberosPolicy, "libdefaults/ticket_lifetime", env.kerberosDeps());
    require(report.status == RollbackStatus::Conflict,
            "kerberos executor drift must Conflict");
    require(!report.rollbackCompleted(),
            "a Conflict must refuse the policy disable");
    require(readFile(env.krb5Main()) ==
                "[libdefaults]\nticket_lifetime = 2h\n",
            "the administrator value must be preserved");
}

int main() {
    const struct {
        const char* name;
        void (*test)();
    } tests[] = {
        {"enrollment matrix", testEnrollmentMatrix},
        {"PAM ownership release", testPamOwnershipRelease},
        {"PAM executor journal lifecycle", testPamExecutorJournalLifecycle},
        {"sssd executor rollback removes managed setting",
         testSssdExecutorRollbackRemovesManagedSetting},
        {"sssd executor drift conflict refuses disable",
         testSssdExecutorDriftConflictRefusesDisable},
        {"kerberos executor rollback restores exact line",
         testKerberosExecutorRollbackRestoresExactLine},
        {"kerberos executor drift conflict refuses disable",
         testKerberosExecutorDriftConflictRefusesDisable},
        {"not enrolled policy keeps legacy disable", testNotEnrolledPolicyKeepsLegacyDisable},
        {"unsupported policy refuses disable", testUnsupportedPolicyRefusesDisable},
        {"sysctl rollback removes managed key and moves runtime",
         testSysctlRollbackRemovesManagedKeyAndMovesRuntime},
        {"sysctl rollback conflict on drift", testSysctlRollbackConflictOnDrift},
        {"sysctl rollback removes shadowed managed entry",
         testSysctlRollbackRemovesShadowedManagedEntry},
        {"sysctl provenance unavailable without journal",
         testSysctlProvenanceUnavailableWithoutJournal},
        {"sysctl legacy provenance refused when shadowed",
         testSysctlLegacyProvenanceRefusedWhenShadowed},
        {"sysctl no records and not owned is nothing to do",
         testSysctlNoRecordsAndNotOwnedIsNothingToDo},
        {"sudo rollback removes managed default", testSudoRollbackRemovesManagedDefault},
        {"sudo rollback conflict on drift", testSudoRollbackConflictOnDrift},
        {"sudo rollback missing managed entry is nothing to do",
         testSudoRollbackMissingManagedEntryIsNothingToDo},
        {"sudo rollback removes shadowed managed entry",
         testSudoRollbackRemovesShadowedManagedEntry},
        {"sudo legacy provenance refused when shadowed",
         testSudoLegacyProvenanceRefusedWhenShadowed},
        {"sudo rollback visudo failure fails closed",
         testSudoRollbackVisudoFailureFailsClosed},
        {"sudo repeated disable is idempotent", testSudoRepeatedDisableIsIdempotent},
        {"sysctl rollback keeps other policy setting",
         testSysctlRollbackKeepsOtherPolicySetting},
        {"sysctl rollback retry is idempotent", testSysctlRollbackRetryIsIdempotent},
        {"sysctl repeated apply repairs drift then rollback",
         testSysctlRepeatedApplyRepairsDriftThenRollback},
        {"executor resolves prepared record after failed commit",
         testExecutorResolvesPreparedRecordAfterFailedCommit},
        {"sudo rollback keeps other managed default",
         testSudoRollbackKeepsOtherManagedDefault},
        {"firewall undo invokes backend", testFirewallUndoInvokesBackend},
        {"firewall undo failure fails closed", testFirewallUndoFailureFailsClosed},
        {"ssh rollback removes managed block and restores disabled lines",
         testSshRollbackRemovesManagedBlockAndRestoresDisabled},
        {"ssh rollback removes scalar managed block",
         testSshRollbackRemovesScalarManagedBlock},
        {"ssh rollback conflict on managed block drift",
         testSshRollbackConflictOnManagedBlockDrift},
        {"ssh rollback conflict on unknown disabled id",
         testSshRollbackConflictOnUnknownDisabledId},
        {"ssh rollback keeps other policy state",
         testSshRollbackKeepsOtherPolicyState},
        {"ssh rollback malformed markers fail closed",
         testSshRollbackMalformedMarkersFailClosed},
        {"ssh rollback validation failure restores pre-rollback state",
         testSshRollbackValidationFailureRestoresPreRollbackState},
        {"ssh rollback reload failure restores pre-rollback state",
         testSshRollbackReloadFailureRestoresPreRollbackState},
        {"ssh rollback nothing to do after crash",
         testSshRollbackNothingToDoAfterCrash},
        {"ssh rollback nothing-to-do reload failure refuses disable",
         testSshRollbackNothingToDoReloadFailureRefusesDisable},
        {"ssh prepared record resolved by disable", testSshPreparedRecordResolvedByDisable},
        {"ssh repeated disable is idempotent", testSshRepeatedDisableIsIdempotent},
        {"ssh provenance refused when markers present without records",
         testSshProvenanceRefusedWhenMarkersPresentWithoutRecords},
        {"ssh no records and no markers is nothing to do",
         testSshNoRecordsNoMarkersIsNothingToDo},
        {"ssh rollback compensation race preserves external edit",
         testSshRollbackCompensationRacePreservesExternalEdit},
        {"ssh rollback refused on concurrent modification",
         testSshRollbackRefusedOnConcurrentModification},
        {"device feature undo invokes backend", testDeviceFeatureUndoInvokesBackend},
        {"device feature undo unknown feature is unsupported",
         testDeviceFeatureUndoUnknownFeatureIsUnsupported},
        {"dac baseline rollback transitions to baseline",
         testDacBaselineRollbackTransitionsToBaseline},
        {"dac baseline rollback is idempotent",
         testDacBaselineRollbackIsIdempotent},
        {"dac unrecorded legacy provenance rolls back enforced state",
         testDacUnrecordedLegacyProvenanceRollsBackEnforcedState},
        {"dac unrecorded foreign state refuses disable",
         testDacUnrecordedForeignStateRefusesDisable},
        {"dac unrecorded at baseline is nothing to do",
         testDacUnrecordedAtBaselineIsNothingToDo},
        {"dac blocking policy rollback uses profile baseline",
         testDacBlockingPolicyRollbackUsesProfileBaseline},
        {"dac baseline rollback conflicts on directory substitution",
         testDacBaselineRollbackConflictOnDirectorySubstitution},
        {"dac wrapper partial apply resolves after rollback",
         testDacWrapperPartialApplyResolvesAfterRollback},
        {"journal update failure fails closed", testJournalUpdateFailureFailsClosed},
        {"empty journal with sysctl hint and no managed ownership",
         testEmptyJournalWithSysctlHintAndNoManagedOwnership},
        {"indeterminate journal fails rollback closed",
         testIndeterminateJournalFailsRollbackClosed},
        {"indeterminate missing journal fails rollback closed",
         testIndeterminateMissingJournalFailsRollbackClosed},
        {"provenance loss after restart fails rollback closed",
         testProvenanceLossAfterRestartFailsRollbackClosed},
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
