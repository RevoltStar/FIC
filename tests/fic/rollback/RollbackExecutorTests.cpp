#include "rollback/DaemonMutationJournal.h"
#include "rollback/RollbackExecutor.h"

#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/sysctl/SysctlConfiguration.h"
#include "modules/sysctl/SysctlRuntime.h"

#include <filesystem>
#include <fstream>
#include <iostream>
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
    require(rollbackEnrollment({"OSS", "Grub", "grub_timeout"}) ==
                RollbackEnrollment::NotEnrolled,
            "modules outside the rollback system keep legacy disable behavior");
}

void testNotEnrolledPolicyKeepsLegacyDisable() {
    TempJournal journal;
    JournalOverride overrideGuard(journal.tree.root / "journal.json");
    const RollbackReport report = rollbackPolicyBeforeDisable(
        {"OSS", "Grub", "grub_timeout"}, "", RollbackExecutorDeps{});
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

} // namespace

int main() {
    const struct {
        const char* name;
        void (*test)();
    } tests[] = {
        {"enrollment matrix", testEnrollmentMatrix},
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
        {"device feature undo invokes backend", testDeviceFeatureUndoInvokesBackend},
        {"device feature undo unknown feature is unsupported",
         testDeviceFeatureUndoUnknownFeatureIsUnsupported},
        {"journal update failure fails closed", testJournalUpdateFailureFailsClosed},
        {"empty journal with sysctl hint and no managed ownership",
         testEmptyJournalWithSysctlHintAndNoManagedOwnership}
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

