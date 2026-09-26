// Production wiring tests: configuration intent -> PamPasswordTopology
// Coordinator -> C2 transition executor -> MutationJournal -> Rollback.
// Deterministic fake native pam-auth-update mutator + fake /etc/pam.d and
// /var/lib/pam trees; the rollback path goes through the REAL
// RollbackExecutor dispatch (rollbackPolicyBeforeDisable -> undoPamCapability
// -> joint C2 transition), exactly as the daemon wires it.
#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "modules/identity_access/pam/PamPasswordTopologyCoordinator.h"
#include "modules/identity_access/pam/PamPasswordTopologyState.h"
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/policies/PamCapabilityActivationPolicy.h"
#include "platform/PlatformProfile.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/RollbackExecutor.h"

#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

using fic::identity::pam::kFicPasswordHistoryHookProfileId;
using fic::identity::pam::kFicPasswordHistoryInitialHookProfileId;
using fic::identity::pam::kFicPasswordQualityHookProfileId;
using fic::identity::pam::kStockPwqualityProfileId;
using fic::identity::pam::ManagedPasswordSlotState;
using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamPasswordRequestedState;
using fic::identity::pam::PamPasswordStateInspectionOptions;
using fic::identity::pam::PamPasswordTopologyClass;
using fic::identity::pam::PamPasswordTopologyCoordinator;
using fic::identity::pam::PamPasswordTopologyExecutorOptions;
using fic::identity::pam::PamPasswordTopologySnapshot;
using fic::identity::pam::PamPasswordTransitionResult;
using fic::identity::pam::PamManagedPasswordSlots;
using fic::rollback::MutationJournal;
using fic::rollback::MutationStatus;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto base = std::filesystem::temp_directory_path();
        root_ = base / ("fic-pam-wiring-test-" +
                        std::to_string(::getpid()) + "-" +
                        std::to_string(counter++));
        std::filesystem::create_directories(root_);
    }
    ~TemporaryDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
    }
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    const std::filesystem::path& path() const { return root_; }
    std::filesystem::path pamd() const { return root_ / "pam.d"; }
    std::filesystem::path state() const { return root_ / "state"; }
    std::filesystem::path conf() const { return root_ / "conf"; }

private:
    static int counter;
    std::filesystem::path root_;
};

int TemporaryDirectory::counter = 0;

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(stream)),
                        std::istreambuf_iterator<char>());
    return content;
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << content;
    require(stream.good(), "test failed to write " + path.string());
}

// Deterministic fake native pam-auth-update mutator (same semantics as the
// executor test harness): "Module:" records in the password state database
// and generated include lines (with the real trailing-whitespace quirk) in
// common-password, ONE profile per invocation.
struct FakeNativeMutator {
    struct Invocation {
        std::string flag;
        std::string profileId;
    };

    TemporaryDirectory& tree;
    std::vector<Invocation> invocations;
    // Scripted exit code by invocation number (1-based); 0 applies.
    std::function<int(std::size_t, const Invocation&)> behavior;

    explicit FakeNativeMutator(TemporaryDirectory& tree) : tree(tree) {}

    ProcessResult run(const std::string& /*executable*/,
                      const std::vector<std::string>& arguments,
                      const ProcessOptions& /*options*/) {
        require(arguments.size() == 2,
                "fake mutator: exactly ONE profile per pam-auth-update "
                "invocation is required");
        require(arguments[0] == "--enable" || arguments[0] == "--disable",
                "fake mutator: unexpected pam-auth-update flag " +
                    arguments[0]);
        const Invocation invocation{arguments[0], arguments[1]};
        invocations.push_back(invocation);
        int exitCode = 0;
        if (behavior) {
            exitCode = behavior(invocations.size(), invocation);
        }
        if (exitCode == 0) {
            apply(invocation);
        }
        ProcessResult result;
        result.started = true;
        result.exitCode = exitCode;
        return result;
    }

    bool isSelected(const std::string& profileId) const {
        std::istringstream stream(readFile(stateFile()));
        std::string line;
        while (std::getline(stream, line)) {
            const std::string prefix = "Module: ";
            if (line.compare(0, prefix.size(), prefix) == 0 &&
                line.substr(prefix.size()) == profileId) {
                return true;
            }
        }
        return false;
    }

    std::filesystem::path stateFile() const {
        return tree.state() / "password";
    }

    void forceSelect(const std::string& profileId) {
        std::vector<std::string> selected = readSelected();
        bool found = false;
        for (const std::string& profile : selected) {
            if (profile == profileId) {
                found = true;
                break;
            }
        }
        if (!found) {
            selected.push_back(profileId);
        }
        writeSelected(selected);
    }

private:
    std::vector<std::string> readSelected() const {
        std::vector<std::string> selected;
        std::istringstream stream(readFile(stateFile()));
        std::string line;
        const std::string prefix = "Module: ";
        while (std::getline(stream, line)) {
            if (line.compare(0, prefix.size(), prefix) == 0) {
                selected.push_back(line.substr(prefix.size()));
            }
        }
        return selected;
    }

    void writeSelected(const std::vector<std::string>& selected) {
        std::string stateContent;
        for (const std::string& profile : selected) {
            stateContent += "Module: " + profile + "\n";
        }
        writeFile(stateFile(), stateContent);
        regenerateStack(selected);
    }

    void apply(const Invocation& invocation) {
        std::vector<std::string> selected = readSelected();
        bool changed = false;
        if (invocation.flag == "--disable") {
            for (std::size_t index = 0; index < selected.size();) {
                if (selected[index] == invocation.profileId) {
                    selected.erase(selected.begin() + index);
                    changed = true;
                } else {
                    ++index;
                }
            }
        } else {
            bool found = false;
            for (const std::string& profile : selected) {
                if (profile == invocation.profileId) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                selected.push_back(invocation.profileId);
                changed = true;
            }
        }
        if (changed) {
            writeSelected(selected);
        }
    }

    void regenerateStack(const std::vector<std::string>& selected) {
        bool quality = false;
        bool consumer = false;
        bool initial = false;
        for (const std::string& profile : selected) {
            if (profile == kFicPasswordQualityHookProfileId) {
                quality = true;
            } else if (profile == kFicPasswordHistoryHookProfileId) {
                consumer = true;
            } else if (profile == kFicPasswordHistoryInitialHookProfileId) {
                initial = true;
            }
        }
        std::string stack;
        if (isSelected(kStockPwqualityProfileId)) {
            stack += "password requisite pam_pwquality.so retry=3 \n";
        }
        if (quality) {
            stack += "password include fic-password-quality \n";
        }
        if (consumer) {
            stack += "password include fic-password-history \n";
        }
        if (initial) {
            stack += "password include fic-password-history-initial \n";
        }
        stack +=
            "password required pam_unix.so obscure use_authtok "
            "try_first_pass yescrypt \n";
        writeFile(tree.pamd() / "common-password", stack);
    }
};

// Full wiring environment: pam.d tree, state directory, IDENTITY_ACCESS
// configuration intent, daemon mutation journal (override path) and the
// production coordinator shape over the fake native mutator.
struct WiringEnvironment {
    TemporaryDirectory tree;
    FakeNativeMutator mutator{tree};
    fic::platform::PlatformExecutableResolver resolver{
        fic::platform::PlatformExecutables{}};
    std::unique_ptr<PamPasswordTopologyCoordinator> coordinator;

    WiringEnvironment() {
        std::filesystem::create_directories(tree.pamd());
        std::filesystem::create_directories(tree.state());
        std::filesystem::create_directories(tree.conf());
        for (const auto& spec : PamManagedPasswordSlots::slots()) {
            writeFile(tree.pamd() / spec.fileName,
                PamManagedPasswordSlots::renderNeutral(spec));
        }
        writeFile(mutator.stateFile(), "Module: unix\n");
        writeFile(tree.pamd() / "common-password",
            "password required pam_unix.so obscure use_authtok "
            "try_first_pass yescrypt \n");
        // Empty IDENTITY_ACCESS config: nothing requested by default.
        writeFile(tree.conf() / "IDENTITY_ACCESS.conf", "");
        fic::rollback::DaemonMutationJournal::instance().setOverridePath(
            tree.path() / "mutation-journal.json");
        rebuildCoordinator();
    }

    ~WiringEnvironment() {
        fic::rollback::DaemonMutationJournal::instance().resetOverride();
    }

    void rebuildCoordinator() {
        PamPasswordTopologyCoordinator::Options options;
        options.configDirectory = tree.pamd();
        options.stateDirectory = tree.state();
        options.identityConfigDirectory = tree.conf();
        options.executorOptions.historyOptions =
            ManagedPwhistorySlotOptions{std::optional<unsigned>(3), false};
        options.executorOptions.runner =
            [this](const std::string& executable,
                const std::vector<std::string>& arguments,
                const ProcessOptions& processOptions) {
                return mutator.run(executable, arguments, processOptions);
            };
        coordinator = std::make_unique<PamPasswordTopologyCoordinator>(
            journal(), resolver, options);
    }

    MutationJournal& journal() {
        std::string error;
        MutationJournal* journal =
            fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        require(journal != nullptr, "daemon journal unavailable: " + error);
        return *journal;
    }

    // Configuration intent is the authoritative desired state (production
    // reader shape: ModuleConfigFileHandler statuses).
    void setIntent(bool quality, bool history) {
        writeFile(tree.conf() / "IDENTITY_ACCESS.conf",
            std::string("enable_password_quality.status=") +
                (quality ? "ENABLE" : "DISABLE") + "\n" +
                "enable_password_history.status=" +
                (history ? "ENABLE" : "DISABLE") + "\n");
    }

    void applyOk() {
        std::string error;
        require(coordinator->applyJointRequestedState(error),
            "joint apply failed: " + error);
    }

    void applyFail(const std::string& why) {
        std::string error;
        require(!coordinator->applyJointRequestedState(error),
            why + ": joint apply unexpectedly succeeded");
    }

    PamPasswordTopologySnapshot inspect() {
        PamPasswordStateInspectionOptions options;
        options.configDirectory = tree.pamd();
        options.stateDirectory = tree.state();
        PamPasswordTopologySnapshot snapshot;
        std::string error;
        require(inspectPamPasswordTopology(options, journal(), snapshot,
                   error),
            "test inspection failed: " + error);
        return snapshot;
    }

    std::size_t appliedCount() {
        std::size_t count = 0;
        for (const auto& record : journal().records()) {
            if (record.status == MutationStatus::Applied) {
                ++count;
            }
        }
        return count;
    }

    MutationStatus statusOf(const std::string& policyName) {
        for (const auto& record : journal().records()) {
            if (record.policy.policyName == policyName) {
                return record.status;
            }
        }
        throw std::runtime_error("no journal record for " + policyName);
    }

    bool hasAppliedRecord(const std::string& policyName) {
        for (const auto& record : journal().records()) {
            if (record.policy.policyName == policyName &&
                record.status == MutationStatus::Applied) {
                return true;
            }
        }
        return false;
    }

    // Production rollback shape: RollbackExecutor dispatch -> C2 joint
    // transition; the joint requested state comes from the configuration
    // intent of the surviving capability.
    fic::rollback::RollbackReport rollback(const std::string& policyName) {
        fic::rollback::RollbackExecutorDeps deps;
        deps.pamPlatform = fic::platform::PamPlatformConfig{};
        deps.pamPasswordTopologyTransition =
            [this](bool qualityRequested, bool historyRequested,
                std::string& error) {
                return jointTransition(qualityRequested, historyRequested,
                    error);
            };
        deps.pamPasswordRequestedState =
            [this](bool& qualityRequested, bool& historyRequested,
                std::string& error) {
                PamPasswordRequestedState requested;
                if (!fic::identity::pam::readJointPasswordConfigIntent(
                        requested, error, tree.conf())) {
                    return false;
                }
                qualityRequested = requested.qualityRequested;
                historyRequested = requested.historyRequested;
                return true;
            };
        return fic::rollback::rollbackPolicyBeforeDisable(
            {"IDENTITY_ACCESS", "PAM", policyName}, "", deps);
    }

    fic::rollback::PamRollbackOptions::JointTransitionOutcome
    jointTransition(bool qualityRequested, bool historyRequested,
        std::string& error) {
        fic::rollback::PamRollbackOptions::JointTransitionOutcome outcome;
        // Same construction shape as the production wiring: a fresh
        // coordinator over the SAME daemon journal per rollback call.
        PamPasswordTopologyCoordinator::Options options;
        options.configDirectory = tree.pamd();
        options.stateDirectory = tree.state();
        options.identityConfigDirectory = tree.conf();
        options.executorOptions.historyOptions =
            ManagedPwhistorySlotOptions{std::optional<unsigned>(3), false};
        options.executorOptions.runner =
            [this](const std::string& executable,
                const std::vector<std::string>& arguments,
                const ProcessOptions& processOptions) {
                return mutator.run(executable, arguments, processOptions);
            };
        PamPasswordTopologyCoordinator rollbackCoordinator(
            journal(), resolver, options);
        const PamPasswordRequestedState requested{
            qualityRequested, historyRequested};
        outcome.success = rollbackCoordinator.transition(requested, error);
        outcome.changedSystemState =
            rollbackCoordinator.lastResult().changedSystemState;
        outcome.error = error;
        return outcome;
    }
};

// ---- R1-R8: apply matrix through the joint configuration intent ----

void testR1_noneToQuality() {
    WiringEnvironment env;
    env.setIntent(true, false);
    env.applyOk();
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::FicQuality, "R1: FicQuality expected");
    require(snapshot.ownership.ficQualityOwned, "R1: quality owned");
    require(env.mutator.invocations.size() == 1 &&
            env.mutator.invocations[0].flag == "--enable" &&
            env.mutator.invocations[0].profileId ==
                kFicPasswordQualityHookProfileId,
        "R1: one native quality enable expected");
    require(env.appliedCount() == 1, "R1: one Applied record expected");
    require(env.statusOf("enable_password_quality") ==
            MutationStatus::Applied, "R1: quality record Applied");
}

void testR2_noneToHistory() {
    WiringEnvironment env;
    env.setIntent(false, true);
    env.applyOk();
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::FicHistoryInitial,
        "R2: FicHistoryInitial expected");
    require(env.mutator.invocations.size() == 1 &&
            env.mutator.invocations[0].profileId ==
                kFicPasswordHistoryInitialHookProfileId,
        "R2: one native history-initial enable expected");
    require(env.statusOf("enable_password_history") ==
            MutationStatus::Applied, "R2: history record Applied");
}

void testR3_noneToQualityPlusHistory() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "R3: FicQualityPlusFicHistory expected");
    require(env.appliedCount() == 2,
        "R3: quality + history Applied records expected");
}

void testR4_qualityToQualityPlusHistory() {
    WiringEnvironment env;
    env.setIntent(true, false);
    env.applyOk();
    const std::size_t before = env.mutator.invocations.size();
    env.setIntent(true, true);
    env.applyOk();
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "R4: Q+H expected");
    require(env.mutator.invocations.size() > before,
        "R4: history consumer attach expected");
    // The quality slot must NOT be re-mutated by the joint transition.
    for (std::size_t index = before;
         index < env.mutator.invocations.size(); ++index) {
        require(env.mutator.invocations[index].profileId !=
                kFicPasswordQualityHookProfileId,
            "R4: quality slot must stay untouched");
    }
}

void testR5_historyToQualityPlusHistory() {
    WiringEnvironment env;
    env.setIntent(false, true);
    env.applyOk();
    env.setIntent(true, true);
    env.applyOk();
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "R5: Q+H expected (variant switch through the planner)");
    require(env.mutator.invocations.size() == 4,
        "R5: initial-enable, initial-disable, quality-enable, "
        "consumer-enable expected");
}

void testR6_qualityPlusHistoryToQuality() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    env.setIntent(true, false);
    env.applyOk();
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::FicQuality, "R6: FicQuality expected");
}

void testR7_qualityPlusHistoryToHistory() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    env.setIntent(false, true);
    env.applyOk();
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::FicHistoryInitial,
        "R7: FicHistoryInitial expected");
}

void testR8_toNone() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    env.setIntent(false, false);
    env.applyOk();
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass == PamPasswordTopologyClass::None,
        "R8: None expected");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral &&
            snapshot.historySlotState == ManagedPasswordSlotState::Neutral &&
            snapshot.historyInitialSlotState ==
                ManagedPasswordSlotState::Neutral,
        "R8: all FIC slots Neutral expected");
}

// ---- R9/R10: idempotent reapply and restart/reconstruct ----

void testR9_idempotentReapply() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    const std::size_t invocations = env.mutator.invocations.size();
    const std::size_t applied = env.appliedCount();
    env.applyOk();
    require(env.mutator.invocations.size() == invocations,
        "R9: no native mutation on idempotent reapply");
    require(env.appliedCount() == applied,
        "R9: no additional Applied ownership on idempotent reapply");
}

void testR10_restartReconcileIsNoOp() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    const std::size_t invocations = env.mutator.invocations.size();
    const std::size_t applied = env.appliedCount();
    // Daemon restart: the coordinator is reconstructed, the journal and
    // the configuration intent persist.
    env.rebuildCoordinator();
    env.applyOk();
    require(env.mutator.invocations.size() == invocations,
        "R10: restart reconcile must not re-mutate the proven topology");
    require(env.appliedCount() == applied,
        "R10: restart reconcile must not create a new mutation id");
}

// ---- R11/R12: foreign stock pwquality producer ----

void testR11_foreignPreExistingSatisfiesQuality() {
    WiringEnvironment env;
    env.mutator.forceSelect(kStockPwqualityProfileId);
    env.setIntent(true, false);
    env.applyOk();
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::ForeignQuality,
        "R11: ForeignQuality expected");
    require(!snapshot.ownership.ficQualityOwned,
        "R11: FIC quality ownership must NOT be taken");
    require(env.mutator.invocations.empty(),
        "R11: no FIC native mutation for a satisfied foreign capability");
}

void testR12_foreignAddedDuringActivityPreservedOnRollback() {
    WiringEnvironment env;
    env.setIntent(true, false);
    env.applyOk();
    // Stock pwquality appears while FIC quality is active.
    env.mutator.forceSelect(kStockPwqualityProfileId);
    const auto report = env.rollback("enable_password_quality");
    require(report.rollbackCompleted(),
        "R12: rollback must succeed: " + report.message);
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::ForeignQuality,
        "R12: stock pwquality must remain the quality producer");
    require(!snapshot.ownership.ficQualityOwned,
        "R12: FIC quality must be released");
    require(env.mutator.isSelected(kStockPwqualityProfileId),
        "R12: foreign stock profile must stay selected");
    require(env.statusOf("enable_password_quality") ==
            MutationStatus::RolledBack, "R12: quality record RolledBack");
}

// ---- R13-R16: rollback matrix ----

void testR13_applyQualityRollbackToNone() {
    WiringEnvironment env;
    env.setIntent(true, false);
    env.applyOk();
    const auto report = env.rollback("enable_password_quality");
    require(report.rollbackCompleted(), "R13: " + report.message);
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass == PamPasswordTopologyClass::None,
        "R13: None expected");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral,
        "R13: quality slot Neutral");
    require(env.statusOf("enable_password_quality") ==
            MutationStatus::RolledBack, "R13: record RolledBack");
}

void testR14_applyHistoryRollbackToNone() {
    WiringEnvironment env;
    env.setIntent(false, true);
    env.applyOk();
    const auto report = env.rollback("enable_password_history");
    require(report.rollbackCompleted(), "R14: " + report.message);
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::None, "R14: None expected");
    require(env.statusOf("enable_password_history") ==
            MutationStatus::RolledBack, "R14: record RolledBack");
}

void testR15_applyQualityPlusHistoryRollbackToNone() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    // Disable quality: the rollback runs while the config still requests
    // quality; the surviving history intent keeps the topology valid.
    auto report = env.rollback("enable_password_quality");
    require(report.rollbackCompleted(), "R15 (quality): " + report.message);
    // The disable flow then flips the configuration (quality released).
    env.setIntent(false, true);
    // Disable history: now nothing is requested anymore.
    report = env.rollback("enable_password_history");
    require(report.rollbackCompleted(), "R15 (history): " + report.message);
    const auto snapshot = env.inspect();
    require(snapshot.classification.topologyClass ==
            PamPasswordTopologyClass::None, "R15: None expected");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Neutral &&
            snapshot.historySlotState == ManagedPasswordSlotState::Neutral &&
            snapshot.historyInitialSlotState ==
                ManagedPasswordSlotState::Neutral,
        "R15: all FIC slots Neutral expected");
}

void testR16_rollbackVariantSwitchRestoresJointState() {
    WiringEnvironment env;
    env.setIntent(true, true);
    env.applyOk();
    // Q+H -> H-only through the production disable path.
    auto report = env.rollback("enable_password_quality");
    require(report.rollbackCompleted(), "R16 (disable): " + report.message);
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::FicHistoryInitial,
        "R16: H-only after the quality release");
    // The surviving history domain keeps journal-backed provenance (the
    // variant switch detached the consumer slot and attached the initial
    // slot with a fresh Applied record; joint semantics never orphan the
    // requested history capability).
    require(env.hasAppliedRecord("enable_password_history"),
        "R16: history provenance stays Applied");
    // Rollback of the change = re-requesting quality: the planner must
    // perform the variant switch DetachInitial -> AttachQuality ->
    // AttachConsumer (no special-casing).
    env.setIntent(true, true);
    const std::size_t mark = env.mutator.invocations.size();
    env.applyOk();
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "R16: Q+H restored");
    require(env.mutator.invocations.size() - mark == 3 &&
                env.mutator.invocations[mark].flag == "--disable" &&
                env.mutator.invocations[mark].profileId ==
                    kFicPasswordHistoryInitialHookProfileId &&
                env.mutator.invocations[mark + 1].flag == "--enable" &&
                env.mutator.invocations[mark + 1].profileId ==
                    kFicPasswordQualityHookProfileId &&
                env.mutator.invocations[mark + 2].flag == "--enable" &&
                env.mutator.invocations[mark + 2].profileId ==
                    kFicPasswordHistoryHookProfileId,
        "R16: planner sequence DetachInitial, AttachQuality, "
        "AttachConsumer expected");
}

// ---- Rollback failure / unsafe states ----

void testRollbackFailureNeverMarksRolledBack() {
    WiringEnvironment env;
    env.setIntent(true, false);
    env.applyOk();
    // Inject a native failure for the FIRST rollback invocation.
    env.mutator.behavior =
        [](std::size_t, const FakeNativeMutator::Invocation&) { return 42; };
    const auto report = env.rollback("enable_password_quality");
    require(!report.rollbackCompleted(),
        "rollback failure must not be reported as completed");
    require(env.statusOf("enable_password_quality") !=
            MutationStatus::RolledBack,
        "originating record must NOT be marked RolledBack on failure");
    // Fail-closed recovery semantics (same as the legacy PAM path): after
    // a failed rollback the record is RollbackFailed and the provenance
    // chain is broken — a retried rollback/apply MUST NOT silently
    // succeed against the unproven state.
    env.mutator.behavior = nullptr;
    const auto retry = env.rollback("enable_password_quality");
    require(!retry.rollbackCompleted(),
        "recovery after a failed rollback must stay fail closed");
    require(env.statusOf("enable_password_quality") ==
            MutationStatus::RollbackFailed,
        "the failed record must stay RollbackFailed");
}

void testSelectedButUnownedFailsClosed() {
    WiringEnvironment env;
    // Physically selected FIC quality identity with NO provenance:
    // a canonical Active slot carrying a mutation id that matches no
    // journal record.
    std::string content;
    std::string error;
    require(PamManagedPasswordSlots::renderActiveQuality(
                7777, content, error),
        "test slot render failed: " + error);
    writeFile(env.tree.pamd() /
                  PamManagedPasswordSlots::qualitySlot().fileName,
        content);
    env.mutator.forceSelect(kFicPasswordQualityHookProfileId);
    // Configuration wants to disable it (joint target None).
    env.setIntent(false, false);
    const std::size_t invocations = env.mutator.invocations.size();
    env.applyFail("selected-but-unowned identity");
    require(env.mutator.invocations.size() == invocations,
        "no destructive mutation against an unowned identity");
}

void testUnsafeStateFailsBeforeMutation() {
    WiringEnvironment env;
    // Selected quality hook + Neutral slot: structurally unsafe.
    env.mutator.forceSelect(kFicPasswordQualityHookProfileId);
    env.setIntent(false, false);
    const std::size_t invocations = env.mutator.invocations.size();
    env.applyFail("unsafe selected+Neutral state");
    require(env.mutator.invocations.size() == invocations,
        "apply must fail BEFORE any mutation on an unsafe topology");
}

// ---- Policy layer: joint wiring through the activation policy ----

void testPolicyLayerUsesJointIntent() {
    WiringEnvironment env;
    // Production runtime paths pointing at the test config root: the
    // policy's module configuration AND the coordinator's default
    // desired-state reader both read the IDENTITY_ACCESS configuration
    // intent from the same place as the real daemon.
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = env.tree.conf();
    paths.logDir = env.tree.path() / "log";
    paths.dataDir = env.tree.path() / "data";
    paths.runtimeDir = env.tree.path() / "run";
    paths.commandHashFile = env.tree.path() / "data/commandhash.txt";
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);

    // Minimal PamAuthUpdate platform composition (quality + history), the
    // same shape the daemon registry sees on the lifted platforms.
    fic::platform::PamPlatformConfig platform;
    platform.configDirectories = {env.tree.pamd()};
    platform.scopes = {
        {fic::platform::PamScope::EffectivePasswordStack, {"passwd"}}};
    platform.capabilities = {
        {fic::platform::PamCapability::PasswordQuality,
         fic::platform::PamProviderKind::PamPwquality,
         fic::platform::PamScope::EffectivePasswordStack,
         env.tree.path() / "security/pwquality.conf",
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate},
        {fic::platform::PamCapability::PasswordHistory,
         fic::platform::PamProviderKind::PamPwhistory,
         fic::platform::PamScope::EffectivePasswordStack, {},
         fic::platform::PamTopologyStrategyKind::PamAuthUpdate, {},
         std::nullopt, fic::platform::PamIdentitySubjectScope::AllPamSubjects,
         fic::platform::PamCapabilityConfigurationMode::ModuleArguments}};
    platform.passwordTopologyRuntimeMutable = true;
    PamCapabilityActivationPolicyOptions options;
    options.passwordCoordinatorFactory = [&env]() {
        PamPasswordTopologyCoordinator::Options coordinatorOptions;
        coordinatorOptions.configDirectory = env.tree.pamd();
        coordinatorOptions.stateDirectory = env.tree.state();
        coordinatorOptions.executorOptions.historyOptions =
            ManagedPwhistorySlotOptions{std::optional<unsigned>(3), false};
        coordinatorOptions.executorOptions.runner =
            [&env](const std::string& executable,
                const std::vector<std::string>& arguments,
                const ProcessOptions& processOptions) {
                return env.mutator.run(executable, arguments, processOptions);
            };
        return std::unique_ptr<PamPasswordTopologyCoordinator>(
            new PamPasswordTopologyCoordinator(
                env.journal(), env.resolver, coordinatorOptions));
    };
    PamCapabilityActivationPolicy qualityPolicy(
        platform, fic::platform::PamCapability::PasswordQuality,
        std::move(options));
    // The configuration intent requests BOTH capabilities; a single
    // quality-policy apply must drive ONE joint transition to Q+H.
    env.setIntent(true, true);
    require(qualityPolicy.apply(), "policy-layer joint apply failed");
    require(env.inspect().classification.topologyClass ==
            PamPasswordTopologyClass::FicQualityPlusFicHistory,
        "policy-layer apply must honor the joint configuration intent");
    // Idempotent: the second policy apply is a proven no-op.
    const std::size_t invocations = env.mutator.invocations.size();
    require(qualityPolicy.apply(), "idempotent policy-layer apply failed");
    require(env.mutator.invocations.size() == invocations,
        "policy-layer idempotent reapply must not mutate");
}

// ---- Support contract (ReadOnly lift) ----

void testSupportContract() {
    const fic::platform::PlatformProfile profile =
        fic::platform::makeBuildPlatformProfile();
    const bool mutableDomain = profile.pam.passwordTopologyRuntimeMutable;
    // Evidence-based acceptance: exactly the gate-validated platforms are
    // lifted; every other platform keeps the safe state.
    if (profile.id == "debian-12" || profile.id == "ubuntu-24.04") {
        require(mutableDomain,
            "Debian 12 / Ubuntu 24.04 must be lifted (gates passed)");
    } else {
        require(!mutableDomain,
            "non-validated platform " + profile.id +
                " must stay ReadOnly");
    }

    const std::vector<fic::platform::PamPolicyFeature> passwordFeatures = {
        fic::platform::PamPolicyFeature::PasswordMinLength,
        fic::platform::PamPolicyFeature::PasswordMinClasses,
        fic::platform::PamPolicyFeature::PasswordCheckUsername,
        fic::platform::PamPolicyFeature::PasswordCheckGecos,
        fic::platform::PamPolicyFeature::PasswordQualityEnforceForRoot,
        fic::platform::PamPolicyFeature::PasswordMinChangedCharacters,
        fic::platform::PamPolicyFeature::PasswordMinLowercase,
        fic::platform::PamPolicyFeature::PasswordMinUppercase,
        fic::platform::PamPolicyFeature::PasswordMinDigits,
        fic::platform::PamPolicyFeature::PasswordMinOther,
        fic::platform::PamPolicyFeature::PasswordHistoryDepth,
        fic::platform::PamPolicyFeature::PasswordHistoryEnforceForRoot,
    };
    for (const fic::platform::PamPolicyFeature feature : passwordFeatures) {
        const auto support =
            fic::identity::pam::pamPolicySupport(profile.pam, feature);
        if (support ==
            fic::platform::PamPolicySupport::Unsupported) {
            continue; // provider binding absent on this platform
        }
        require(mutableDomain
                    ? support == fic::platform::PamPolicySupport::
                          RequiresTopologyActivation
                    : support ==
                          fic::platform::PamPolicySupport::ReadOnly,
            "password feature support must follow the validated lift flag");
    }

    // Negative: clearing the flag restores the safe state on the SAME
    // platform composition.
    auto readOnlyPlatform = profile.pam;
    readOnlyPlatform.passwordTopologyRuntimeMutable = false;
    for (const fic::platform::PamPolicyFeature feature : passwordFeatures) {
        const auto support =
            fic::identity::pam::pamPolicySupport(readOnlyPlatform, feature);
        if (support ==
            fic::platform::PamPolicySupport::Unsupported) {
            continue;
        }
        require(support == fic::platform::PamPolicySupport::ReadOnly,
            "without the validated lift flag password policies must stay "
            "ReadOnly");
    }

    // Negative: the flag must not create mutable support outside the
    // PamAuthUpdate topology.
    auto staticPlatform = readOnlyPlatform;
    staticPlatform.passwordTopologyRuntimeMutable = true;
    for (auto& capability : staticPlatform.capabilities) {
        if (capability.capability !=
                fic::platform::PamCapability::AuthenticationLockout) {
            capability.topology =
                fic::platform::PamTopologyStrategyKind::StaticVerifyOnly;
        }
    }
    require(fic::identity::pam::pamPolicySupport(
                staticPlatform,
                fic::platform::PamPolicyFeature::PasswordMinLength) ==
            fic::platform::PamPolicySupport::Supported,
        "the flag must not lift non-PamAuthUpdate topologies");
}

} // namespace

int main() {
    const std::vector<std::pair<const char*, void (*)()>> tests = {
        {"R1_noneToQuality", testR1_noneToQuality},
        {"R2_noneToHistory", testR2_noneToHistory},
        {"R3_noneToQualityPlusHistory", testR3_noneToQualityPlusHistory},
        {"R4_qualityToQualityPlusHistory",
            testR4_qualityToQualityPlusHistory},
        {"R5_historyToQualityPlusHistory",
            testR5_historyToQualityPlusHistory},
        {"R6_qualityPlusHistoryToQuality",
            testR6_qualityPlusHistoryToQuality},
        {"R7_qualityPlusHistoryToHistory",
            testR7_qualityPlusHistoryToHistory},
        {"R8_toNone", testR8_toNone},
        {"R9_idempotentReapply", testR9_idempotentReapply},
        {"R10_restartReconcileIsNoOp", testR10_restartReconcileIsNoOp},
        {"R11_foreignPreExisting", testR11_foreignPreExistingSatisfiesQuality},
        {"R12_foreignAddedDuringActivity",
            testR12_foreignAddedDuringActivityPreservedOnRollback},
        {"R13_rollbackQuality", testR13_applyQualityRollbackToNone},
        {"R14_rollbackHistory", testR14_applyHistoryRollbackToNone},
        {"R15_rollbackQualityPlusHistory",
            testR15_applyQualityPlusHistoryRollbackToNone},
        {"R16_rollbackVariantSwitch",
            testR16_rollbackVariantSwitchRestoresJointState},
        {"rollbackFailure", testRollbackFailureNeverMarksRolledBack},
        {"selectedButUnowned", testSelectedButUnownedFailsClosed},
        {"unsafeState", testUnsafeStateFailsBeforeMutation},
        {"policyLayerJointIntent", testPolicyLayerUsesJointIntent},
        {"supportContract", testSupportContract},
    };

    std::size_t failed = 0;
    for (const auto& entry : tests) {
        try {
            entry.second();
            std::cout << "PASS " << entry.first << '\n';
        } catch (const std::exception& exception) {
            ++failed;
            std::cout << "FAIL " << entry.first << ": "
                      << exception.what() << '\n';
        } catch (...) {
            ++failed;
            std::cout << "FAIL " << entry.first << ": unknown exception\n";
        }
    }
    if (failed != 0) {
        std::cout << failed << " wiring test(s) FAILED\n";
        return 1;
    }
    std::cout << "all pam password wiring tests passed\n";
    return 0;
}








