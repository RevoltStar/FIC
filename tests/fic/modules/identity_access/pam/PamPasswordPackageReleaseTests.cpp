// Package-release helper tests: the C2 password topology release the
// Debian prerm performs through fic --maintenance
// pam-password-prerm-prepare. Same fake native pam-auth-update mutator
// model as the executor/wiring tests; the release path is the REAL
// PamPasswordPackageRelease over the REAL transition executor, planner,
// slot writers and mutation journal.
#include "modules/identity_access/pam/PamManagedPasswordSlotWriter.h"
#include "modules/identity_access/pam/PamPasswordPackageRelease.h"
#include "modules/identity_access/pam/PamPasswordTopologyCoordinator.h"
#include "modules/identity_access/pam/PamPasswordTopologyState.h"

#include <fic/core/process/ProcessExecutor.h>

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
using fic::identity::pam::PamPasswordPackageRelease;
using fic::identity::pam::PamPasswordRequestedState;
using fic::identity::pam::PamPasswordStateInspectionOptions;
using fic::identity::pam::PamPasswordTopologyClass;
using fic::identity::pam::PamPasswordTopologyCoordinator;
using fic::identity::pam::PamPasswordTopologySnapshot;
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
        root_ = base / ("fic-pam-package-release-test-" +
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

// Deterministic fake native pam-auth-update mutator (same semantics as
// the executor/wiring harness): "Module:" records in the password state
// database and generated include lines (with the real trailing-whitespace
// quirk) in common-password, ONE profile per invocation.
struct FakeNativeMutator {
    struct Invocation {
        std::string flag;
        std::string profileId;
    };

    TemporaryDirectory& tree;
    std::vector<Invocation> invocations;
    std::function<int(std::size_t, const Invocation&)> behavior;
    std::function<void()> afterApplyHook;

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
            if (afterApplyHook) {
                afterApplyHook();
            }
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

    // Partial native DISABLE: the generated include disappears while the
    // selection record stays.
    void forceIncludeOnlyRemove(const std::string& slotName) {
        std::string stack = readFile(tree.pamd() / "common-password");
        std::string filtered;
        std::istringstream stream(stack);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find("include " + slotName) == std::string::npos) {
                filtered += line + "\n";
            }
        }
        writeFile(tree.pamd() / "common-password", filtered);
    }

    // Partial native mutation: the state record lands but the generated
    // stack regeneration does not happen.
    void forceStateOnlySelect(const std::string& profileId) {
        std::vector<std::string> selected = readSelected();
        selected.push_back(profileId);
        std::string stateContent;
        for (const std::string& profile : selected) {
            stateContent += "Module: " + profile + "\n";
        }
        writeFile(stateFile(), stateContent);
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

    void regenerateStack(const std::vector<std::string>& selected) const {
        // Deterministic generation order: foreign pwquality rule, FIC
        // quality (1024), FIC history consumer (1023), FIC history
        // initial (1022), stock pam_unix. Include lines carry the real
        // trailing space.
        bool quality = false;
        bool consumer = false;
        bool initial = false;
        for (const std::string& profile : selected) {
            if (profile == kFicPasswordQualityHookProfileId) {
                quality = true;
            } else if (profile == kFicPasswordHistoryHookProfileId) {
                consumer = true;
            } else if (profile ==
                       kFicPasswordHistoryInitialHookProfileId) {
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

// Full release environment: pam.d tree, state directory, mutation
// journal, production coordinator (to BUILD owned states) and the
// package-release helper under test.
struct ReleaseEnvironment {
    TemporaryDirectory tree;
    MutationJournal journal{tree.path() / "journal.json"};
    FakeNativeMutator mutator{tree};
    fic::platform::PlatformExecutableResolver resolver{
        fic::platform::PlatformExecutables{}};
    std::unique_ptr<PamPasswordTopologyCoordinator> coordinator;

    ReleaseEnvironment() {
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
        writeFile(tree.conf() / "IDENTITY_ACCESS.conf", "");
        std::string error;
        require(journal.initializeOrLoad(error),
            "journal initialization failed: " + error);
        rebuildCoordinator();
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
            journal, resolver, options);
    }

    void setIntent(bool quality, bool history) {
        writeFile(tree.conf() / "IDENTITY_ACCESS.conf",
            std::string("enable_password_quality.status=") +
                (quality ? "ENABLE" : "DISABLE") + "\n" +
                "enable_password_history.status=" +
                (history ? "ENABLE" : "DISABLE") + "\n");
    }

    void applyOk(bool quality, bool history) {
        setIntent(quality, history);
        std::string error;
        require(coordinator->applyJointRequestedState(error),
            "joint apply failed: " + error);
    }

    PamPasswordPackageRelease makeRelease() {
        PamPasswordPackageRelease::Options options;
        options.configDirectory = tree.pamd();
        options.stateDirectory = tree.state();
        options.executorOptions.historyOptions =
            ManagedPwhistorySlotOptions{std::optional<unsigned>(3), false};
        options.executorOptions.runner =
            [this](const std::string& executable,
                const std::vector<std::string>& arguments,
                const ProcessOptions& processOptions) {
                return mutator.run(executable, arguments, processOptions);
            };
        return PamPasswordPackageRelease(journal, resolver, options);
    }

    bool runPreflight(PamPasswordPackageRelease::Report& report,
        std::string& error) {
        PamPasswordPackageRelease release = makeRelease();
        return release.run(
            PamPasswordPackageRelease::Mode::Preflight, report, error);
    }

    bool runRelease(PamPasswordPackageRelease::Report& report,
        std::string& error) {
        PamPasswordPackageRelease release = makeRelease();
        return release.run(
            PamPasswordPackageRelease::Mode::Release, report, error);
    }

    PamPasswordTopologySnapshot inspect() {
        PamPasswordStateInspectionOptions options;
        options.configDirectory = tree.pamd();
        options.stateDirectory = tree.state();
        PamPasswordTopologySnapshot snapshot;
        std::string error;
        require(inspectPamPasswordTopology(options, journal, snapshot,
                   error),
            "test inspection failed: " + error);
        return snapshot;
    }

    std::size_t activeRecordCount() {
        std::size_t count = 0;
        for (const auto& record : journal.records()) {
            if (record.status == MutationStatus::Prepared ||
                record.status == MutationStatus::Applied) {
                ++count;
            }
        }
        return count;
    }
};

void requireFullyReleased(ReleaseEnvironment& env,
    bool foreignExpected) {
    const auto snapshot = env.inspect();
    require(!snapshot.selections.ficQualitySelected &&
            !snapshot.selections.ficHistorySelected &&
            !snapshot.selections.ficHistoryInitialSelected,
        "no FIC password selection may remain after the release");
    require(snapshot.qualitySlotState ==
                ManagedPasswordSlotState::Neutral &&
            snapshot.historySlotState ==
                ManagedPasswordSlotState::Neutral &&
            snapshot.historyInitialSlotState ==
                ManagedPasswordSlotState::Neutral,
        "all three managed password slots must be Neutral after the "
        "release");
    require(snapshot.classification.topologyClass ==
                (foreignExpected ? PamPasswordTopologyClass::ForeignQuality
                                 : PamPasswordTopologyClass::None),
        "the final semantic topology must be None or ForeignQuality");
    require(snapshot.foreignQualityProducer == foreignExpected,
        "the foreign producer presence must match the expectation");
}

// ---- P1-P7: package release matrix (owned states) ----

void testP1_noneReleasesAsNoOp() {
    ReleaseEnvironment env;
    const std::size_t recordsBefore = env.activeRecordCount();
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(env.runPreflight(report, error),
        "P1 preflight: " + error);
    require(env.mutator.invocations.empty(),
        "P1: preflight must not invoke the native mutator");
    require(env.runRelease(report, error), "P1 release: " + error);
    require(report.detachedIdentities.empty(),
        "P1: nothing to detach from the None state");
    require(report.topologyAfter == PamPasswordTopologyClass::None,
        "P1: final class None");
    require(env.mutator.invocations.empty(),
        "P1: no native mutation for the None release");
    require(env.activeRecordCount() == recordsBefore,
        "P1: no journal records created by a no-op release");
    requireFullyReleased(env, false);
}

void testP2_qualityReleasesToNone() {
    ReleaseEnvironment env;
    env.applyOk(true, false);
    require(env.inspect().ownership.ficQualityOwned,
        "P2 fixture: quality must be owned");
    std::string error;
    PamPasswordPackageRelease::Report report;
    const std::size_t invocationsAfterApply =
        env.mutator.invocations.size();
    require(env.runPreflight(report, error),
        "P2 preflight: " + error);
    require(report.topologyBefore == PamPasswordTopologyClass::FicQuality,
        "P2: preflight class FicQuality");
    require(env.mutator.invocations.size() == invocationsAfterApply,
        "P2: preflight must not mutate");
    require(env.runRelease(report, error), "P2 release: " + error);
    require(report.detachedIdentities ==
            std::vector<std::string>{kFicPasswordQualityHookProfileId},
        "P2: exactly the quality identity detached");
    requireFullyReleased(env, false);
}

void testP3_historyInitialReleasesToNone() {
    ReleaseEnvironment env;
    env.applyOk(false, true);
    require(env.inspect().ownership.ficHistoryInitialOwned,
        "P3 fixture: history-initial must be owned");
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(env.runRelease(report, error), "P3 release: " + error);
    require(report.detachedIdentities ==
            std::vector<std::string>{
                kFicPasswordHistoryInitialHookProfileId},
        "P3: exactly the history-initial identity detached");
    requireFullyReleased(env, false);
}

void testP4_qualityPlusHistoryReleasesToNone() {
    ReleaseEnvironment env;
    env.applyOk(true, true);
    const std::size_t invocationsAfterApply =
        env.mutator.invocations.size();
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(env.runRelease(report, error), "P4 release: " + error);
    // Planner order: the history consumer detaches before its producer.
    require(report.detachedIdentities ==
            std::vector<std::string>{
                kFicPasswordHistoryHookProfileId,
                kFicPasswordQualityHookProfileId},
        "P4: consumer-before-producer release order");
    require(env.mutator.invocations.size() ==
                invocationsAfterApply + 2 &&
            env.mutator.invocations[invocationsAfterApply].flag ==
                "--disable" &&
            env.mutator.invocations[invocationsAfterApply].profileId ==
                kFicPasswordHistoryHookProfileId &&
            env.mutator.invocations[invocationsAfterApply + 1]
                    .profileId ==
                kFicPasswordQualityHookProfileId,
        "P4: one profile per native mutation, planner order");
    requireFullyReleased(env, false);
}

void testP5_foreignQualityReleasesAsNoOp() {
    ReleaseEnvironment env;
    env.mutator.forceSelect(kStockPwqualityProfileId);
    const std::size_t recordsBefore = env.activeRecordCount();
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(env.runPreflight(report, error),
        "P5 preflight: " + error);
    require(report.topologyBefore ==
            PamPasswordTopologyClass::ForeignQuality,
        "P5: preflight class ForeignQuality");
    require(env.runRelease(report, error), "P5 release: " + error);
    require(report.detachedIdentities.empty(),
        "P5: the foreign producer is never touched");
    require(env.mutator.invocations.empty(),
        "P5: no native mutation for a foreign-only release");
    require(env.activeRecordCount() == recordsBefore,
        "P5: no journal records for a foreign-only release");
    requireFullyReleased(env, true);
    require(env.mutator.isSelected(kStockPwqualityProfileId),
        "P5: stock pwquality selection preserved");
}

void testP6_foreignQualityPlusHistoryReleasesToForeignQuality() {
    ReleaseEnvironment env;
    env.mutator.forceSelect(kStockPwqualityProfileId);
    env.applyOk(false, true);
    const auto before = env.inspect();
    require(before.classification.topologyClass ==
            PamPasswordTopologyClass::ForeignQualityPlusFicHistory,
        "P6 fixture: ForeignQualityPlusFicHistory expected");
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(env.runRelease(report, error), "P6 release: " + error);
    require(report.detachedIdentities ==
            std::vector<std::string>{kFicPasswordHistoryHookProfileId},
        "P6: only the FIC history consumer detached");
    requireFullyReleased(env, true);
    require(env.mutator.isSelected(kStockPwqualityProfileId),
        "P6: stock pwquality preserved");
}

void testP7_foreignAddedDuringFicQualityReleasesToForeignQuality() {
    ReleaseEnvironment env;
    env.applyOk(true, false);
    // A foreign stock pwquality producer appears while FIC quality is
    // still owned (§10 recoverable release state).
    env.mutator.forceSelect(kStockPwqualityProfileId);
    const auto before = env.inspect();
    require(before.classification.topologyClass ==
            PamPasswordTopologyClass::ForeignQualityPlusFicQuality,
        "P7 fixture: ForeignQualityPlusFicQuality expected");
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(env.runPreflight(report, error),
        "P7: the recoverable foreign+quality state must be releasable "
        "eligible: " +
            error);
    require(env.runRelease(report, error), "P7 release: " + error);
    require(report.detachedIdentities ==
            std::vector<std::string>{kFicPasswordQualityHookProfileId},
        "P7: only the FIC quality detached");
    requireFullyReleased(env, true);
    require(env.mutator.isSelected(kStockPwqualityProfileId),
        "P7: stock pwquality preserved");
}

// ---- P8-P12: fail-closed states (before ANY mutation) ----

void requireRefusedBeforeMutation(ReleaseEnvironment& env,
    const std::string& why, const std::string& diagnosticFragment) {
    const std::size_t invocationsBefore = env.mutator.invocations.size();
    std::string preflightError;
    PamPasswordPackageRelease::Report report;
    require(!env.runPreflight(report, preflightError),
        why + ": preflight must refuse: " + preflightError);
    require(preflightError.find(diagnosticFragment) !=
            std::string::npos,
        why + ": classified diagnostic expected, got: " + preflightError);
    require(env.mutator.invocations.size() == invocationsBefore,
        why + ": preflight must not invoke the native mutator");
    const std::size_t recordsBefore = env.activeRecordCount();
    std::string releaseError;
    require(!env.runRelease(report, releaseError),
        why + ": release must refuse: " + releaseError);
    require(env.mutator.invocations.size() == invocationsBefore,
        why + ": the refusal must happen BEFORE any native mutation");
    require(env.activeRecordCount() == recordsBefore,
        why + ": the refusal must not create journal records");
}

void testP8_selectedUnownedQualityFailsBeforeMutation() {
    ReleaseEnvironment env;
    env.mutator.forceSelect(kFicPasswordQualityHookProfileId);
    requireRefusedBeforeMutation(env, "P8",
        "not proven FIC-owned");
}

void testP9_selectedUnownedHistoryFailsBeforeMutation() {
    ReleaseEnvironment env;
    env.mutator.forceSelect(kFicPasswordHistoryHookProfileId);
    requireRefusedBeforeMutation(env, "P9",
        "not proven FIC-owned");
}

void testP10_selectedUnownedInitialFailsBeforeMutation() {
    ReleaseEnvironment env;
    env.mutator.forceSelect(kFicPasswordHistoryInitialHookProfileId);
    requireRefusedBeforeMutation(env, "P10",
        "not proven FIC-owned");
}

void testP11_bothHistoryVariantsFailClosed() {
    ReleaseEnvironment env;
    env.mutator.forceSelect(kFicPasswordHistoryHookProfileId);
    env.mutator.forceSelect(kFicPasswordHistoryInitialHookProfileId);
    requireRefusedBeforeMutation(env, "P11", "both FIC history variants");
}

void testP12_selectedWithNeutralSlotFailsClosed() {
    ReleaseEnvironment env;
    // Selected quality profile with a Neutral slot: unsafe selected+slot
    // state. The refusal happens before any mutation.
    env.mutator.forceSelect(kFicPasswordQualityHookProfileId);
    requireRefusedBeforeMutation(env, "P12", "not proven FIC-owned");
}

// ---- P13: exact-id Prepared crash-leftover recovery (§18) ----

void testP13_preparedCrashLeftoverRecoveredByRelease() {
    ReleaseEnvironment env;
    // Simulate the crash between the slot activation and the native
    // selection: an exact-id Prepared record with a canonical Active
    // quality slot and NO profile selection.
    {
        // Use a dedicated writer over the same journal/config paths to
        // build the crash-leftover through REAL production semantics.
        fic::identity::pam::PamManagedPasswordSlotWriter writer(
            env.tree.pamd(), env.journal,
            fic::identity::pam::PamManagedPasswordDomain::Quality);
        writer.setJournalCompletionFaultHookForTests(
            []() { return false; });
        fic::identity::pam::PamManagedPasswordSlotActivationResult
            activation;
        std::string writerError;
        require(!writer.activateC2Slot(
                    fic::identity::pam::ManagedPasswordSlotRole::Quality,
                    fic::identity::pam::ManagedPwhistorySlotOptions{
                        std::optional<unsigned>(3), false},
                    activation, writerError),
            "P13 fixture: the faulted activation must fail");
        require(activation.mutationId != 0,
            "P13 fixture: the outstanding partial activation must carry "
            "the exact mutation id");
    }
    const auto before = env.inspect();
    require(before.qualitySlotState == ManagedPasswordSlotState::Active &&
            before.ownership.ficQualityPrepared &&
            !before.ownership.ficQualityOwned &&
            !before.selections.ficQualitySelected,
        "P13 fixture: exact-id Prepared crash-leftover expected");
    std::string error;
    PamPasswordPackageRelease::Report report;
    // Preflight: strictly read-only; the leftover Active slot must still
    // be present afterwards (recovery belongs to the release stage).
    require(env.runPreflight(report, error),
        "P13 preflight: the recoverable leftover state must be "
        "eligible: " +
            error);
    require(env.inspect().qualitySlotState ==
            ManagedPasswordSlotState::Active,
        "P13: the preflight must not touch the crash-leftover");
    require(env.runRelease(report, error), "P13 release: " + error);
    require(report.recoveredCrashLeftovers ==
            std::vector<std::string>{kFicPasswordQualityHookProfileId},
        "P13: the exact-id crash-leftover must be reported recovered");
    require(report.detachedIdentities.empty(),
        "P13: after the recovery the release target is already met");
    requireFullyReleased(env, false);
}

void testP13b_unselectedOwnedSlotFailsClosed() {
    ReleaseEnvironment env;
    env.applyOk(true, false);
    // Deselect the profile OUTSIDE any FIC provenance: the slot stays
    // Active and owned while the profile is unselected — an incoherent
    // state that must fail closed (never silently repaired).
    std::vector<std::string> selected;
    std::istringstream stream(readFile(env.mutator.stateFile()));
    std::string line;
    while (std::getline(stream, line)) {
        if (line != "Module: fic-password-quality-hook") {
            selected.push_back(line.substr(8));
        }
    }
    std::string stateContent;
    for (const std::string& profile : selected) {
        stateContent += "Module: " + profile + "\n";
    }
    writeFile(env.mutator.stateFile(), stateContent);
    writeFile(env.tree.pamd() / "common-password",
        "password required pam_unix.so obscure use_authtok "
        "try_first_pass yescrypt \n");
    requireRefusedBeforeMutation(env, "P13b", "not selected");
}

// ---- PF1-PF8: release failure matrix ----

void testPF1_firstDetachFailsNoChange() {
    ReleaseEnvironment env;
    env.applyOk(true, false);
    env.mutator.behavior = [](std::size_t, const auto&) { return 3; };
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(!env.runRelease(report, error),
        "PF1: the release must fail");
    require(report.compensated && report.compensatedStateProven,
        "PF1: the pre-release topology must be proven restored: " +
            error);
    const auto snapshot = env.inspect();
    require(snapshot.selections.ficQualitySelected &&
            snapshot.ownership.ficQualityOwned,
        "PF1: the owned quality state must be intact");
    require(snapshot.qualitySlotState == ManagedPasswordSlotState::Active,
        "PF1: the quality slot must stay Active");
}

void testPF3_rcZeroMalformedResultFailsClosed() {
    ReleaseEnvironment env;
    env.applyOk(true, false);
    // rc=0 but the include disappears while the selection record stays:
    // the resulting state is malformed and rc is never trusted alone.
    // The executor detects the unproven detach; the partial native
    // mutation leaves an INCOHERENT topology that the compensation can
    // NOT prove restored, so the release must fail closed with a
    // CRITICAL diagnostic and no false success.
    env.mutator.afterApplyHook = [&env]() {
        env.mutator.forceStateOnlySelect(kFicPasswordQualityHookProfileId);
        env.mutator.afterApplyHook = nullptr;
    };
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(!env.runRelease(report, error),
        "PF3: the release must fail");
    require(report.compensated && !report.compensatedStateProven,
        "PF3: the unproven compensation must NOT be reported proven: " +
            error);
    require(error.find("CRITICAL") != std::string::npos &&
            error.find("NOT proven restored") != std::string::npos,
        "PF3: a CRITICAL fail-closed diagnostic is required: " + error);
}

void testPF4_secondDetachFailsAfterFirstSuccess() {
    ReleaseEnvironment env;
    env.applyOk(true, true);
    const std::size_t baseline = env.mutator.invocations.size();
    env.mutator.behavior = [baseline](std::size_t number, const auto&) {
        return number - baseline == 2 ? 5 : 0;
    };
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(!env.runRelease(report, error),
        "PF4: the release must fail");
    require(report.compensated && report.compensatedStateProven,
        "PF4: the executor must compensate the proven first detach: " +
            error);
    const auto snapshot = env.inspect();
    require(snapshot.selections.ficQualitySelected &&
            snapshot.selections.ficHistorySelected,
        "PF4: both owned selections must be restored");
    require(snapshot.ownership.ficHistoryOwned &&
            snapshot.ownership.ficQualityOwned,
        "PF4: both ownerships must be proven again");
}

void testPF5_compensationFailureStopsCritical() {
    ReleaseEnvironment env;
    env.applyOk(true, true);
    // The first detach (history consumer) is proven; the second native
    // detach fails; the inverse re-attach of the history consumer then
    // fails on its native enable: the compensation must STOP with a
    // CRITICAL diagnostic instead of mutating further.
    env.mutator.behavior = [](std::size_t, const auto& invocation) {
        if (invocation.flag == "--enable" &&
            invocation.profileId == kFicPasswordHistoryHookProfileId) {
            return 5;
        }
        if (invocation.flag == "--disable" &&
            invocation.profileId == kFicPasswordQualityHookProfileId) {
            return 5;
        }
        return 0;
    };
    PamPasswordPackageRelease release = env.makeRelease();
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(!release.run(
                PamPasswordPackageRelease::Mode::Release, report, error),
        "PF5: the release must fail");
    require(error.find("NOT proven restored") != std::string::npos &&
            error.find("CRITICAL") != std::string::npos,
        "PF5: a CRITICAL fail-closed diagnostic is required: " + error);
    require(!report.compensatedStateProven,
        "PF5: the compensation must NOT be reported proven");
}

void testPF6_foreignDriftMidReleaseAbortsAndCompensates() {
    ReleaseEnvironment env;
    env.applyOk(true, true);
    // After the first (history consumer) detach succeeds, a foreign
    // producer appears: the stale plan aborts and the proven change is
    // compensated; the foreign state is never removed.
    env.mutator.afterApplyHook = [&env]() {
        env.mutator.forceSelect(kStockPwqualityProfileId);
        env.mutator.afterApplyHook = nullptr;
    };
    env.mutator.behavior = [](std::size_t number, const auto&) {
        return number == 2 ? 6 : 0;
    };
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(!env.runRelease(report, error),
        "PF6: the drifted release must fail");
    require(report.compensated && report.compensatedStateProven,
        "PF6: the proven first detach must be compensated: " + error);
    require(env.mutator.isSelected(kStockPwqualityProfileId),
        "PF6: the foreign producer must be preserved");
    require(env.mutator.isSelected(kFicPasswordQualityHookProfileId) &&
            env.mutator.isSelected(kFicPasswordHistoryHookProfileId),
        "PF6: the pre-release FIC state must be restored");
}

void testPF7_preparedRecoveryFailureFailsClosed() {
    ReleaseEnvironment env;
    // History-initial exact-id Prepared crash-leftover; the exact-id
    // compensation primitive is faulted so the recovery must fail closed
    // BEFORE the transition.
    {
        fic::identity::pam::PamManagedPasswordSlotWriter writer(
            env.tree.pamd(), env.journal,
            fic::identity::pam::PamManagedPasswordDomain::History);
        writer.setJournalCompletionFaultHookForTests(
            []() { return false; });
        fic::identity::pam::PamManagedPasswordSlotActivationResult
            activation;
        std::string writerError;
        require(!writer.activateC2Slot(
                    fic::identity::pam::ManagedPasswordSlotRole::
                        HistoryInitial,
                    fic::identity::pam::ManagedPwhistorySlotOptions{
                        std::optional<unsigned>(3), false},
                    activation, writerError),
            "PF7 fixture: the faulted activation must fail");
        require(activation.mutationId != 0,
            "PF7 fixture: an outstanding partial activation is required");
    }
    PamPasswordPackageRelease release = env.makeRelease();
    release.setHistoryC2CompensationFaultHookForTests(
        []() { return false; });
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(!release.run(
                PamPasswordPackageRelease::Mode::Release, report, error),
        "PF7: the failed crash-leftover recovery must fail the release");
    require(error.find("crash-leftover") != std::string::npos,
        "PF7: the diagnostic must classify the crash-leftover failure: " +
            error);
    require(env.mutator.invocations.empty(),
        "PF7: no native mutation may happen");
    require(env.inspect().historyInitialSlotState ==
            ManagedPasswordSlotState::Active,
        "PF7: the leftover state must be left untouched (fail closed)");
}

void testPF8_slotNeutralizationFailureCompensates() {
    ReleaseEnvironment env;
    env.applyOk(true, false);
    // The quality slot neutralization fails right after the native
    // disable was proven; the compensation re-attaches the identity
    // (slot Active first, then the native selection) and proves it.
    bool faultArmed = true;
    PamPasswordPackageRelease release = env.makeRelease();
    release.setQualitySlotFaultHooksForTests(
        [&](std::size_t) { return faultArmed; }, nullptr);
    env.mutator.behavior = [&](std::size_t number, const auto& invocation) {
        if (number == 2 &&
            invocation.profileId == kFicPasswordQualityHookProfileId) {
            // The compensation enable: disarm the write fault so the
            // inverse re-attach can prove the restoration.
            faultArmed = false;
        }
        return 0;
    };
    std::string error;
    PamPasswordPackageRelease::Report report;
    require(!release.run(
                PamPasswordPackageRelease::Mode::Release, report, error),
        "PF8: the release must fail");
    require(report.compensated && report.compensatedStateProven,
        "PF8: the exact-id compensation must prove the pre-release "
        "state: " +
            error);
    const auto snapshot = env.inspect();
    require(snapshot.selections.ficQualitySelected &&
            snapshot.ownership.ficQualityOwned &&
            snapshot.qualitySlotState == ManagedPasswordSlotState::Active,
        "PF8: the owned quality state must be fully restored");
}

} // namespace

int main() {
    const std::vector<std::pair<const char*, void (*)()>> tests = {
        {"P1_noneReleasesAsNoOp", testP1_noneReleasesAsNoOp},
        {"P2_qualityReleasesToNone", testP2_qualityReleasesToNone},
        {"P3_historyInitialReleasesToNone",
            testP3_historyInitialReleasesToNone},
        {"P4_qualityPlusHistoryReleasesToNone",
            testP4_qualityPlusHistoryReleasesToNone},
        {"P5_foreignQualityReleasesAsNoOp",
            testP5_foreignQualityReleasesAsNoOp},
        {"P6_foreignQualityPlusHistory",
            testP6_foreignQualityPlusHistoryReleasesToForeignQuality},
        {"P7_foreignAddedDuringFicQuality",
            testP7_foreignAddedDuringFicQualityReleasesToForeignQuality},
        {"P8_selectedUnownedQuality",
            testP8_selectedUnownedQualityFailsBeforeMutation},
        {"P9_selectedUnownedHistory",
            testP9_selectedUnownedHistoryFailsBeforeMutation},
        {"P10_selectedUnownedInitial",
            testP10_selectedUnownedInitialFailsBeforeMutation},
        {"P11_bothHistoryVariants", testP11_bothHistoryVariantsFailClosed},
        {"P12_selectedNeutralSlot",
            testP12_selectedWithNeutralSlotFailsClosed},
        {"P13_preparedCrashLeftoverRecovered",
            testP13_preparedCrashLeftoverRecoveredByRelease},
        {"P13b_unselectedOwnedFailClosed",
            testP13b_unselectedOwnedSlotFailsClosed},
        {"PF1_firstDetachFails", testPF1_firstDetachFailsNoChange},
        {"PF3_rcZeroMalformedFailClosed",
            testPF3_rcZeroMalformedResultFailsClosed},
        {"PF4_secondDetachFails",
            testPF4_secondDetachFailsAfterFirstSuccess},
        {"PF5_compensationStopsCritical",
            testPF5_compensationFailureStopsCritical},
        {"PF6_foreignDriftMidRelease",
            testPF6_foreignDriftMidReleaseAbortsAndCompensates},
        {"PF7_preparedRecoveryFailure",
            testPF7_preparedRecoveryFailureFailsClosed},
        {"PF8_slotNeutralizationFailure",
            testPF8_slotNeutralizationFailureCompensates},
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
        std::cout << failed << " package release test(s) FAILED\n";
        return 1;
    }
    std::cout << "all pam password package release tests passed\n";
    return 0;
}