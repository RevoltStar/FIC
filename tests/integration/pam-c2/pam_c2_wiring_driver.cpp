// C2 production wiring gate driver: exercises the PRODUCTION wiring path —
//   IDENTITY_ACCESS configuration intent (ModuleConfigFileHandler)
//   -> PamPasswordTopologyCoordinator (production desired-state reader)
//   -> PamPasswordTopologyTransitionExecutor (real pam-auth-update)
//   -> MutationJournal
// and the production PAM rollback backend (undoPamCapability with the joint
// C2 transition, exactly what RollbackExecutor dispatches to).
//
// Built and run ONLY inside a disposable container as root by
// tests/integration/pam-c2/pam_c2_wiring_gate.sh. Never run against a real
// host policy state outside the gate harness.
#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/pam/PamManagedPasswordSlotBootstrap.h"
#include "modules/identity_access/pam/PamPasswordTopologyCoordinator.h"
#include "modules/identity_access/pam/PamPasswordTopologyState.h"
#include "platform/PlatformExecutableResolver.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/PamRollback.h"

#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamPasswordRequestedState;
using fic::identity::pam::PamPasswordTopologyCoordinator;
using fic::rollback::PamRollbackOptions;
using fic::rollback::PamRollbackResult;
using fic::rollback::PamRollbackState;

namespace {

std::unique_ptr<PamPasswordTopologyCoordinator> makeGateCoordinator(
    std::string& error) {
    // Same journal as the production rollback path (daemon journal with the
    // gate override path); executor options carry the managed pwhistory
    // module arguments (the Step 6 option writer is a later stage).
    auto& daemonJournal = fic::rollback::DaemonMutationJournal::instance();
    fic::rollback::MutationJournal* journal = daemonJournal.tryGet(error);
    if (journal == nullptr) {
        error = "PAM mutation journal unavailable: " + error;
        return nullptr;
    }
    fic::platform::PlatformExecutables executables;
    fic::platform::PlatformExecutableSpec spec;
    spec.id = fic::platform::ExecutableId::PamAuthUpdate;
    spec.required = true;
    spec.candidates = {
        std::filesystem::path("/usr/sbin/pam-auth-update"),
        std::filesystem::path("/sbin/pam-auth-update")};
    executables.entries.push_back(spec);
    static fic::platform::PlatformExecutableResolver resolver(executables);
    PamPasswordTopologyCoordinator::Options options;
    options.executorOptions.historyOptions =
        ManagedPwhistorySlotOptions{std::optional<unsigned>(3), false};
    return std::unique_ptr<PamPasswordTopologyCoordinator>(
        new PamPasswordTopologyCoordinator(*journal, resolver, options));
}

PamRollbackOptions::JointTransitionOutcome runTransition(
    bool qualityRequested, bool historyRequested, std::string& error) {
    PamRollbackOptions::JointTransitionOutcome outcome;
    auto coordinator = makeGateCoordinator(error);
    if (!coordinator) {
        outcome.error = error;
        return outcome;
    }
    const PamPasswordRequestedState requested{
        qualityRequested, historyRequested};
    outcome.success = coordinator->transition(requested, error);
    outcome.changedSystemState =
        coordinator->lastResult().changedSystemState;
    outcome.error = error;
    return outcome;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0]
                  << " intent <quality> <history>|apply|rollback <policy>\n";
        return 2;
    }
    const std::string command = argv[1];

    // Production runtime paths: the daemon layout in the disposable gate
    // container (the desired-state reader reads the production config dir).
    if (!fic::core::FicRuntimePaths::isInitialized()) {
        std::string pathsError;
        if (!fic::core::FicRuntimePaths::initializeProduction(pathsError)) {
            std::cerr << "runtime paths initialization failed: "
                      << pathsError << "\n";
            return 2;
        }
    }
    std::filesystem::create_directories("/opt/fic/db");
    std::string hashError;
    if (!CommandHashStore::saveHash("/usr/sbin/pam-auth-update", hashError)) {
        std::cerr << "command hash registration failed: " << hashError
                  << "\n";
        return 2;
    }
    // The daemon journal with the gate path: the SAME journal the C2
    // slot writers and the rollback backend use.
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(
        std::filesystem::path("/var/lib/fic/pam-c2-gate") /
        "mutation-journal.json");

    if (command == "bootstrap") {
        // Package bootstrap of the canonical neutral managed slots (same
        // production component the daemon bootstrap uses).
        fic::identity::pam::PamManagedPasswordSlotBootstrap bootstrap(
            std::filesystem::path("/etc/pam.d"));
        fic::identity::pam::PamManagedPasswordSlotBootstrapResult result;
        if (!bootstrap.run(result, hashError)) {
            std::cerr << "bootstrap failed: " << hashError << "\n";
            return 1;
        }
        for (const auto& outcome : result.slots) {
            std::cout << "bootstrap " << outcome.path << " "
                      << (outcome.status ==
                                  fic::identity::pam::
                                      PamManagedPasswordSlotBootstrapStatus::
                                          Created
                              ? "Created"
                              : "AlreadyPresent")
                      << "\n";
        }
        std::cout << "bootstrap complete="
                  << (result.complete() ? "true" : "false")
                  << " changedSystemState="
                  << (result.changedSystemState ? "true" : "false")
                  << "\n";
        return result.complete() ? 0 : 1;
    }

    if (command == "intent") {
        if (argc < 4) {
            std::cerr << "intent requires <quality> <history>\n";
            return 2;
        }
        // The configuration intent is written through the production
        // ModuleConfigFileHandler exactly like `fic policy enable/disable`.
        ModuleConfigFileHandler config("IDENTITY_ACCESS");
        if (!config.loadConfig()) {
            std::cerr << "could not load IDENTITY_ACCESS.conf\n";
            return 2;
        }
        if (!config.setPolicyStatus("enable_password_quality",
                std::string(argv[2]) == "1" ? "ENABLE" : "DISABLE") ||
            !config.setPolicyStatus("enable_password_history",
                std::string(argv[3]) == "1" ? "ENABLE" : "DISABLE") ||
            !config.saveConfig()) {
            std::cerr << "could not persist the IDENTITY_ACCESS intent\n";
            return 1;
        }
        std::cout << "intent ok quality=" << argv[2]
                  << " history=" << argv[3] << "\n";
        return 0;
    }

    if (command == "inspect") {
        // Read-only production inspection of the physical topology (the
        // same component and defaults the executor uses: /etc/pam.d +
        // /var/lib/pam + journal ownership).
        fic::identity::pam::PamPasswordStateInspectionOptions options;
        fic::identity::pam::PamPasswordTopologySnapshot snapshot;
        auto& daemonJournal = fic::rollback::DaemonMutationJournal::instance();
        fic::rollback::MutationJournal* journal =
            daemonJournal.tryGet(hashError);
        if (journal == nullptr ||
            !fic::identity::pam::inspectPamPasswordTopology(
                options, *journal, snapshot, hashError)) {
            std::cerr << "inspect failed: " << hashError << "\n";
            return 1;
        }
        std::cout << "ficQualitySelected="
                  << (snapshot.selections.ficQualitySelected ? 1 : 0)
                  << "\n";
        std::cout << "ficHistorySelected="
                  << (snapshot.selections.ficHistorySelected ? 1 : 0)
                  << "\n";
        std::cout << "ficHistoryInitialSelected="
                  << (snapshot.selections.ficHistoryInitialSelected ? 1 : 0)
                  << "\n";
        std::cout << "qualitySlotState="
                  << (snapshot.qualitySlotState ==
                              fic::identity::pam::ManagedPasswordSlotState::
                                  Active
                          ? "Active"
                          : snapshot.qualitySlotState ==
                                  fic::identity::pam::
                                      ManagedPasswordSlotState::Neutral
                              ? "Neutral"
                              : "Broken")
                  << "\n";
        std::cout << "historySlotState="
                  << (snapshot.historySlotState ==
                              fic::identity::pam::ManagedPasswordSlotState::
                                  Active
                          ? "Active"
                          : snapshot.historySlotState ==
                                  fic::identity::pam::
                                      ManagedPasswordSlotState::Neutral
                              ? "Neutral"
                              : "Broken")
                  << "\n";
        std::cout << "historyInitialSlotState="
                  << (snapshot.historyInitialSlotState ==
                              fic::identity::pam::ManagedPasswordSlotState::
                                  Active
                          ? "Active"
                          : snapshot.historyInitialSlotState ==
                                  fic::identity::pam::
                                      ManagedPasswordSlotState::Neutral
                              ? "Neutral"
                              : "Broken")
                  << "\n";
        std::cout << "foreignQualityProducer="
                  << (snapshot.foreignQualityProducer ? 1 : 0) << "\n";
        std::cout << "ficQualityOwned="
                  << (snapshot.ownership.ficQualityOwned ? 1 : 0) << "\n";
        std::cout << "ficHistoryOwned="
                  << (snapshot.ownership.ficHistoryOwned ? 1 : 0) << "\n";
        std::cout << "ficHistoryInitialOwned="
                  << (snapshot.ownership.ficHistoryInitialOwned ? 1 : 0)
                  << "\n";
        std::cout << "topologyClass="
                  << (snapshot.classification.topologyClass ==
                              fic::identity::pam::PamPasswordTopologyClass::
                                  FicQuality
                          ? "FicQuality"
                          : snapshot.classification.topologyClass ==
                                  fic::identity::pam::
                                      PamPasswordTopologyClass::
                                          FicHistoryInitial
                              ? "FicHistoryInitial"
                              : snapshot.classification.topologyClass ==
                                      fic::identity::pam::
                                          PamPasswordTopologyClass::
                                              FicQualityPlusFicHistory
                                  ? "FicQualityPlusFicHistory"
                                  : snapshot.classification.topologyClass ==
                                          fic::identity::pam::
                                              PamPasswordTopologyClass::
                                                  ForeignQuality
                                      ? "ForeignQuality"
                                      : snapshot.classification.topologyClass ==
                                              fic::identity::pam::
                                                  PamPasswordTopologyClass::None
                                          ? "None"
                                          : "Other")
                  << "\n";
        return 0;
    }

    if (command == "apply") {
        // The FULL production wiring: the coordinator reads the joint
        // requested state from the configuration intent and performs ONE
        // semantic C2 transition.
        auto coordinator = makeGateCoordinator(hashError);
        if (!coordinator) {
            std::cerr << "coordinator unavailable: " << hashError << "\n";
            return 2;
        }
        std::string error;
        const bool ok = coordinator->applyJointRequestedState(error);
        const auto& result = coordinator->lastResult();
        std::cout << "success=" << (result.success ? 1 : 0) << "\n";
        std::cout << "changedSystemState="
                  << (result.changedSystemState ? 1 : 0) << "\n";
        std::cout << "executedActions=";
        for (const std::string& action : result.executedActions) {
            std::cout << action << ",";
        }
        std::cout << "\n";
        std::cout << "error=" << error << "\n";
        return ok ? 0 : 1;
    }

    if (command == "rollback") {
        if (argc < 3) {
            std::cerr << "rollback requires <policy>\n";
            return 2;
        }
        const std::string policyName = argv[2];
        std::string error;
        auto* journal =
            fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        if (journal == nullptr) {
            std::cerr << "journal unavailable: " << error << "\n";
            return 2;
        }
        const std::vector<fic::rollback::MutationRecord> active =
            journal->activeRecords({"IDENTITY_ACCESS", "PAM", policyName});
        if (active.empty()) {
            std::cout << "rollback NothingToDo no active records\n";
            return 0;
        }
        bool allReleased = true;
        for (const fic::rollback::MutationRecord& record : active) {
            const auto* payload =
                std::get_if<fic::rollback::UndoDisablePamCapability>(
                    &record.undo.payload);
            if (payload == nullptr) {
                std::cerr << "record " << record.id
                          << " has a foreign undo payload\n";
                allReleased = false;
                continue;
            }
            // Production PAM rollback backend (the exact function
            // RollbackExecutor dispatches to for PAM records).
            PamRollbackOptions options;
            options.jointTransition =
                [](bool qualityRequested, bool historyRequested,
                    std::string& transitionError) {
                    return runTransition(qualityRequested, historyRequested,
                        transitionError);
                };
            options.jointRequestedState =
                [](bool& qualityRequested, bool& historyRequested,
                    std::string& intentError) {
                    PamPasswordRequestedState requested;
                    if (!fic::identity::pam::readJointPasswordConfigIntent(
                            requested, intentError)) {
                        return false;
                    }
                    qualityRequested = requested.qualityRequested;
                    historyRequested = requested.historyRequested;
                    return true;
                };
            const PamRollbackResult result = fic::rollback::undoPamCapability(
                options, record.id, *payload);
            const char* stateName = "Failed";
            if (result.state == PamRollbackState::Released) {
                stateName = "Released";
            } else if (result.state == PamRollbackState::AlreadyReleased) {
                stateName = "AlreadyReleased";
            } else if (result.state == PamRollbackState::Conflict) {
                stateName = "Conflict";
            }
            std::cout << "rollback record=" << record.id << " state="
                      << stateName << " message=" << result.message << "\n";
            if (result.state != PamRollbackState::Released &&
                result.state != PamRollbackState::AlreadyReleased) {
                allReleased = false;
            }
        }
        return allReleased ? 0 : 1;
    }

    std::cerr << "unknown command: " << command << "\n";
    return 2;
}

