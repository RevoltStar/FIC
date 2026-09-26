// C2 functional gate driver: runs the PRODUCTION C2 password topology
// components (PamManagedPasswordSlotBootstrap, PamPasswordTopologyState
// inspection, PamManagedPasswordSlotWriter, PamPasswordTopologyTransition
// Executor) against the REAL system paths (/etc/pam.d, /var/lib/pam) with
// the real pam-auth-update and the real VerifiedProcessExecutor path.
//
// Intended to be built and run INSIDE a disposable container as root by
// tests/integration/pam-c2/pam_c2_gate.sh. This is NOT a CTest and must
// never run against a real host policy state outside the gate harness.
#include "modules/identity_access/pam/PamManagedPasswordSlotBootstrap.h"
#include "modules/identity_access/pam/PamPasswordTopologyState.h"
#include "modules/identity_access/pam/PamPasswordTopologyTransitionExecutor.h"
#include "platform/PlatformExecutableResolver.h"
#include "rollback/MutationJournal.h"
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>

using fic::identity::pam::ManagedPasswordSlotState;
using fic::identity::pam::ManagedPwhistorySlotOptions;
using fic::identity::pam::PamManagedPasswordSlotBootstrap;
using fic::identity::pam::PamPasswordStateInspectionOptions;
using fic::identity::pam::PamPasswordTopologyClass;
using fic::identity::pam::PamPasswordTopologyExecutorOptions;
using fic::identity::pam::PamPasswordTopologySnapshot;
using fic::identity::pam::PamPasswordTopologyTransitionExecutor;
using fic::identity::pam::PamPasswordTransitionResult;
using fic::rollback::MutationJournal;

namespace {

const char* topologyClassName(PamPasswordTopologyClass topologyClass) {
    switch (topologyClass) {
    case PamPasswordTopologyClass::None:
        return "None";
    case PamPasswordTopologyClass::FicQuality:
        return "FicQuality";
    case PamPasswordTopologyClass::FicHistoryInitial:
        return "FicHistoryInitial";
    case PamPasswordTopologyClass::FicQualityPlusFicHistory:
        return "FicQualityPlusFicHistory";
    case PamPasswordTopologyClass::ForeignQuality:
        return "ForeignQuality";
    case PamPasswordTopologyClass::ForeignQualityPlusFicHistory:
        return "ForeignQualityPlusFicHistory";
    case PamPasswordTopologyClass::ForeignQualityPlusFicQuality:
        return "ForeignQualityPlusFicQuality";
    case PamPasswordTopologyClass::Ambiguous:
        return "Ambiguous";
    }
    return "Unknown";
}

const char* slotStateName(ManagedPasswordSlotState state) {
    switch (state) {
    case ManagedPasswordSlotState::Neutral:
        return "Neutral";
    case ManagedPasswordSlotState::Active:
        return "Active";
    case ManagedPasswordSlotState::Broken:
        return "Broken";
    }
    return "Unknown";
}

} // namespace

int runExecutorCommand(const std::string& command, int argc, char** argv);

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0]
                  << " bootstrap|inspect|transition <quality> <history>\n";
        return 2;
    }
    const std::string command = argv[1];

    const std::filesystem::path configDirectory = "/etc/pam.d";
    const std::filesystem::path stateDirectory = "/var/lib/pam";
    const std::filesystem::path journalDirectory =
        "/var/lib/fic/pam-c2-gate";
    const std::filesystem::path journalPath =
        journalDirectory / "mutation-journal.json";

    std::error_code fsError;
    std::filesystem::create_directories(journalDirectory, fsError);
    if (fsError) {
        std::cerr << "cannot create " << journalDirectory << ": "
                  << fsError.message() << "\n";
        return 2;
    }
    MutationJournal journal(journalPath);
    std::string error;
    if (!journal.initializeOrLoad(error)) {
        std::cerr << "journal initialization failed: " << error << "\n";
        return 2;
    }

    if (command == "bootstrap") {
        PamManagedPasswordSlotBootstrap bootstrap(configDirectory);
        fic::identity::pam::PamManagedPasswordSlotBootstrapResult result;
        if (!bootstrap.run(result, error)) {
            std::cerr << "bootstrap failed: " << error << "\n";
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
    return runExecutorCommand(command, argc, argv);
}

int runExecutorCommand(const std::string& command, int argc, char** argv) {
    // The production components (VerifiedProcessExecutor path) expect the
    // daemon runtime paths to be initialized; initialize them to the
    // production layout (the gate runs as root inside a disposable
    // container, exactly like the daemon would).
    if (!fic::core::FicRuntimePaths::isInitialized()) {
        std::string pathsError;
        if (!fic::core::FicRuntimePaths::initializeProduction(pathsError)) {
            std::cerr << "runtime paths initialization failed: "
                      << pathsError << "\n";
            return 2;
        }
    }
    // Register the executable hash exactly like the daemon does before
    // first privileged execution (VerifiedProcessExecutor verifies it).
    std::filesystem::create_directories("/opt/fic/db");
    std::string hashError;
    if (!CommandHashStore::saveHash("/usr/sbin/pam-auth-update",
            hashError)) {
        std::cerr << "command hash registration failed: " << hashError
                  << "\n";
        return 2;
    }
    // Production-style executable resolution (the same resolver the
    // daemon uses, with the distro pam-auth-update candidates).
    fic::platform::PlatformExecutables executables;
    fic::platform::PlatformExecutableSpec spec;
    spec.id = fic::platform::ExecutableId::PamAuthUpdate;
    spec.required = true;
    spec.candidates = {
        std::filesystem::path("/usr/sbin/pam-auth-update"),
        std::filesystem::path("/sbin/pam-auth-update")};
    executables.entries.push_back(spec);
    fic::platform::PlatformExecutableResolver resolver(executables);

    const std::filesystem::path configDirectory = "/etc/pam.d";
    const std::filesystem::path stateDirectory = "/var/lib/pam";
    const std::filesystem::path journalPath =
        std::filesystem::path("/var/lib/fic/pam-c2-gate") /
        "mutation-journal.json";
    MutationJournal journal(journalPath);
    std::string error;
    if (!journal.initializeOrLoad(error)) {
        std::cerr << "journal initialization failed: " << error << "\n";
        return 2;
    }

    PamPasswordTopologyExecutorOptions options;
    options.historyOptions =
        ManagedPwhistorySlotOptions{std::optional<unsigned>(3), false};
    PamPasswordTopologyTransitionExecutor executor(
        journal, resolver, options, configDirectory, stateDirectory);

    if (command == "inspect") {
        PamPasswordStateInspectionOptions inspectionOptions;
        inspectionOptions.configDirectory = configDirectory;
        inspectionOptions.stateDirectory = stateDirectory;
        PamPasswordTopologySnapshot snapshot;
        if (!fic::identity::pam::inspectPamPasswordTopology(
                inspectionOptions, journal, snapshot, error)) {
            std::cerr << "inspect failed: " << error << "\n";
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
                  << slotStateName(snapshot.qualitySlotState) << "\n";
        std::cout << "historySlotState="
                  << slotStateName(snapshot.historySlotState) << "\n";
        std::cout << "historyInitialSlotState="
                  << slotStateName(snapshot.historyInitialSlotState)
                  << "\n";
        std::cout << "qualitySlotMutationId="
                  << snapshot.qualitySlotMutationId << "\n";
        std::cout << "historySlotMutationId="
                  << snapshot.historySlotMutationId << "\n";
        std::cout << "historyInitialSlotMutationId="
                  << snapshot.historyInitialSlotMutationId << "\n";
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
                  << topologyClassName(snapshot.classification.topologyClass)
                  << "\n";
        std::cout << "classificationValid="
                  << (snapshot.classification.valid ? 1 : 0) << "\n";
        std::cout << "safetySafe=" << (snapshot.safety.safe ? 1 : 0)
                  << "\n";
        std::cout << "coherenceError=" << snapshot.coherenceError << "\n";
        return 0;
    }

    if (command == "transition") {
        if (argc < 4) {
            std::cerr << "transition requires <quality> <history>\n";
            return 2;
        }
        const bool quality = std::string(argv[2]) == "1";
        const bool history = std::string(argv[3]) == "1";
        PamPasswordTransitionResult result;
        const bool success =
            executor.transition(quality, history, result, error);
        std::cout << "success=" << (result.success ? 1 : 0) << "\n";
        std::cout << "changedSystemState="
                  << (result.changedSystemState ? 1 : 0) << "\n";
        std::cout << "compensated=" << (result.compensated ? 1 : 0)
                  << "\n";
        std::cout << "compensatedStateProven="
                  << (result.compensatedStateProven ? 1 : 0) << "\n";
        std::cout << "topologyBefore="
                  << topologyClassName(result.topologyBefore) << "\n";
        std::cout << "topologyAfter="
                  << topologyClassName(result.topologyAfter) << "\n";
        std::cout << "executedActions=";
        for (const std::string& action : result.executedActions) {
            std::cout << action << ",";
        }
        std::cout << "\n";
        std::cout << "error=" << result.error << "\n";
        if (!success && error != result.error) {
            std::cout << "outError=" << error << "\n";
        }
        return result.success ? 0 : 1;
    }

    std::cerr << "unknown command: " << command << "\n";
    return 2;
}
