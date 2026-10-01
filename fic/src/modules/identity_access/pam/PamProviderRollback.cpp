#include "modules/identity_access/pam/PamProviderRollback.h"

#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"
#include "modules/identity_access/pam/PamProviderManagedLock.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <utility>

namespace fic::identity::pam {

namespace {

using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoOwnPamProviderContainer;
using fic::rollback::UndoRemovePamProviderManagedEntry;
using fic::rollback::UndoRemovePamProviderManagedFlag;

PamProviderRollbackResult conflictResult(const std::string& message) {
    PamProviderRollbackResult result;
    result.ok = false;
    result.conflict = true;
    result.message = message;
    return result;
}

PamProviderRollbackResult failureResult(const std::string& message,
                                        bool changedSystemState = false) {
    PamProviderRollbackResult result;
    result.ok = false;
    result.changedSystemState = changedSystemState;
    result.message = message;
    return result;
}

PamProviderRollbackResult nothingToDoResult(const std::string& message) {
    PamProviderRollbackResult result;
    result.ok = true;
    result.nothingToDo = true;
    result.message = message;
    return result;
}

PamProviderRollbackResult successResult(const std::string& message,
                                        bool changedSystemState) {
    PamProviderRollbackResult result;
    result.ok = true;
    result.changedSystemState = changedSystemState;
    result.message = message;
    return result;
}

fic::rollback::PamProviderBlockPlacementContract contractOf(
    PamProviderBlockPlacementRequest request) {
    return request == PamProviderBlockPlacementRequest::Beginning
        ? fic::rollback::PamProviderBlockPlacementContract::Beginning
        : fic::rollback::PamProviderBlockPlacementContract::End;
}

bool samePath(const std::filesystem::path& left,
              const std::filesystem::path& right) {
    return std::filesystem::path(left).lexically_normal() ==
        std::filesystem::path(right).lexically_normal();
}

// Current-platform capability match for a journaled (provider, configPath)
// identity: the ONLY capability shape FIC ever reads or mutates through a
// journal path is a ProviderConfigFile capability whose lexically-normal
// config path and provider descriptor name both match. Shared by the
// entry/flag route proof and the container provenance proof (one identity
// model — no second, weaker match).
const fic::platform::PamCapabilityConfig* findProviderConfigFileCapability(
    const PamProviderRollbackOptions& options,
    const std::string& providerName,
    const std::string& configPath,
    std::string& message) {
    for (const fic::platform::PamCapabilityConfig& candidate :
         options.platform.capabilities) {
        if (candidate.configurationMode ==
                fic::platform::PamCapabilityConfigurationMode::
                    ProviderConfigFile &&
            samePath(candidate.configPath, configPath) &&
            std::string(pamProviderDescriptor(candidate.provider).name) ==
                providerName) {
            return &candidate;
        }
    }
    message = "текущая platform profile не подтверждает identity "
              "journal-записи (provider '" + providerName +
              "', config path '" + configPath + "'): rollback запрещён";
    return nullptr;
}

// Payload-side route proof (Step 7F platform identity proof): the CURRENT
// platform must confirm the journaled provider identity, configuration
// path, managed key, placement contract, CANONICAL policy identity and
// NATIVE option syntax through the SAME typed routing helper the apply
// path uses. The journal path is never executed blindly.
std::optional<PamProviderRollbackRoute> routeForPayload(
    const PamProviderRollbackOptions& options,
    const std::string& providerName,
    const std::string& configPath,
    const std::string& policyName,
    const std::string& managedKey,
    PamNativeOptionSyntax expectedSyntax,
    fic::rollback::PamProviderBlockPlacementContract placementContract,
    std::string& message) {
    const fic::platform::PamCapabilityConfig* capability =
        findProviderConfigFileCapability(options, providerName, configPath,
                                         message);
    if (capability == nullptr) {
        return std::nullopt;
    }
    const PamProviderDescriptor descriptor =
        pamProviderDescriptor(capability->provider);
    for (const PamProviderPolicyBinding& binding : descriptor.policies) {
        if (binding.option != managedKey) {
            continue;
        }
        const std::optional<PamProviderBlockPlacementRequest> placement =
            pamProviderManagedEntryPlacement(descriptor, *capability, binding,
                                             binding.feature);
        if (!placement.has_value()) {
            continue;
        }
        if (contractOf(*placement) != placementContract) {
            message = "placement contract journal-записи не совпадает с "
                      "текущим контрактом platform profile: rollback "
                      "запрещён";
            return std::nullopt;
        }
        // Canonical policy identity: the routing binding's managed feature
        // must be the typed feature of the journaled canonical policy name.
        // A structurally valid journal can never bind a canonical key to a
        // wrong policy identity.
        const char* canonicalPolicyName =
            pamProviderManagedFeaturePolicyName(binding.feature);
        if (canonicalPolicyName == nullptr ||
            policyName != canonicalPolicyName) {
            message = "canonical policy identity journal-записи ('" +
                policyName + "') не совпадает с managed feature маршрута ('" +
                (canonicalPolicyName != nullptr ? canonicalPolicyName : "?") +
                "') для managed key '" + managedKey + "': rollback запрещён";
            return std::nullopt;
        }
        // Native option syntax: an assignment key can never travel through
        // a flag payload and vice versa.
        if (binding.syntax != expectedSyntax) {
            message = "native option syntax journal-записи не совпадает с "
                      "синтаксисом managed key '" + managedKey +
                      "' в текущем platform profile: rollback запрещён";
            return std::nullopt;
        }
        PamProviderRollbackRoute route;
        route.descriptor = descriptor;
        route.capability = capability;
        route.binding = binding;
        route.feature = binding.feature;
        route.placement = *placement;
        route.configPath = capability->configPath;
        return route;
    }
    message = "текущая platform profile не маршрутизирует managed key '" +
        managedKey + "' провайдера '" + providerName +
        "' через managed provider configuration: rollback запрещён";
    return std::nullopt;
}

// Active FIC-created container provenance record for the given
// provider/config path (Step 7B durable provenance, independent of any
// entry record lifecycle).
std::optional<MutationRecord> findActiveContainerRecord(
    MutationJournal& journal,
    const std::string& providerName,
    const std::string& configPath,
    std::string& error) {
    std::optional<MutationRecord> found;
    for (const MutationRecord& record : journal.records()) {
        if (!record.isActive()) {
            continue;
        }
        const auto* payload =
            std::get_if<UndoOwnPamProviderContainer>(&record.undo.payload);
        if (payload == nullptr ||
            payload->providerName != providerName ||
            !samePath(payload->configPath, configPath)) {
            continue;
        }
        if (found.has_value()) {
            error = "несколько активных container provenance записей для " +
                configPath + " (fail closed)";
            return std::nullopt;
        }
        found = record;
    }
    return found;
}

// Completes the container provenance lifecycle after a DURABLE release:
//   * container deleted durably (or proven durably absent on retry)
//                                       -> RolledBack (Step 7F §38);
//   * foreign-only final state written  -> Detached (FIC forever gives up
//                                         any right to unlink this
//                                         container, §39);
//   * no provenance / unproven          -> record untouched (§40).
// Journal ownership is NEVER resolved before the durability proof.
PamProviderRollbackResult resolveContainerRecordAfterDurableRelease(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord* containerRecord,
    bool detachInsteadOfRollback,
    std::string& error) {
    if (containerRecord == nullptr) {
        return successResult("container provenance отсутствует; файл "
                             "оставлен как есть",
                             /*changedSystemState=*/false);
    }
    if (options.simulateContainerJournalResolutionFailure &&
        options.simulateContainerJournalResolutionFailure()) {
        error = "simulated container journal resolution failure (test seam): "
                "the physical release is durable, the provenance record stays "
                "recoverable";
        return failureResult(error, /*changedSystemState=*/true);
    }
    std::string journalError;
    if (!journal.setStatus(containerRecord->id,
                           detachInsteadOfRollback
                               ? MutationStatus::Detached
                               : MutationStatus::RolledBack,
                           journalError)) {
        error = "physical release is durable, but the container provenance "
                "journal record " + std::to_string(containerRecord->id) +
                " could not be resolved: " + journalError;
        return failureResult(error, /*changedSystemState=*/true);
    }
    return successResult(
        std::string("container provenance resolved as ") +
            (detachInsteadOfRollback ? "Detached" : "RolledBack"),
        /*changedSystemState=*/true);
}

// Shared typed refusal mapping of a failed release write: a snapshot CAS
// failure is a typed conflict (nothing was replaced), everything else is a
// failure with the changedSystemState flag set (the write may have
// installed).
PamProviderRollbackResult releaseWriteOutcome(
    const PamProviderContainerWriteResult& write,
    const std::string& error,
    const std::string& description) {
    if (write.stale) {
        return conflictResult(
            "snapshot precondition failed during the release write (the "
            "file changed concurrently): nothing was replaced, retry the "
            "rollback");
    }
    return failureResult(description + ": " + error,
                         /*changedSystemState=*/true);
}

// Common post-release step for both the assignment and the flag rollback:
// installs the released content (snapshot-CAS write), then resolves the
// container provenance. `read` is the FRESH pre-release trusted read;
// `preReleaseParse` is its strict parse (the Prepared container creation
// witness is proven against the PRE-release physical state, never against
// content this mutation would create). `newContent` is the pure release
// transform result.
PamProviderRollbackResult finishOwnershipRelease(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const std::string& providerName,
    const std::filesystem::path& path,
    const PamProviderContainerReadResult& read,
    const PamProviderBlockParseResult& preReleaseParse,
    const std::string& newContent,
    const std::string& releaseDescription) {
    // NOTE: no early "already equal" return here — the container final
    // sweep passes the current content on purpose so an empty FIC-created
    // container is conditionally deleted and a foreign-only container has
    // its provenance detached.
    const PamProviderBlockParseResult postParse =
        parsePamProviderManagedBlock(newContent);
    if (!postParse.ok) {
        return failureResult("released content failed the strict parse "
                             "(defensive): " + postParse.error);
    }
    const bool blockRemoved = !postParse.view.present;

    std::string error;
    std::optional<MutationRecord> containerRecord =
        findActiveContainerRecord(journal, providerName, path.string(),
                                  error);
    if (!containerRecord.has_value() && !error.empty()) {
        return failureResult(error);
    }

    // Container provenance legalization (Step 7F §42): a PREPARED container
    // provenance counts as FIC-created ONLY with the exact pre-existing
    // journal↔physical creation witness proven against the PRE-release
    // parse. Existence of the path alone legalizes nothing.
    bool containerCreatedProven = false;
    if (containerRecord.has_value()) {
        if (containerRecord->status == MutationStatus::Applied) {
            containerCreatedProven = true;
        } else if (containerRecord->status == MutationStatus::Prepared) {
            std::string witnessError;
            if (!provePamProviderPreparedContainerWitness(
                    journal, providerName, path, preReleaseParse,
                    witnessError)) {
                return conflictResult(
                    "container provenance is Prepared but the strict "
                    "creation witness proof failed: " + witnessError);
            }
            std::string journalError;
            if (!journal.setStatus(containerRecord->id,
                                   MutationStatus::Applied, journalError)) {
                return failureResult(
                    "Prepared container provenance witness proven, but the "
                    "record could not be reconciled to Applied: " +
                    journalError);
            }
            containerCreatedProven = true;
        } else {
            return conflictResult(
                "container provenance record is RollbackFailed: ambiguous "
                "FIC-created container state (fail closed)");
        }
    }

    if (!blockRemoved) {
        // Other FIC entries survive: the block is rewritten, the container
        // provenance stays active exactly as it was (Step 7F §41).
        PamProviderContainerWriteResult write =
            PamProviderManagedBlockFile::writeMutation(
                path, /*containerWasAbsent=*/false, read.snapshot, newContent,
                error);
        if (!write.ok) {
            return releaseWriteOutcome(write, error, releaseDescription);
        }
        return successResult(releaseDescription + ": FIC entry удалена, "
                             "блок сохраняет другие FIC entries",
                             /*changedSystemState=*/true);
    }

    if (!containerCreatedProven) {
        // RetainUnproven (§40): no container provenance — only the FIC
        // serialization is removed; the (pre-existing) file stays and is
        // never unlinked.
        PamProviderContainerWriteResult write =
            PamProviderManagedBlockFile::writeMutation(
                path, /*containerWasAbsent=*/false, read.snapshot, newContent,
                error);
        if (!write.ok) {
            return releaseWriteOutcome(write, error, releaseDescription);
        }
        return successResult(releaseDescription + ": FIC serialization "
                             "удалена, файл сохранён (container provenance "
                             "не доказана — файл никогда не удаляется)",
                             /*changedSystemState=*/true);
    }

    if (!newContent.empty()) {
        // RetainForeignContent (§39): the FIC-created container keeps
        // foreign bytes — remove only the FIC serialization, then detach
        // the provenance forever after the durable write.
        PamProviderContainerWriteResult write =
            PamProviderManagedBlockFile::writeMutation(
                path, /*containerWasAbsent=*/false, read.snapshot, newContent,
                error);
        if (!write.ok) {
            return releaseWriteOutcome(write, error, releaseDescription);
        }
        PamProviderRollbackResult resolution =
            resolveContainerRecordAfterDurableRelease(
                options, journal, &*containerRecord,
                /*detachInsteadOfRollback=*/true, error);
        if (!resolution.ok) {
            return resolution;
        }
        return successResult(releaseDescription + ": FIC serialization "
                             "удалена; foreign bytes сохранены, container "
                             "provenance Detached",
                             /*changedSystemState=*/true);
    }

    // Last-entry + empty (§30 key optimization): the released content is
    // EMPTY and the container creation is proven. The file currently
    // consists only of FIC serialization, so instead of writing an empty
    // file and unlinking it afterwards (a wider crash window), the exact
    // CURRENT captured snapshot is deleted directly through the
    // snapshot-bound conditional delete.
    if (read.state == PamProviderContainerState::PreExisting) {
        AtomicRemoveResult removal;
        std::string removeError;
        const bool removalOk = AtomicFileWriter::removeIfCurrentState(
            path.string(), read.snapshot, &removeError, &removal);
        if (!removalOk && !removal.removed) {
            return failureResult("conditional delete failed before any "
                                 "removal: " + removeError);
        }
        if (removal.preconditionFailed) {
            return conflictResult(
                "stale conditional delete: the container no longer matches "
                "the captured snapshot; the replacement was NOT touched (" +
                removeError + ")");
        }
        if (!removalOk || (removal.removed && !removal.durabilityConfirmed)) {
            // The unlink installed, but the durability barrier failed: the
            // journal ownership is NOT resolved and every record stays
            // recoverable (Step 7F §35).
            return failureResult(
                "container unlink installed but the parent directory fsync "
                "failed: the removal is NOT durable, journal records remain "
                "recoverable (" + removeError + ")",
                /*changedSystemState=*/true);
        }
        PamProviderRollbackResult resolution =
            resolveContainerRecordAfterDurableRelease(
                options, journal, &*containerRecord,
                /*detachInsteadOfRollback=*/false, error);
        if (!resolution.ok) {
            return resolution;
        }
        return successResult(releaseDescription + ": последний FIC entry "
                             "удален; FIC-created пустой контейнер удален "
                             "через exact snapshot-bound conditional delete",
                             /*changedSystemState=*/true);
    }

    // The container is already absent (crash after the conditional delete
    // but before the journal resolution): the durable absence is re-proven
    // and the provenance record is resolved (Step 7F §36/§38/§85 retry).
    std::string absenceError;
    if (!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
            path.string(), &absenceError)) {
        return failureResult(
            "absence recovery failed (fail closed, the appearing object was "
            "never touched): " + absenceError);
    }
    PamProviderRollbackResult resolution =
        resolveContainerRecordAfterDurableRelease(
            options, journal, &*containerRecord,
            /*detachInsteadOfRollback=*/false, error);
    if (!resolution.ok) {
        return resolution;
    }
    return successResult(releaseDescription + ": физическое состояние "
                         "отсутствует (crash после release); durable "
                         "absence доказана, lifecycle завершен",
                         /*changedSystemState=*/true);
}

// Retry path when the primary file is PROVEN absent at rollback entry:
// the policy entry itself is already released; only the container
// provenance lifecycle may need completion.
PamProviderRollbackResult resolveAlreadyReleasedState(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const std::string& providerName,
    const std::filesystem::path& path) {
    std::string error;
    std::optional<MutationRecord> containerRecord =
        findActiveContainerRecord(journal, providerName, path.string(),
                                  error);
    if (!containerRecord.has_value()) {
        if (!error.empty()) {
            return failureResult(error);
        }
        return nothingToDoResult("exact FIC state физически отсутствует "
                                 "(externally released state); container "
                                 "provenance также отсутствует");
    }
    if (containerRecord->status != MutationStatus::Applied) {
        return conflictResult(
            "physical primary is absent while the container provenance "
            "record is not Applied (ambiguous externally deleted container; "
            "fail closed)");
    }
    std::string absenceError;
    if (!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
            path.string(), &absenceError)) {
        return failureResult(
            "absence recovery failed (fail closed, the appearing object was "
            "never touched): " + absenceError);
    }
    PamProviderRollbackResult resolution =
        resolveContainerRecordAfterDurableRelease(
            options, journal, &*containerRecord,
            /*detachInsteadOfRollback=*/false, error);
    if (!resolution.ok) {
        return resolution;
    }
    return nothingToDoResult("exact FIC state физически отсутствует; "
                             "durable absence доказана, container "
                             "provenance resolved as RolledBack");
}

// Assignment rollback core (status matrix §6-§11).
PamProviderRollbackResult undoEntryUnlocked(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedEntry& undo) {
    std::string routeMessage;
    const std::optional<PamProviderRollbackRoute> route = routeForPayload(
        options, undo.providerName, undo.configPath, undo.policyName,
        undo.managedKey, PamNativeOptionSyntax::Assignment, undo.placement,
        routeMessage);
    if (!route.has_value()) {
        return conflictResult(routeMessage);
    }
    const std::filesystem::path path(undo.configPath);

    std::string error;
    PamProviderContainerReadResult read =
        PamProviderManagedBlockFile::readForMutation(
            path, PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */, error);
    if (!read.ok) {
        return failureResult("не удалось выполнить trusted read provider "
                             "primary '" + undo.configPath + "': " + error);
    }
    if (read.state == PamProviderContainerState::Absent) {
        // The whole primary is gone: the entry is externally released; only
        // the container lifecycle may need completion.
        return resolveAlreadyReleasedState(options, journal,
                                           undo.providerName, path);
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        // Malformed/foreign FIC marker namespace: never "repair" drift
        // before rollback (fail closed, §7).
        return conflictResult("строгий parse provider primary не удался "
                              "(поврежденные FIC markers): " + parse.error);
    }

    // Ownership expectation per status (§6/§10/§11).
    PamProviderOwnershipExpectation expectation;
    expectation.provider = undo.providerName;
    expectation.policy = undo.policyName;
    expectation.managedKey = undo.managedKey;
    expectation.body = undo.appliedBody;
    expectation.previousBody = undo.previousAppliedBody;
    expectation.mutationId = record.id;

    const PamProviderJournalMutationStatus classifyStatus =
        record.status == MutationStatus::Prepared
        ? PamProviderJournalMutationStatus::Prepared
        : PamProviderJournalMutationStatus::Applied;
    const PamProviderJournalBindingResult binding =
        classifyPamProviderJournalBinding(classifyStatus, parse, expectation);
    if (!binding.ok) {
        return conflictResult("ownership classification не удалась: " +
                              binding.error);
    }

    std::string releaseBody;
    switch (binding.state) {
    case PamProviderJournalBindingState::AppliedExact:
    case PamProviderJournalBindingState::PreparedFreshTargetPresent:
    case PamProviderJournalBindingState::PreparedUpdateTargetPresent:
        // RollbackFailed (§11) and Applied (§6) treat appliedBody as the
        // ownership target state; Prepared refresh crash recovery releases
        // the durable target side (§10).
        releaseBody = undo.appliedBody;
        break;
    case PamProviderJournalBindingState::PreparedUpdatePreviousPresent:
        // Prepared refresh on the PREVIOUS side (§10): rollback releases
        // the durable previous side — the disable goal is to release policy
        // ownership entirely, not to finish the target first.
        releaseBody = undo.previousAppliedBody;
        break;
    case PamProviderJournalBindingState::AppliedMissing:
    case PamProviderJournalBindingState::PreparedFreshAbsent:
        // Externally released state (§8/§9/§44): nothing is reconstructed.
        return resolveAlreadyReleasedState(options, journal,
                                           undo.providerName, path);
    case PamProviderJournalBindingState::AppliedDrifted:
        return conflictResult("physical entry drift (wrong mutation id, "
                              "изменённый body или другой identity): "
                              "rollback запрещён");
    case PamProviderJournalBindingState::PreparedConflict:
        return conflictResult("physical state не совпадает ни с previous, "
                              "ни с target ownership Prepared-записи: "
                              "rollback запрещён");
    }

    PamProviderOwnershipExpectation removalExpectation;
    removalExpectation.provider = undo.providerName;
    removalExpectation.policy = undo.policyName;
    removalExpectation.managedKey = undo.managedKey;
    removalExpectation.body = releaseBody;
    removalExpectation.mutationId = record.id;
    const PamProviderRemovalResult removal = removePamProviderManagedEntry(
        read.content, removalExpectation, route->placement);
    if (!removal.ok) {
        return conflictResult("удаление exact owned entry отклонено: " +
                              removal.error);
    }
    if (removal.outcome == PamProviderRemovalResult::Outcome::AlreadyAbsent) {
        // Concurrent external release between read and transform: retry
        // re-classifies.
        return resolveAlreadyReleasedState(options, journal,
                                           undo.providerName, path);
    }

    return finishOwnershipRelease(
        options, journal, undo.providerName, path, read, parse,
        removal.content,
        "Assignment rollback (record " + std::to_string(record.id) + ")");
}

// Set-only flag rollback core (status matrix §17-§24).
PamProviderRollbackResult undoFlagUnlocked(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& undo) {
    std::string routeMessage;
    const std::optional<PamProviderRollbackRoute> route = routeForPayload(
        options, undo.providerName, undo.configPath, undo.policyName,
        undo.managedKey, PamNativeOptionSyntax::Flag, undo.placement,
        routeMessage);
    if (!route.has_value()) {
        return conflictResult(routeMessage);
    }
    const std::filesystem::path path(undo.configPath);

    std::string error;
    PamProviderContainerReadResult read =
        PamProviderManagedBlockFile::readForMutation(
            path, PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */, error);
    if (!read.ok) {
        return failureResult("не удалось выполнить trusted read provider "
                             "primary '" + undo.configPath + "': " + error);
    }
    if (read.state == PamProviderContainerState::Absent) {
        return resolveAlreadyReleasedState(options, journal,
                                           undo.providerName, path);
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        return conflictResult("строгий parse provider primary не удался "
                              "(поврежденные FIC markers): " + parse.error);
    }

    // Authorized ownership candidates per status (§17/§18/§19):
    // Applied/RollbackFailed — target candidate ONLY (previousSuppressionIds
    // is historical provenance); Prepared — the target candidate plus, when
    // the previous state is journaled, the previous candidate.
    PamProviderFlagOwnedStateCandidate targetCandidate;
    targetCandidate.entryKind =
        undo.appliedEnabled
            ? PamProviderManagedEntryKind::FlagEnabled
            : PamProviderManagedEntryKind::FlagDisabled;
    if (!undo.appliedEnabled) {
        targetCandidate.authorizedSuppressionIds = undo.suppressionIds;
    }
    PamProviderFlagReleaseExpectation releaseExpectation;
    releaseExpectation.provider = undo.providerName;
    releaseExpectation.policy = undo.policyName;
    releaseExpectation.managedKey = undo.managedKey;
    releaseExpectation.mutationId = record.id;
    releaseExpectation.candidates.push_back(targetCandidate);
    if (record.status == MutationStatus::Prepared &&
        undo.previousAppliedEnabled.has_value()) {
        PamProviderFlagOwnedStateCandidate previousCandidate;
        previousCandidate.entryKind =
            *undo.previousAppliedEnabled
                ? PamProviderManagedEntryKind::FlagEnabled
                : PamProviderManagedEntryKind::FlagDisabled;
        if (!*undo.previousAppliedEnabled) {
            previousCandidate.authorizedSuppressionIds =
                undo.previousSuppressionIds;
        }
        releaseExpectation.candidates.push_back(previousCandidate);
    }

    const PamProviderFlagReleaseResult release =
        releasePamProviderManagedFlag(read.content, releaseExpectation,
                                      route->placement);
    if (!release.ok) {
        return conflictResult("release managed flag state отклонено: " +
                              release.error);
    }
    if (release.outcome ==
        PamProviderFlagReleaseResult::Outcome::AlreadyAbsent) {
        return resolveAlreadyReleasedState(options, journal,
                                           undo.providerName, path);
    }

    return finishOwnershipRelease(
        options, journal, undo.providerName, path, read, parse,
        release.content,
        "Flag rollback (record " + std::to_string(record.id) + ")");
}

// Shared managed-provider-domain predicate (Step 7F security follow-up).
// A capability belongs to the managed provider configuration domain ONLY
// when its typed descriptor actually routes at least one managed policy
// binding through pamProviderManagedEntryPlacement(). SINGLE source of
// truth for BOTH the container provenance proof
// (pamProviderContainerRollbackRouteForPayload) and the managed primary
// enumeration (pamProviderManagedPrimaryPath) — the two domain models can
// never drift apart (e.g. ALT p11: faillock is a managed ProviderConfigFile
// domain, while passwdqc and the AltTcbManaged pwhistory stay outside it
// despite being ProviderConfigFile-shaped).
bool capabilityHasManagedProviderRoute(
    const PamProviderDescriptor& descriptor,
    const fic::platform::PamCapabilityConfig& capability) {
    for (const PamProviderPolicyBinding& binding : descriptor.policies) {
        if (pamProviderManagedEntryPlacement(descriptor, capability, binding,
                                             binding.feature).has_value()) {
            return true;
        }
    }
    return false;
}

} // namespace

const char* pamProviderManagedFeaturePolicyName(
    fic::platform::PamPolicyFeature feature);

// Shared SSOT table of the managed PAM provider policy identities (canonical
// FIC policy name <-> typed platform feature). One definition serves both
// lookup directions.
const std::vector<std::pair<const char*, fic::platform::PamPolicyFeature>>&
pamProviderManagedPolicyNames() {
    static const std::vector<std::pair<const char*,
        fic::platform::PamPolicyFeature>> names = {
        {"failed_authentication_attempts",
         fic::platform::PamPolicyFeature::FailedAuthenticationAttempts},
        {"failed_authentication_counting_period",
         fic::platform::PamPolicyFeature::FailedAuthenticationCountingPeriod},
        {"failed_authentication_enforce_for_root",
         fic::platform::PamPolicyFeature::FailedAuthenticationEnforceForRoot},
        {"failed_authentication_unlock_time",
         fic::platform::PamPolicyFeature::FailedAuthenticationUnlockTime},
        {"password_min_length",
         fic::platform::PamPolicyFeature::PasswordMinLength},
        {"password_min_classes",
         fic::platform::PamPolicyFeature::PasswordMinClasses},
        {"password_check_username",
         fic::platform::PamPolicyFeature::PasswordCheckUsername},
        {"password_check_gecos",
         fic::platform::PamPolicyFeature::PasswordCheckGecos},
        {"password_quality_enforce_for_root",
         fic::platform::PamPolicyFeature::PasswordQualityEnforceForRoot},
        {"password_min_changed_characters",
         fic::platform::PamPolicyFeature::PasswordMinChangedCharacters},
        {"password_min_lowercase",
         fic::platform::PamPolicyFeature::PasswordMinLowercase},
        {"password_min_uppercase",
         fic::platform::PamPolicyFeature::PasswordMinUppercase},
        {"password_min_digits",
         fic::platform::PamPolicyFeature::PasswordMinDigits},
        {"password_min_other",
         fic::platform::PamPolicyFeature::PasswordMinOther},
        {"password_history_depth",
         fic::platform::PamPolicyFeature::PasswordHistoryDepth},
        {"password_history_enforce_for_root",
         fic::platform::PamPolicyFeature::PasswordHistoryEnforceForRoot},
    };
    return names;
}

const fic::platform::PamPolicyFeature* pamProviderManagedPolicyFeature(
    const std::string& policyName) {
    for (const auto& entry : pamProviderManagedPolicyNames()) {
        if (policyName == entry.first) {
            return &entry.second;
        }
    }
    return nullptr;
}

const char* pamProviderManagedFeaturePolicyName(
    fic::platform::PamPolicyFeature feature) {
    for (const auto& entry : pamProviderManagedPolicyNames()) {
        if (feature == entry.second) {
            return entry.first;
        }
    }
    return nullptr;
}

std::optional<PamProviderRollbackRoute> pamProviderRollbackRouteForFeature(
    const PamProviderRollbackOptions& options,
    fic::platform::PamPolicyFeature feature,
    std::string& conflictMessage) {
    const fic::platform::PamCapabilityConfig* capability =
        capabilityConfig(options.platform, pamPolicyCapability(feature));
    if (capability == nullptr) {
        conflictMessage = "текущая platform profile не содержит capability "
                          "для этого managed PAM policy feature";
        return std::nullopt;
    }
    const PamProviderDescriptor descriptor =
        pamProviderDescriptor(capability->provider);
    const PamProviderPolicyBinding* binding =
        pamProviderPolicyBinding(capability->provider, feature);
    if (binding == nullptr) {
        conflictMessage = "провайдер не имеет binding для этого managed PAM "
                          "policy feature";
        return std::nullopt;
    }
    const std::optional<PamProviderBlockPlacementRequest> placement =
        pamProviderManagedEntryPlacement(descriptor, *capability, *binding,
                                         feature);
    if (!placement.has_value()) {
        conflictMessage = "текущая platform profile не маршрутизирует эту "
                          "политику через managed provider configuration";
        return std::nullopt;
    }
    PamProviderRollbackRoute route;
    route.descriptor = descriptor;
    route.capability = capability;
    route.binding = *binding;
    route.feature = feature;
    route.placement = *placement;
    route.configPath = capability->configPath;
    return route;
}

std::optional<PamProviderRollbackRoute> pamProviderRollbackRouteForPayload(
    const PamProviderRollbackOptions& options,
    const std::string& providerName,
    const std::string& configPath,
    const std::string& policyName,
    const std::string& managedKey,
    PamNativeOptionSyntax expectedSyntax,
    fic::rollback::PamProviderBlockPlacementContract placementContract,
    std::string& conflictMessage) {
    return routeForPayload(options, providerName, configPath, policyName,
                           managedKey, expectedSyntax, placementContract,
                           conflictMessage);
}

std::optional<PamProviderContainerRollbackRoute>
pamProviderContainerRollbackRouteForPayload(
    const PamProviderRollbackOptions& options,
    const std::string& providerName,
    const std::string& configPath,
    std::string& conflictMessage) {
    const fic::platform::PamCapabilityConfig* capability =
        findProviderConfigFileCapability(options, providerName, configPath,
                                         conflictMessage);
    if (capability == nullptr) {
        return std::nullopt;
    }
    const PamProviderDescriptor descriptor =
        pamProviderDescriptor(capability->provider);
    // Managed-provider domain proof (Step 7B-7E): the capability is the
    // managed provider configuration domain ONLY when its typed descriptor
    // actually routes at least one managed policy binding through
    // pamProviderManagedEntryPlacement(). Shared typed predicate (SSOT with
    // pamProviderManagedPrimaryPath) — never a distro switch, never a
    // second whitelist.
    if (!capabilityHasManagedProviderRoute(descriptor, *capability)) {
        conflictMessage = "capability текущего platform profile ('" + providerName +
            "', config path '" + configPath +
            "') не входит в managed provider configuration domain: container "
            "provenance rollback запрещён";
        return std::nullopt;
    }
    PamProviderContainerRollbackRoute route;
    route.descriptor = descriptor;
    route.capability = capability;
    route.configPath = capability->configPath;
    return route;
}

std::optional<std::filesystem::path> pamProviderManagedPrimaryPath(
    const fic::platform::PamCapabilityConfig& capability) {
    if (capability.configurationMode !=
            fic::platform::PamCapabilityConfigurationMode::
                ProviderConfigFile ||
        capability.configPath.empty()) {
        return std::nullopt;
    }
    // Route-aware managed-provider domain eligibility (Step 7F security
    // follow-up): a ProviderConfigFile capability is a managed primary ONLY
    // when its typed descriptor actually routes at least one managed policy
    // binding (pamProviderManagedEntryPlacement). Shared predicate (SSOT
    // with pamProviderContainerRollbackRouteForPayload) — ALT passwdqc and
    // the ALT AltTcbManaged pwhistory are never enumerated as managed
    // provider primaries.
    const PamProviderDescriptor descriptor =
        pamProviderDescriptor(capability.provider);
    if (!capabilityHasManagedProviderRoute(descriptor, capability)) {
        return std::nullopt;
    }
    return capability.configPath;
}

std::vector<std::filesystem::path> pamProviderManagedPrimaryPaths(
    const fic::platform::PamPlatformConfig& platform) {
    std::vector<std::filesystem::path> paths;
    for (const fic::platform::PamCapabilityConfig& capability :
         platform.capabilities) {
        const std::optional<std::filesystem::path> primary =
            pamProviderManagedPrimaryPath(capability);
        if (!primary.has_value()) {
            continue;
        }
        if (std::find(paths.begin(), paths.end(), *primary) == paths.end()) {
            paths.push_back(*primary);
        }
    }
    return paths;
}

PamProviderRollbackResult inspectUnrecordedPamProviderManagedState(
    const PamProviderRollbackOptions& options,
    const std::string& policyName) {
    const fic::platform::PamPolicyFeature* feature =
        pamProviderManagedPolicyFeature(policyName);
    if (feature == nullptr) {
        return nothingToDoResult("политика не входит в managed provider "
                                 "route");
    }
    std::string routeMessage;
    const std::optional<PamProviderRollbackRoute> route =
        pamProviderRollbackRouteForFeature(options, *feature, routeMessage);
    if (!route.has_value()) {
        // The current platform does not route this policy through the
        // managed provider configuration: no provider primary FIC could
        // have marked for it.
        return nothingToDoResult(routeMessage);
    }
    std::string error;
    PamProviderContainerReadResult read =
        PamProviderManagedBlockFile::readForMutation(
            route->configPath, PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */,
            error);
    if (!read.ok) {
        return failureResult("не удалось выполнить trusted read provider "
                             "primary '" + route->configPath.string() +
                             "': " + error);
    }
    if (read.state == PamProviderContainerState::Absent) {
        return nothingToDoResult("provider primary отсутствует: orphan FIC "
                                 "markers невозможны");
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        return conflictResult("строгий parse provider primary не удался "
                              "(orphan/поврежденные FIC markers, fail "
                              "closed): " + parse.error);
    }
    for (const PamProviderManagedEntry& entry : parse.view.entries) {
        if (entry.policy == policyName) {
            return conflictResult(
                "orphan FIC PAM entry политики '" + policyName +
                "' без активной journal-записи: маркер не усыновляется и не "
                "удаляется (fail closed)");
        }
    }
    for (const PamProviderSuppressedLine& wrapper : parse.view.suppressions) {
        if (wrapper.policy == policyName) {
            return conflictResult(
                "orphan FIC PAM suppression wrapper политики '" + policyName +
                "' без активной journal-записи: маркер не усыновляется и не "
                "удаляется (fail closed)");
        }
    }
    return nothingToDoResult("no record и no physical FIC state: disable "
                             "разрешен");
}

// Public locked API: every runtime provider rollback serializes through the
// shared interprocess managed-provider mutation lock domain.
PamProviderRollbackResult undoPamProviderManagedEntry(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedEntry& undo) {
    PamProviderManagedLock::Handle lock;
    std::string lockError;
    if (!PamProviderManagedLock::acquire(lock, lockError)) {
        return failureResult(lockError);
    }
    return undoEntryUnlocked(options, journal, record, undo);
}

PamProviderRollbackResult undoPamProviderManagedFlag(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& undo) {
    PamProviderManagedLock::Handle lock;
    std::string lockError;
    if (!PamProviderManagedLock::acquire(lock, lockError)) {
        return failureResult(lockError);
    }
    return undoFlagUnlocked(options, journal, record, undo);
}

PamProviderRollbackResult undoPamProviderManagedEntryUnlocked(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedEntry& undo) {
    return undoEntryUnlocked(options, journal, record, undo);
}

PamProviderRollbackResult undoPamProviderManagedFlagUnlocked(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& undo) {
    return undoFlagUnlocked(options, journal, record, undo);
}

PamProviderRollbackResult undoOwnPamProviderContainer(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoOwnPamProviderContainer& undo) {
    PamProviderManagedLock::Handle lock;
    std::string lockError;
    if (!PamProviderManagedLock::acquire(lock, lockError)) {
        return failureResult(lockError);
    }
    return undoOwnPamProviderContainerUnlocked(options, journal, record, undo);
}

// Package-release final sweep of one container provenance record: releases
// a FIC-created container that provably holds no FIC state anymore, or
// detaches the provenance when foreign content remains. Retried safely
// after a crash.
PamProviderRollbackResult undoOwnPamProviderContainerUnlocked(
    const PamProviderRollbackOptions& options,
    MutationJournal& journal,
    const MutationRecord& record,
    const UndoOwnPamProviderContainer& undo) {
    // Defense-in-depth (stale-record refusal): the passed record must be
    // the CURRENT active container provenance record of the journal. A
    // resolved (RolledBack/Detached) or stale snapshot copy never receives
    // destructive processing — Detached means FIC permanently relinquished
    // the container and never writes to it again. The MAIN guarantee lives
    // in the package release orchestration (re-enumeration of the current
    // active records); this refusal only closes the second entry point.
    const MutationRecord* current = nullptr;
    for (const MutationRecord& candidate : journal.records()) {
        if (candidate.id == record.id) {
            current = &candidate;
            break;
        }
    }
    if (current == nullptr || !current->isActive()) {
        return conflictResult(
            "container provenance record " + std::to_string(record.id) +
            " больше не является активной записью журнала (resolved or "
            "stale snapshot); destructive container sweep запрещён");
    }
    const UndoOwnPamProviderContainer* currentPayload =
        std::get_if<UndoOwnPamProviderContainer>(&current->undo.payload);
    if (currentPayload == nullptr ||
        currentPayload->providerName != undo.providerName ||
        !samePath(currentPayload->configPath, undo.configPath)) {
        return conflictResult(
            "container provenance payload record " +
            std::to_string(record.id) +
            " не совпадает с текущей активной записью журнала (stale "
            "snapshot); destructive container sweep запрещён");
    }

    // Current-platform proof (Step 7F security follow-up): the journal
    // path is never executed blindly — the CURRENT platform profile must
    // confirm the (provider, configPath) managed container identity
    // through the single typed SSOT before any trusted read or mutation.
    std::string routeMessage;
    const std::optional<PamProviderContainerRollbackRoute> route =
        pamProviderContainerRollbackRouteForPayload(options, undo.providerName,
                                                    undo.configPath,
                                                    routeMessage);
    if (!route.has_value()) {
        return conflictResult(routeMessage);
    }

    const std::filesystem::path path(undo.configPath);
    std::string error;
    PamProviderContainerReadResult read =
        PamProviderManagedBlockFile::readForMutation(
            path, PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */, error);
    if (!read.ok) {
        return failureResult("не удалось выполнить trusted read provider "
                             "primary '" + undo.configPath + "': " + error);
    }
    if (read.state == PamProviderContainerState::Absent) {
        return resolveAlreadyReleasedState(options, journal,
                                           undo.providerName, path);
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        return conflictResult("строгий parse provider primary не удался "
                              "(orphan/поврежденные FIC markers): " +
                              parse.error);
    }
    if (parse.view.present) {
        return conflictResult(
            "container provenance release refused: the primary still carries "
            "the '" + undo.providerName +
            "' FIC block — active FIC state must be released before the "
            "container provenance (fail closed)");
    }
    // No FIC block: any surviving suppression wrapper is orphan FIC
    // serialization and refuses the sweep (never silently removed).
    if (!parse.view.suppressions.empty()) {
        return conflictResult(
            "container provenance release refused: the primary still carries "
            "FIC suppression wrappers (orphan provenance, fail closed)");
    }
    // The content is foreign (or empty). The pure "release" result is the
    // content itself: an empty FIC-created file is conditionally deleted;
    // foreign-only content detaches the provenance after the durable
    // re-write.
    return finishOwnershipRelease(options, journal, undo.providerName, path,
                                  read, parse, read.content,
                                  "Container release (record " +
                                      std::to_string(record.id) + ")");
}

} // namespace fic::identity::pam
