#include "modules/identity_access/pam/PamProviderPackageRelease.h"

#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"

#include <fic/core/process/ExclusivePidLock.h>

#include <algorithm>
#include <tuple>
#include <utility>

namespace fic::identity::pam {

namespace {

using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoOwnPamProviderContainer;
using fic::rollback::UndoRemovePamProviderManagedEntry;
using fic::rollback::UndoRemovePamProviderManagedFlag;

const UndoRemovePamProviderManagedEntry* entryPayload(
    const MutationRecord& record) {
    return std::get_if<UndoRemovePamProviderManagedEntry>(
        &record.undo.payload);
}

const UndoRemovePamProviderManagedFlag* flagPayload(
    const MutationRecord& record) {
    return std::get_if<UndoRemovePamProviderManagedFlag>(&record.undo.payload);
}

const UndoOwnPamProviderContainer* containerPayload(
    const MutationRecord& record) {
    return std::get_if<UndoOwnPamProviderContainer>(&record.undo.payload);
}

bool isActivePayloadKind(const MutationRecord& record) {
    return record.isActive() &&
        (entryPayload(record) != nullptr || flagPayload(record) != nullptr ||
         containerPayload(record) != nullptr);
}

bool samePath(const std::filesystem::path& left,
              const std::filesystem::path& right) {
    return std::filesystem::path(left).lexically_normal() ==
        std::filesystem::path(right).lexically_normal();
}

// Known managed provider primary paths of the CURRENT platform: the Step 7F
// SSOT (pamProviderManagedPrimaryPaths, same eligibility as the typed
// routing proof — configuration MODE, never configTopology.has_value(),
// which is nullopt for production profiles whose provider topology lives in
// provider.defaultConfigTopology). This is the only domain where the FIC
// managed block/wrapper serialization can ever live.
std::vector<std::filesystem::path> knownProviderPrimaries(
    const fic::platform::PamPlatformConfig& platform) {
    return pamProviderManagedPrimaryPaths(platform);
}

// The deterministic release order (Step 7F §70): configPath, policy,
// managedKey, record id — testable and independent of JSON ordering.
std::tuple<std::string, std::string, std::string, std::uint64_t>
releaseOrderKey(const MutationRecord& record) {
    if (const auto* entry = entryPayload(record)) {
        return {entry->configPath, entry->policyName, entry->managedKey,
                record.id};
    }
    if (const auto* flag = flagPayload(record)) {
        return {flag->configPath, flag->policyName, flag->managedKey,
                record.id};
    }
    return {record.resource, {}, {}, record.id};
}

} // namespace

PamProviderPackageRelease::PamProviderPackageRelease(
    fic::rollback::MutationJournal& journal,
    fic::platform::PamPlatformConfig platform,
    Options options)
    : journal_(journal), platform_(std::move(platform)),
      options_(std::move(options)) {}

bool PamProviderPackageRelease::preflight(Report& report, std::string& error) {
    std::vector<MutationRecord> active;
    for (const MutationRecord& record : journal_.records()) {
        if (isActivePayloadKind(record)) {
            active.push_back(record);
        }
    }

    // Per-record releasability proof through the PURE release primitives
    // (no write): the same exact-ownership proofs the release will use.
    for (const MutationRecord& record : active) {
        std::string payloadConfigPath;
        std::string payloadProvider;
        std::string payloadKey;
        fic::rollback::PamProviderBlockPlacementContract placementContract =
            fic::rollback::PamProviderBlockPlacementContract::End;
        if (const auto* entry = entryPayload(record)) {
            payloadConfigPath = entry->configPath;
            payloadProvider = entry->providerName;
            payloadKey = entry->managedKey;
            placementContract = entry->placement;
        } else if (const auto* flag = flagPayload(record)) {
            payloadConfigPath = flag->configPath;
            payloadProvider = flag->providerName;
            payloadKey = flag->managedKey;
            placementContract = flag->placement;
        } else {
            continue; // container records are proven below
        }
        // Platform identity proof against the CURRENT profile (§67.3).
        std::string routeMessage;
        PamProviderRollbackOptions rollbackOptions;
        rollbackOptions.platform = platform_;
        const std::optional<PamProviderRollbackRoute> route =
            pamProviderRollbackRouteForPayload(
                rollbackOptions, payloadProvider, payloadConfigPath,
                payloadKey, placementContract, routeMessage);
        if (!route.has_value()) {
            error = "preflight: active record " + std::to_string(record.id) +
                " is not confirmed by the current platform: " + routeMessage;
            return false;
        }
        // Trusted read + strict parse (§67.4/§67.5).
        std::string readError;
        PamProviderContainerReadResult read =
            PamProviderManagedBlockFile::readForMutation(
                std::filesystem::path(payloadConfigPath),
                PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */, readError);
        if (!read.ok) {
            error = "preflight: trusted read failed for " + payloadConfigPath +
                ": " + readError;
            return false;
        }
        if (read.state == PamProviderContainerState::Absent) {
            continue; // externally released primary: releasable no-op
        }
        const PamProviderBlockParseResult parse =
            parsePamProviderManagedBlock(read.content);
        if (!parse.ok) {
            error = "preflight: strict parse failed for " + payloadConfigPath +
                ": " + parse.error;
            return false;
        }
        if (const auto* entry = entryPayload(record)) {
            PamProviderOwnershipExpectation expectation;
            expectation.provider = entry->providerName;
            expectation.policy = entry->policyName;
            expectation.managedKey = entry->managedKey;
            expectation.body = entry->appliedBody;
            expectation.previousBody = entry->previousAppliedBody;
            expectation.mutationId = record.id;
            const PamProviderJournalMutationStatus classifyStatus =
                record.status == MutationStatus::Prepared
                ? PamProviderJournalMutationStatus::Prepared
                : PamProviderJournalMutationStatus::Applied;
            const PamProviderJournalBindingResult binding =
                classifyPamProviderJournalBinding(classifyStatus, parse,
                                                  expectation);
            if (!binding.ok) {
                error = "preflight: record " + std::to_string(record.id) +
                    " ownership classification failed: " + binding.error;
                return false;
            }
            // Stage A is a strict READ-ONLY proof that Stage B can release.
            // A classification that completed is not automatically
            // releasable: only the binding states the runtime rollback
            // handles as release/no-op may proceed. Drift/conflict states
            // fail the package preflight BEFORE any writer is stopped and
            // without touching config/journal.
            switch (binding.state) {
            case PamProviderJournalBindingState::AppliedExact:
            case PamProviderJournalBindingState::AppliedMissing:
            case PamProviderJournalBindingState::PreparedFreshAbsent:
            case PamProviderJournalBindingState::PreparedFreshTargetPresent:
            case PamProviderJournalBindingState::
                PreparedUpdatePreviousPresent:
            case PamProviderJournalBindingState::
                PreparedUpdateTargetPresent:
                break;
            case PamProviderJournalBindingState::AppliedDrifted:
            case PamProviderJournalBindingState::PreparedConflict:
            default:
                error = "preflight: record " + std::to_string(record.id) +
                    " is in a non-releasable binding state (fail closed; " +
                    std::string(classifyStatus ==
                                    PamProviderJournalMutationStatus::Prepared
                                ? "PreparedConflict"
                                : "AppliedDrifted") +
                    "); package removal is blocked";
                return false;
            }
            continue;
        }
        if (!preflightFlagRecord(record, *flagPayload(record),
                                 route->placement, error)) {
            return false;
        }
    }

    if (!preflightPhysicalState(error)) {
        return false;
    }
    (void)report; // preflight is strictly read-only; nothing to report
    return true;
}

bool PamProviderPackageRelease::preflightFlagRecord(
    const fic::rollback::MutationRecord& record,
    const fic::rollback::UndoRemovePamProviderManagedFlag& flag,
    PamProviderBlockPlacementRequest placement, std::string& error) {
    std::string readError;
    PamProviderContainerReadResult read =
        PamProviderManagedBlockFile::readForMutation(
            std::filesystem::path(flag.configPath),
            PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */, readError);
    if (!read.ok) {
        error = "preflight: trusted read failed for " + flag.configPath +
            ": " + readError;
        return false;
    }
    if (read.state == PamProviderContainerState::Absent) {
        return true;
    }
    const PamProviderBlockParseResult parse =
        parsePamProviderManagedBlock(read.content);
    if (!parse.ok) {
        error = "preflight: strict parse failed for " + flag.configPath +
            ": " + parse.error;
        return false;
    }
    PamProviderFlagOwnedStateCandidate targetCandidate;
    targetCandidate.entryKind =
        flag.appliedEnabled ? PamProviderManagedEntryKind::FlagEnabled
                            : PamProviderManagedEntryKind::FlagDisabled;
    if (!flag.appliedEnabled) {
        targetCandidate.authorizedSuppressionIds = flag.suppressionIds;
    }
    PamProviderFlagReleaseExpectation releaseExpectation;
    releaseExpectation.provider = flag.providerName;
    releaseExpectation.policy = flag.policyName;
    releaseExpectation.managedKey = flag.managedKey;
    releaseExpectation.mutationId = record.id;
    releaseExpectation.candidates.push_back(targetCandidate);
    if (record.status == MutationStatus::Prepared &&
        flag.previousAppliedEnabled.has_value()) {
        PamProviderFlagOwnedStateCandidate previousCandidate;
        previousCandidate.entryKind =
            *flag.previousAppliedEnabled
                ? PamProviderManagedEntryKind::FlagEnabled
                : PamProviderManagedEntryKind::FlagDisabled;
        if (!*flag.previousAppliedEnabled) {
            previousCandidate.authorizedSuppressionIds =
                flag.previousSuppressionIds;
        }
        releaseExpectation.candidates.push_back(previousCandidate);
    }
    const PamProviderFlagReleaseResult release = releasePamProviderManagedFlag(
        read.content, releaseExpectation, placement);
    if (!release.ok) {
        error = "preflight: flag record " + std::to_string(record.id) +
            " is not releasable: " + release.error;
        return false;
    }
    return true;
}

bool PamProviderPackageRelease::preflightPhysicalState(std::string& error) {
    std::vector<std::pair<std::string, std::string>> journaledIdentities;
    for (const MutationRecord& record : journal_.records()) {
        if (!record.isActive()) {
            continue;
        }
        if (const auto* entry = entryPayload(record)) {
            journaledIdentities.emplace_back(entry->configPath,
                                             entry->policyName);
        } else if (const auto* flag = flagPayload(record)) {
            journaledIdentities.emplace_back(flag->configPath,
                                             flag->policyName);
        }
    }
    auto covered = [&](const std::string& configPath,
                       const std::string& policy) {
        for (const auto& identity : journaledIdentities) {
            if (identity.first == configPath && identity.second == policy) {
                return true;
            }
        }
        return false;
    };

    // Orphan detection (§68) over every known provider primary.
    for (const std::filesystem::path& path :
         knownProviderPrimaries(platform_)) {
        std::string readError;
        PamProviderContainerReadResult read =
            PamProviderManagedBlockFile::readForMutation(
                path, PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */,
                readError);
        if (!read.ok) {
            error = "preflight: trusted read failed for " + path.string() +
                ": " + readError;
            return false;
        }
        if (read.state == PamProviderContainerState::Absent) {
            continue;
        }
        const PamProviderBlockParseResult parse =
            parsePamProviderManagedBlock(read.content);
        if (!parse.ok) {
            error = "preflight: strict parse failed for " + path.string() +
                ": " + parse.error;
            return false;
        }
        for (const PamProviderManagedEntry& entry : parse.view.entries) {
            if (!covered(path.string(), entry.policy)) {
                error = "preflight: orphan FIC PAM entry for policy '" +
                    entry.policy + "' in " + path.string() +
                    " without active journal provenance — package removal is "
                    "blocked (fail closed)";
                return false;
            }
        }
        for (const PamProviderSuppressedLine& wrapper :
             parse.view.suppressions) {
            if (!covered(path.string(), wrapper.policy)) {
                error = "preflight: orphan FIC PAM suppression wrapper for "
                        "policy '" + wrapper.policy + "' in " +
                    path.string() +
                    " without active journal provenance — package removal is "
                    "blocked (fail closed)";
                return false;
            }
        }
    }

    // Container provenance coherence (§67.8).
    for (const MutationRecord& record : journal_.records()) {
        if (!record.isActive()) {
            continue;
        }
        const auto* container = containerPayload(record);
        if (container == nullptr) {
            continue;
        }
        std::string readError;
        PamProviderContainerReadResult read =
            PamProviderManagedBlockFile::readForMutation(
                std::filesystem::path(container->configPath),
                PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */, readError);
        if (!read.ok) {
            error = "preflight: container provenance record " +
                std::to_string(record.id) +
                " references an unreadable primary " + container->configPath +
                ": " + readError;
            return false;
        }
        if (read.state == PamProviderContainerState::Absent) {
            if (record.status == MutationStatus::Applied) {
                // Recoverable crash state (Step 7F follow-up): conditional
                // delete was durable, the journal resolution did not happen,
                // then the process died. The primary being absent with an
                // APPLIED container provenance is exactly the state the
                // runtime backend legally recovers (prove absence again →
                // parent-dir durability barrier → resolve the record as
                // RolledBack through resolveAlreadyReleasedState in Stage
                // B). This is read-only here: Stage A just must not block
                // the recovery path forever.
                continue;
            }
            // Prepared/RollbackFailed + absent primary: an absent file alone
            // proves nothing about ownership (no creation witness here).
            // Strict ownership semantics are kept — fail closed.
            error = "preflight: container provenance record " +
                std::to_string(record.id) +
                " references an absent primary " + container->configPath +
                " while the record is not Applied (ambiguous externally "
                "deleted container; fail closed)";
            return false;
        }
        const PamProviderBlockParseResult parse =
            parsePamProviderManagedBlock(read.content);
        if (!parse.ok) {
            error = "preflight: strict parse failed for " +
                container->configPath + ": " + parse.error;
            return false;
        }
        if (parse.view.present &&
            parse.view.provider != container->providerName) {
            error = "preflight: container provenance for '" +
                container->providerName + "' but the primary block belongs "
                "to '" + parse.view.provider + "' (fail closed)";
            return false;
        }
    }
    return true;
}

bool PamProviderPackageRelease::run(Mode mode, Report& report,
                                    std::string& error) {
    if (mode == Mode::Preflight) {
        // Stage A: strictly read-only; the shared lock is NOT required and
        // is deliberately not taken (§64: Stage A preflight needs no lock).
        return preflight(report, error);
    }

    // Stage B: exclusive acquisition of the SHARED managed-provider
    // mutation lock (same domain as apply/runtime rollback, §59-§64). A
    // held lock refuses the release safely: no journal/file mutation.
    ExclusivePidLock lock(options_.lockFilePath.string(),
                          options_.lockDebugLogPath, /*enableDebug=*/true);
    if (!options_.lockFilePath.empty() && !lock.tryAcquire()) {
        error = "release: the shared managed-provider mutation lock is held "
                "by another process (" + options_.lockFilePath.string() +
                "); the release refuses safely without any mutation";
        return false;
    }

    // Fresh full preflight (§69): the Stage A snapshot is never trusted.
    Report unusedPreflightReport;
    if (!preflight(unusedPreflightReport, error)) {
        return false;
    }

    // Deterministic release of the active entry/flag records (§70).
    std::vector<MutationRecord> releasable;
    std::vector<MutationRecord> containers;
    for (const MutationRecord& record : journal_.records()) {
        if (!record.isActive()) {
            continue;
        }
        if (containerPayload(record) != nullptr) {
            containers.push_back(record);
        } else {
            releasable.push_back(record);
        }
    }
    std::sort(releasable.begin(), releasable.end(),
              [](const MutationRecord& left, const MutationRecord& right) {
                  return releaseOrderKey(left) < releaseOrderKey(right);
              });
    std::sort(containers.begin(), containers.end(),
              [](const MutationRecord& left, const MutationRecord& right) {
                  return releaseOrderKey(left) < releaseOrderKey(right);
              });

    PamProviderRollbackOptions rollbackOptions;
    rollbackOptions.platform = platform_;
    rollbackOptions.simulateContainerJournalResolutionFailure =
        options_.simulateContainerJournalResolutionFailure;

    for (const MutationRecord& record : releasable) {
        PamProviderRollbackResult result;
        if (const auto* entry = entryPayload(record)) {
            result = undoPamProviderManagedEntryUnlocked(
                rollbackOptions, journal_, record, *entry);
            if (result.ok) {
                report.releasedRecords.push_back(
                    "entry " + std::to_string(record.id) + " " +
                    entry->policyName);
            }
        } else if (const auto* flag = flagPayload(record)) {
            result = undoPamProviderManagedFlagUnlocked(
                rollbackOptions, journal_, record, *flag);
            if (result.ok) {
                report.releasedRecords.push_back(
                    "flag " + std::to_string(record.id) + " " +
                    flag->policyName);
            }
        } else {
            continue;
        }
        if (!result.ok) {
            // Monotonic ownership release (§72): released records stay
            // RolledBack, this record stays active, the removal is blocked.
            error = "release: record " + std::to_string(record.id) +
                " could not be released: " + result.message;
            return false;
        }
        std::string journalError;
        if (!journal_.setStatus(record.id, MutationStatus::RolledBack,
                                journalError)) {
            error = "release: record " + std::to_string(record.id) +
                " was physically released, but the journal record could not "
                "be resolved: " + journalError;
            return false;
        }
        report.changedSystemState = report.changedSystemState ||
            result.changedSystemState;
    }

    // Container cleanup AFTER all provider state is released (§71/§73).
    for (const MutationRecord& record : containers) {
        const auto* container = containerPayload(record);
        if (container == nullptr) {
            continue;
        }
        const PamProviderRollbackResult result =
            undoOwnPamProviderContainerUnlocked(rollbackOptions, journal_,
                                                record, *container);
        if (!result.ok) {
            error = "release: container provenance record " +
                std::to_string(record.id) + " could not be resolved: " +
                result.message;
            return false;
        }
        MutationStatus resolved = MutationStatus::Applied;
        for (const MutationRecord& current : journal_.records()) {
            if (current.id == record.id) {
                resolved = current.status;
                break;
            }
        }
        if (resolved == MutationStatus::RolledBack) {
            report.containersDeleted.push_back(container->configPath);
        } else if (resolved == MutationStatus::Detached) {
            report.containersDetached.push_back(container->configPath);
        } else {
            report.containersRetained.push_back(container->configPath);
        }
        report.changedSystemState = report.changedSystemState ||
            result.changedSystemState;
    }

    // Independent final proof (§73): no active provider domain records and
    // no FIC serialization on any known provider primary.
    for (const MutationRecord& record : journal_.records()) {
        if (isActivePayloadKind(record)) {
            error = "release: final proof failed: active provider domain "
                    "record " + std::to_string(record.id) + " remains";
            return false;
        }
    }
    for (const std::filesystem::path& path :
         knownProviderPrimaries(platform_)) {
        std::string readError;
        PamProviderContainerReadResult read =
            PamProviderManagedBlockFile::readForMutation(
                path, PamProviderAbsentContainerDecision::CreateFicOwned /* read-only ENOENT classification; the rollback path never creates a container */,
                readError);
        if (!read.ok) {
            error = "release: final proof trusted read failed for " +
                path.string() + ": " + readError;
            return false;
        }
        if (read.state == PamProviderContainerState::Absent) {
            continue;
        }
        const PamProviderBlockParseResult parse =
            parsePamProviderManagedBlock(read.content);
        if (!parse.ok) {
            error = "release: final proof strict parse failed for " +
                path.string() + ": " + parse.error;
            return false;
        }
        if (parse.view.present || !parse.view.suppressions.empty()) {
            error = "release: final proof failed: FIC serialization remains "
                    "in " + path.string();
            return false;
        }
    }
    return true;
}

} // namespace fic::identity::pam
