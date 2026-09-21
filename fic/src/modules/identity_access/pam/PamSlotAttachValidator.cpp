#include "modules/identity_access/pam/PamSlotAttachValidator.h"

#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <set>
#include <utility>
#include <vector>

namespace fic::identity::pam {
namespace {

using fic::rollback::MutationBackend;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::UndoDisablePamCapability;

// Complete active-FIC-owned-state proof for the attach decision: the journal
// must carry an ACTIVE record whose payload proves the exact managed-slot
// ownership domain for this capability. No semantic equality and no
// profile-name inference is used as a substitute for this physical proof.
bool proveJournalOwnership(
    std::uint64_t mutationId,
    const fic::platform::PamCapabilityConfig& capability,
    const std::filesystem::path& mutationJournalFile,
    PamSlotAttachVerdict& verdict) {
    // Read-only journal access: load() never creates, bootstraps or rewrites
    // the document. A missing, zero-byte or malformed journal fails closed
    // instead of healing into an empty provenance source.
    MutationJournal journal(mutationJournalFile);
    std::string journalError;
    if (!journal.load(journalError)) {
        verdict.detail =
            "mutation journal is not readable (fail closed): " + journalError;
        return true;
    }

    const MutationRecord* match = nullptr;
    for (const MutationRecord& record : journal.records()) {
        if (record.id == mutationId) {
            match = &record;
            break;
        }
    }
    if (match == nullptr) {
        verdict.detail =
            "active FIC PAM slots reference journal mutation " +
            std::to_string(mutationId) +
            " with no matching journal record";
        return true;
    }
    if (!match->isActive()) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " is not active (status " +
            fic::rollback::mutationStatusToString(match->status) +
            "); it cannot prove the active slot state";
        return true;
    }
    if (match->undo.backend != MutationBackend::Pam) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " does not belong to the PAM backend";
        return true;
    }
    const auto* payload =
        std::get_if<UndoDisablePamCapability>(&match->undo.payload);
    if (payload == nullptr) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " carries no PAM capability ownership payload";
        return true;
    }
    if (payload->capability != "enable_authentication_lockout" ||
        payload->topology != fic::rollback::PamTopologyKind::PamAuthUpdate) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " proves a different PAM capability or topology";
        return true;
    }
    // The recorded ownership domain must exactly match the managed-slot
    // activation domain of the CURRENT platform profile: a partial, extended
    // or legacy domain is not a provenance for this topology.
    const std::vector<std::string> domain =
        activationIdentifiers(capability);
    const std::set<std::string> recorded(
        payload->activationIdentifiers.begin(),
        payload->activationIdentifiers.end());
    const std::set<std::string> expected(domain.begin(), domain.end());
    if (domain.empty() || recorded != expected) {
        verdict.detail =
            "journal record for mutation " + std::to_string(mutationId) +
            " proves a different FIC PAM activation domain";
        return true;
    }
    verdict.safeToAttach = true;
    verdict.detail =
        "active FIC PAM slots are bound to active journal mutation " +
        std::to_string(mutationId);
    return true;
}

} // namespace

bool validatePamSlotAttach(
    const fic::platform::PamPlatformConfig& platformConfig,
    const fic::platform::PamCapabilityConfig& capability,
    const std::vector<std::string>& services,
    const fic::platform::PlatformExecutableResolver& executables,
    const std::filesystem::path& mutationJournalFile,
    const PamAuthUpdateTopologyManagerOptions& options,
    PamSlotAttachVerdict& verdict,
    std::string& error) {
    verdict = {};
    if (capability.capability !=
        fic::platform::PamCapability::AuthenticationLockout) {
        error =
            "FIC PAM slot attach validation is specific to "
            "enable_authentication_lockout";
        return false;
    }

    // Reuse the daemon classification: the managed-slot grammar, the strict
    // neutral/active/broken states and the full-strategy topology check are
    // owned by the topology manager, never re-implemented here.
    PamAuthUpdateTopologyManager manager(
        platformConfig, capability, services, executables, options);
    PamTopologyStatus status;
    std::string inspectError;
    if (!manager.inspect(status, inspectError)) {
        verdict.detail =
            "FIC PAM slot state cannot be proven safe (fail closed): " +
            inspectError;
        error.clear();
        return true;
    }

    if (status.state == PamTopologyState::Disabled ||
        (status.state == PamTopologyState::Enabled && !status.manageable)) {
        // Disabled means every slot carries the exact canonical neutral
        // content. Enabled without manageability is reported by inspect()
        // ONLY when all FIC slots are canonical neutral while an external
        // pam_faillock topology exists; attaching the permanent hooks adds
        // only inert neutral pam_deny slots there.
        verdict.safeToAttach = true;
        verdict.detail =
            "all FIC PAM slots carry the canonical neutral content";
        error.clear();
        return true;
    }

    if (status.state == PamTopologyState::Enabled) {
        if (!status.ownershipMutationId.has_value()) {
            verdict.detail =
                "FIC PAM slot topology is active without a mutation id";
            error.clear();
            return true;
        }
        error.clear();
        return proveJournalOwnership(
            *status.ownershipMutationId, capability, mutationJournalFile,
            verdict);
    }

    // Broken (malformed marker, modified body, partial or mixed strategy
    // topology) or unavailable (missing slot): fail closed. The package
    // never repairs, neutralizes or deletes such state.
    verdict.detail = status.detail.empty()
        ? "FIC PAM slot topology is broken or indeterminate"
        : "FIC PAM slot topology is not proven safe: " + status.detail;
    error.clear();
    return true;
}

} // namespace fic::identity::pam
