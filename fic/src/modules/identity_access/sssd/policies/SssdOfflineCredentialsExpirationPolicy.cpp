#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"

#include "modules/identity_access/sssd/SssdRollback.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <utility>
#include <variant>

namespace {

// Single logical mutation identity of this policy: the FIC-owned drop-in
// setting. The journal record resource is "<section>/<option>".
constexpr const char* kSection = "pam";
constexpr const char* kOption = "offline_credentials_expiration";

std::string managedResource() {
    return std::string(kSection) + "/" + kOption;
}

} // namespace

SssdOfflineCredentialsExpirationPolicy::
SssdOfflineCredentialsExpirationPolicy(
    const fic::platform::PlatformExecutableResolver& executables)
    : SssdOfflineCredentialsExpirationPolicy(
          fic::identity::sssd::SssdConfigurationOptions::production(),
          executables,
          {"sssd.service"},
          {}) {
}

SssdOfflineCredentialsExpirationPolicy::
SssdOfflineCredentialsExpirationPolicy(
    fic::identity::sssd::SssdConfigurationOptions configurationOptions,
    const fic::platform::PlatformExecutableResolver& executables,
    std::vector<std::string> serviceUnits,
    fic::identity::sssd::SssdCommandRunner runner)
    : SssdPolicy(std::move(configurationOptions)),
      runtime_(executables, serviceUnits, std::move(runner)) {
    rollbackOptions_.configuration = this->configurationOptions();
    rollbackOptions_.serviceUnits = std::move(serviceUnits);
    rollbackOptions_.executables = &executables;
    rollbackOptions_.runner = runtime_.runner();
    this->policyName = "sssd_offline_credentials_expiration";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, 3650, 30);
}

namespace {

using fic::rollback::MutationBackend;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::identity::sssd::SssdManagedSnippetObservation;

// Journal reconciliation BEFORE anything is mutated: crash recovery
// (already-released ownership), active value change (ownership-safe release)
// and drift detection (fail closed). Returns:
//   Proceed     — no active record blocks the apply;
//   Reused      — the drop-in already carries exactly the desired value and
//                 the single active record proves FIC ownership: no new
//                 provenance, no persistent mutation;
//   Failed      — fail closed (error is set).
enum class ReconciliationOutcome { Proceed, Reused, Failed };

bool classifyObservedDropIn(
    SssdPolicy& policy,
    const SssdManagedSnippetObservation& observed,
    bool& ok) {
    using DropInState = SssdManagedSnippetObservation::DropInState;
    if (observed.dropInState == DropInState::Unsafe ||
        observed.dropInState == DropInState::Malformed ||
        !observed.laterConflictingSnippets.empty()) {
        policy.log(
            "FIC-owned SSSD drop-in повреждён или перекрыт, apply "
            "невозможен (fail closed)",
            logLevel::ERROR);
        ok = false;
        return false;
    }
    return true;
}

ReconciliationOutcome reconcileSssdJournal(
    SssdOfflineCredentialsExpirationPolicy& policy,
    fic::identity::sssd::SssdConfiguration& configuration,
    const SssdRollbackOptions& rollbackOptions,
    MutationJournal* journal,
    const PolicyRef& policyRef,
    const std::string& expectedValue,
    bool& ok) {
    ok = true;
    const std::string activeValue = expectedValue;
    for (const MutationRecord& record : journal->activeRecords(policyRef)) {
        if (record.undo.backend != MutationBackend::Sssd) {
            policy.log(
                "Неожиданный backend активной mutation записи для " +
                    std::string(policy.policyName) + " (fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        const auto* undo =
            std::get_if<fic::rollback::UndoRemoveSssdManagedSetting>(
                &record.undo.payload);
        if (undo == nullptr || undo->section != kSection ||
            undo->option != kOption) {
            policy.log(
                "Активная mutation запись не согласована с identity "
                "политики (fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }

        SssdManagedSnippetObservation observed;
        std::string observationError;
        if (!configuration.inspectManagedSnippet(
                kSection, kOption, observed, observationError)) {
            policy.log(
                "Не удалось проанализировать SSSD топологию: " +
                    observationError,
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        if (!classifyObservedDropIn(policy, observed, ok)) {
            return ReconciliationOutcome::Failed;
        }
        if (!observed.optionPresent) {
            // Ownership already released (crash window after release):
            // resolve the stale record and continue fresh.
            std::string resolveError;
            if (!journal->setStatus(
                    record.id, MutationStatus::RolledBack, resolveError)) {
                policy.log(
                    "Ошибка разрешения устаревшей SSSD journal записи: " +
                        resolveError,
                    logLevel::ERROR);
                ok = false;
                return ReconciliationOutcome::Failed;
            }
            continue;
        }
        if (observed.optionValue != undo->appliedValue) {
            policy.log(
                "FIC-owned SSSD значение изменилось извне ('" +
                    observed.optionValue + "' вместо '" +
                    undo->appliedValue + "'): apply отклонён (fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        if (activeValue == undo->appliedValue) {
            // Same-value re-apply: keep the single active record, no new
            // provenance and no persistent mutation.
            return ReconciliationOutcome::Reused;
        }
        // Active value change: ownership-safe release of the old mutation
        // BEFORE the new value is prepared. The previous foreign value is
        // never restored from anywhere — it becomes effective naturally.
        const SssdRollbackResult released =
            undoSssdManagedSetting(rollbackOptions, *undo);
        if (released.conflict || !released.ok) {
            policy.log(
                "Не удалось освободить предыдущую SSSD mutation: " +
                    released.message,
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        std::string releaseError;
        if (!journal->setStatus(
                record.id, MutationStatus::RolledBack, releaseError)) {
            policy.log(
                "Ошибка закрытия предыдущей SSSD mutation записи: " +
                    releaseError,
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        return ReconciliationOutcome::Proceed;
    }
    return ReconciliationOutcome::Proceed;
}

} // namespace

bool SssdOfflineCredentialsExpirationPolicy::applySssd(
    fic::identity::sssd::SssdConfiguration& configuration,
    const std::string& expectedValue) {
    const auto policyRef = this->policyRef();

    // Journal access with the established GRUB-style semantics: an existing
    // but unloadable journal fails closed; missing runtime paths (unit-test
    // environment without initialized FIC runtime) are tolerated.
    std::string journalError;
    auto* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr && !journalError.empty()) {
        this->log(
            "Mutation journal недоступен для " + this->policyName + ": " +
                journalError,
            logLevel::ERROR);
        return false;
    }

    if (journal != nullptr) {
        bool ok = true;
        const ReconciliationOutcome outcome = reconcileSssdJournal(
            *this, configuration, rollbackOptions_, journal, policyRef,
            expectedValue, ok);
        if (!ok) {
            return false;
        }
        if (outcome == ReconciliationOutcome::Reused) {
            return reapplyExistingManagedValue(configuration, expectedValue);
        }
    }
    return applyFreshManagedValue(configuration, expectedValue, journal,
                                  policyRef);
}

bool SssdOfflineCredentialsExpirationPolicy::reapplyExistingManagedValue(
    fic::identity::sssd::SssdConfiguration& configuration,
    const std::string& expectedValue) {
    // The FIC-owned drop-in already carries exactly the desired value under
    // the single active record: no new provenance is created and the
    // persistent mutation is a no-op; runtime effectiveness (restart of an
    // active SSSD + verification) is re-enforced.
    auto prepared = configuration.prepareManagedSnippetValue(
        kSection, kOption, expectedValue);
    if (!prepared.ok()) {
        this->log(
            "SSSD policy preflight failed for " + this->policyName + ": " +
                prepared.error,
            logLevel::ERROR);
        return false;
    }
    prepared = runtime_.attach(std::move(prepared.change));
    if (!prepared.ok()) {
        this->log(
            "SSSD runtime preflight failed for " + this->policyName + ": " +
                prepared.error,
            logLevel::ERROR);
        return false;
    }
    std::string executionError;
    if (!fic::identity::executePreparedFileChange(
            std::move(prepared.change), executionError)) {
        this->log(
            "Could not apply SSSD policy " + this->policyName + ": " +
                executionError,
            logLevel::ERROR);
        return false;
    }
    this->log(
        "SSSD policy " + this->policyName + " is persistent and effective",
        logLevel::INFO);
    return true;
}

bool SssdOfflineCredentialsExpirationPolicy::applyFreshManagedValue(
    fic::identity::sssd::SssdConfiguration& configuration,
    const std::string& expectedValue,
    fic::rollback::MutationJournal* journal,
    const PolicyRef& policyRef) {
    // Topology/semantics inspection for the fresh mutation decision.
    fic::identity::sssd::SssdManagedSnippetObservation observed;
    std::string error;
    if (!configuration.inspectManagedSnippet(
            kSection, kOption, observed, error)) {
        this->log(
            "SSSD policy preflight failed for " + this->policyName + ": " +
                error,
            logLevel::ERROR);
        return false;
    }
    if (!observed.optionPresent && observed.effectiveValue.has_value() &&
        *observed.effectiveValue == expectedValue) {
        // Desired value is already effective exclusively through the
        // foreign configuration: FIC changes nothing and records nothing.
        this->log(
            "SSSD policy " + this->policyName +
                " уже эффективна через foreign configuration",
            logLevel::INFO);
        return true;
    }
    if (observed.optionPresent) {
        // A FIC-owned drop-in option without provenance (or with unexpected
        // content) is unattributable owned state: fail closed.
        this->log(
            "FIC-owned SSSD drop-in содержит значение '" +
                observed.optionValue + "' без активной mutation записи "
                "(fail closed)",
            logLevel::ERROR);
        return false;
    }

    // Prepared provenance BEFORE the persistent mutation.
    fic::rollback::MutationId mutationId = 0;
    bool mutationPrepared = false;
    std::string journalError;
    if (journal != nullptr) {
        fic::rollback::MutationRecord record;
        record.policy = policyRef;
        record.resource = managedResource();
        record.undo = fic::rollback::UndoAction{
            MutationBackend::Sssd,
            fic::rollback::UndoRemoveSssdManagedSetting{
                kSection, kOption, expectedValue}};
        if (!journal->prepareMutation(record, mutationId, journalError)) {
            this->log(
                "Ошибка подготовки SSSD mutation записи: " + journalError,
                logLevel::ERROR);
            return false;
        }
        mutationPrepared = true;
    }

    // Install/update the FIC-owned drop-in and enforce the runtime
    // postcondition (restart of an active SSSD + effective verification)
    // through the existing SssdRuntime participant.
    auto prepared = configuration.prepareManagedSnippetValue(
        kSection, kOption, expectedValue);
    if (!prepared.ok()) {
        // Fail closed BEFORE any system change: the fresh Prepared record
        // never mutated anything and can be discarded.
        if (mutationPrepared) {
            std::string discardError;
            journal->discard(mutationId, discardError);
        }
        this->log(
            "SSSD policy preflight failed for " + this->policyName + ": " +
                prepared.error,
            logLevel::ERROR);
        return false;
    }
    prepared = runtime_.attach(std::move(prepared.change));
    if (!prepared.ok()) {
        if (mutationPrepared) {
            std::string discardError;
            journal->discard(mutationId, discardError);
        }
        this->log(
            "SSSD runtime preflight failed for " + this->policyName + ": " +
                prepared.error,
            logLevel::ERROR);
        return false;
    }

    std::string executionError;
    if (!fic::identity::executePreparedFileChange(
            std::move(prepared.change), executionError)) {
        // The transaction already attempted full compensation (persistent
        // rollback + runtime restore). When the compensation completed, the
        // fresh Prepared record can be discarded; a failed/indeterminate
        // compensation keeps the record active for recovery (existing
        // journal invariants).
        if (mutationPrepared &&
            executionError.find("recovery error") == std::string::npos) {
            std::string discardError;
            journal->discard(mutationId, discardError);
        }
        this->log(
            "Could not apply SSSD policy " + this->policyName + ": " +
                executionError,
            logLevel::ERROR);
        return false;
    }

    // Effective verification of the FIC-owned source AFTER the mutation.
    fic::identity::sssd::SssdManagedSnippetObservation verified;
    if (!configuration.inspectManagedSnippet(
            kSection, kOption, verified, error) ||
        !verified.optionPresent ||
        verified.optionValue != expectedValue ||
        !verified.laterConflictingSnippets.empty()) {
        // The system may already be mutated: the Prepared record stays
        // active and remains resolvable.
        this->log(
            "SSSD policy postcondition failed for " + this->policyName,
            logLevel::ERROR);
        return false;
    }

    if (mutationPrepared) {
        if (!fic::rollback::commitMutation(mutationId, journalError)) {
            this->log(
                "Ошибка фиксации SSSD mutation записи: " + journalError,
                logLevel::ERROR);
            return false;
        }
    }

    this->log(
        "SSSD policy " + this->policyName + " is persistent and effective",
        logLevel::INFO);
    return true;
}
