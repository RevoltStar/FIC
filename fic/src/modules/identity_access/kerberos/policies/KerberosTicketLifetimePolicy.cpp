#include "modules/identity_access/kerberos/policies/KerberosTicketLifetimePolicy.h"

#include "modules/identity_access/kerberos/KerberosRollback.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <utility>
#include <variant>

namespace {

// Single logical mutation identity of this policy: the root
// /etc/krb5.conf [libdefaults]/ticket_lifetime relation. The journal record
// resource is "<section>/<relation>".
constexpr const char* kSection = "libdefaults";
constexpr const char* kRelation = "ticket_lifetime";

std::string managedResource() {
    return std::string(kSection) + "/" + kRelation;
}

} // namespace

KerberosTicketLifetimePolicy::KerberosTicketLifetimePolicy()
    : KerberosTicketLifetimePolicy(
          fic::identity::kerberos::KerberosConfigurationOptions::production()) {
}

KerberosTicketLifetimePolicy::KerberosTicketLifetimePolicy(
    fic::identity::kerberos::KerberosConfigurationOptions options)
    : KerberosPolicy(std::move(options)) {
    rollbackOptions_.configuration = this->configurationOptions();
    this->policyName = "kerberos_ticket_lifetime";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(60, 86400, 36000);
}

bool KerberosTicketLifetimePolicy::applyKerberos(
    fic::identity::kerberos::KerberosConfiguration& configuration,
    const std::string& expectedValue) {
    const std::string profileValue = expectedValue + "s";
    const auto policyRef = this->policyRef();

    // Journal access with the established GRUB-style semantics: an existing
    // but unloadable journal fails closed; missing runtime paths (unit-test
    // environment) are tolerated.
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
        const ReconciliationOutcome outcome = reconcileKerberosJournal(
            configuration, journal, policyRef, profileValue, ok);
        if (!ok) {
            return false;
        }
        if (outcome == ReconciliationOutcome::Reused) {
            return reapplyExistingRelation(configuration, profileValue);
        }
    }
    return applyFreshMutation(configuration, profileValue, journal, policyRef);
}

KerberosTicketLifetimePolicy::ReconciliationOutcome
KerberosTicketLifetimePolicy::reconcileKerberosJournal(
    fic::identity::kerberos::KerberosConfiguration& configuration,
    fic::rollback::MutationJournal* journal,
    const PolicyRef& policyRef,
    const std::string& profileValue,
    bool& ok) {
    ok = true;
    for (const fic::rollback::MutationRecord& record :
         journal->activeRecords(policyRef)) {
        if (record.undo.backend !=
            fic::rollback::MutationBackend::Kerberos) {
            this->log(
                "Неожиданный backend активной mutation записи для " +
                    this->policyName + " (fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        const auto* undo =
            std::get_if<fic::rollback::UndoRestoreKerberosScalar>(
                &record.undo.payload);
        if (undo == nullptr || undo->section != kSection ||
            undo->relation != kRelation) {
            this->log(
                "Активная mutation запись не согласована с identity "
                "политики (fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }

        fic::identity::kerberos::KerberosRootScalarObservation observed;
        std::string error;
        if (!configuration.inspectRootScalar(
                kSection, kRelation, observed, error)) {
            this->log(
                "Не удалось проанализировать Kerberos профиль: " + error,
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        if (observed.externallyDefined || observed.duplicateInRoot) {
            this->log(
                "Kerberos target relation неоднозначна (внешний include "
                "или дубликат): apply отклонён (fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        const bool relationMissing =
            undo->beforeKind ==
                fic::rollback::KerberosBeforeKind::Missing &&
            !observed.relationInRoot;
        const bool lineRestored =
            undo->beforeKind ==
                fic::rollback::KerberosBeforeKind::Present &&
            observed.relationInRoot &&
            observed.rawLine == undo->beforeRawLine;
        if (undo->beforeKind ==
                fic::rollback::KerberosBeforeKind::Present &&
            !observed.relationInRoot) {
            // The relation FIC set was externally removed: the before-state
            // can never be restored unambiguously.
            this->log(
                "Target relation исчезла из /etc/krb5.conf: apply отклонён "
                "(fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        if (relationMissing || lineRestored) {
            // Ownership already released (crash window): resolve the stale
            // record and continue fresh.
            std::string resolveError;
            if (!journal->setStatus(
                    record.id,
                    fic::rollback::MutationStatus::RolledBack,
                    resolveError)) {
                this->log(
                    "Ошибка разрешения устаревшей Kerberos journal записи: " +
                        resolveError,
                    logLevel::ERROR);
                ok = false;
                return ReconciliationOutcome::Failed;
            }
            continue;
        }
        if (!observed.relationInRoot ||
            observed.value != undo->appliedValue) {
            this->log(
                "Kerberos значение [" + undo->section + "]/" +
                    undo->relation + " изменилось извне: apply отклонён "
                    "(fail closed)",
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        if (profileValue == undo->appliedValue) {
            // Same-value re-apply: keep the single active record, no new
            // provenance and no persistent mutation.
            if (record.status ==
                fic::rollback::MutationStatus::RollbackFailed) {
                // RollbackFailed semantics do not allow a silent apply
                // repair of the same value: the interrupted rollback must
                // be finished first (retry the policy disable).
                this->log(
                    "Активная Kerberos mutation в состоянии RollbackFailed "
                    "не может быть тихо исправлена apply (fail closed)",
                    logLevel::ERROR);
                ok = false;
                return ReconciliationOutcome::Failed;
            }
            if (record.status ==
                fic::rollback::MutationStatus::Prepared) {
                // Crash recovery: the checks above are a FRESH full-graph
                // AFTER proof (no external include, no duplicate, relation
                // exactly in the expected root topology with value ==
                // undo.appliedValue == desired). Promote the SAME mutation
                // id Prepared → Applied; no new record is created.
                std::string commitError;
                if (!journal->setStatus(
                        record.id,
                        fic::rollback::MutationStatus::Applied,
                        commitError)) {
                    this->log(
                        "Ошибка фиксации Kerberos recovery записи: " +
                            commitError,
                        logLevel::ERROR);
                    ok = false;
                    return ReconciliationOutcome::Failed;
                }
            }
            // Applied: the proven AFTER state is already idempotent.
            return ReconciliationOutcome::Reused;
        }
        // Active value change: ownership-safe release of the old mutation
        // (inverse delta) BEFORE the new value is prepared.
        const KerberosRollbackResult released =
            undoKerberosScalar(rollbackOptions_, *undo);
        if (released.conflict || !released.ok) {
            this->log(
                "Не удалось освободить предыдущую Kerberos mutation: " +
                    released.message,
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        std::string releaseError;
        if (!journal->setStatus(
                record.id,
                fic::rollback::MutationStatus::RolledBack,
                releaseError)) {
            this->log(
                "Ошибка закрытия предыдущей Kerberos mutation записи: " +
                    releaseError,
                logLevel::ERROR);
            ok = false;
            return ReconciliationOutcome::Failed;
        }
        return ReconciliationOutcome::Proceed;
    }
    return ReconciliationOutcome::Proceed;
}

bool KerberosTicketLifetimePolicy::reapplyExistingRelation(
    fic::identity::kerberos::KerberosConfiguration& configuration,
    const std::string& profileValue) {
    // The root relation already carries exactly the desired value under the
    // single active record: re-run the standard CAS structured edit as a
    // no-op without creating new provenance, then re-verify effectiveness
    // through the full graph.
    std::string error;
    if (!configuration.setScalar(kSection, kRelation, profileValue, error)) {
        this->log(
            "Could not apply Kerberos policy " + this->policyName + ": " +
                error,
            logLevel::ERROR);
        return false;
    }
    std::optional<std::string> observed;
    if (!configuration.tryGetScalarValue(
            kSection, kRelation, observed, error) ||
        observed != profileValue) {
        this->log(
            "Kerberos policy postcondition failed for " + this->policyName +
                ": " + (error.empty() ? "unexpected effective value" : error),
            logLevel::ERROR);
        return false;
    }
    this->log(
        "Kerberos policy " + this->policyName + " is persistent and effective",
        logLevel::INFO);
    return true;
}

bool KerberosTicketLifetimePolicy::applyFreshMutation(
    fic::identity::kerberos::KerberosConfiguration& configuration,
    const std::string& profileValue,
    fic::rollback::MutationJournal* journal,
    const PolicyRef& policyRef) {
    // Exact BEFORE inspection for the fresh mutation.
    fic::identity::kerberos::KerberosRootScalarObservation observed;
    std::string error;
    if (!configuration.inspectRootScalar(
            kSection, kRelation, observed, error)) {
        this->log(
            "Kerberos policy preflight failed for " + this->policyName +
                ": " + error,
            logLevel::ERROR);
        return false;
    }
    if (observed.externallyDefined || observed.duplicateInRoot) {
        this->log(
            "Kerberos target relation неоднозначна (внешний include или "
            "дубликат): apply отклонён (fail closed)",
            logLevel::ERROR);
        return false;
    }
    if (observed.relationInRoot && observed.value == profileValue) {
        // The effective target already equals the desired value through the
        // foreign configuration: FIC changes nothing and records nothing.
        this->log(
            "Kerberos policy " + this->policyName +
                " уже эффективна через foreign configuration",
            logLevel::INFO);
        return true;
    }

    // Prepared provenance BEFORE the persistent mutation, with the exact
    // before-state captured from the root document.
    fic::rollback::MutationId mutationId = 0;
    bool mutationPrepared = false;
    std::string journalError;
    if (journal != nullptr) {
        fic::rollback::UndoRestoreKerberosScalar undo;
        undo.section = kSection;
        undo.relation = kRelation;
        undo.appliedValue = profileValue;
        undo.beforeKind = observed.relationInRoot
            ? fic::rollback::KerberosBeforeKind::Present
            : fic::rollback::KerberosBeforeKind::Missing;
        undo.beforeRawLine =
            observed.relationInRoot ? observed.rawLine : std::string();
        undo.sectionExistedBefore = observed.sectionExistsInRoot;
        fic::rollback::MutationRecord record;
        record.policy = policyRef;
        record.resource = managedResource();
        record.undo = fic::rollback::UndoAction{
            fic::rollback::MutationBackend::Kerberos, std::move(undo)};
        if (!journal->prepareMutation(record, mutationId, journalError)) {
            this->log(
                "Ошибка подготовки Kerberos mutation записи: " + journalError,
                logLevel::ERROR);
            return false;
        }
        mutationPrepared = true;
    }

    // CAS/atomic structured edit of the root /etc/krb5.conf.
    auto prepared = configuration.prepareSetScalar(
        kSection, kRelation, profileValue);
    if (!prepared.ok()) {
        if (mutationPrepared) {
            std::string discardError;
            journal->discard(mutationId, discardError);
        }
        this->log(
            "Kerberos policy preflight failed for " + this->policyName +
                ": " + prepared.error,
            logLevel::ERROR);
        return false;
    }
    const auto execution = fic::identity::executePreparedFileChangeDetailed(
        std::move(prepared.change));
    if (execution.status !=
        fic::identity::PreparedChangeExecutionStatus::Committed) {
        // The transaction already attempted full compensation. Only a
        // fully compensated failure (typed result, no recovery errors)
        // may discard the fresh Prepared record; a failed/indeterminate
        // compensation keeps the record active for recovery.
        if (mutationPrepared && execution.status ==
                fic::identity::PreparedChangeExecutionStatus::Compensated) {
            std::string discardError;
            journal->discard(mutationId, discardError);
        }
        this->log(
            "Could not apply Kerberos policy " + this->policyName + ": " +
                execution.error,
            logLevel::ERROR);
        return false;
    }

    // Postcondition: reparse of the full profile graph proves the effective
    // target equals the applied value.
    std::optional<std::string> effective;
    if (!configuration.tryGetScalarValue(
            kSection, kRelation, effective, error) ||
        effective != profileValue) {
        // The file may already be mutated: the Prepared record stays active
        // and remains resolvable.
        this->log(
            "Kerberos policy postcondition failed for " + this->policyName +
                ": " + (error.empty() ? "unexpected effective value" : error),
            logLevel::ERROR);
        return false;
    }

    if (mutationPrepared) {
        if (!fic::rollback::commitMutation(mutationId, journalError)) {
            this->log(
                "Ошибка фиксации Kerberos mutation записи: " + journalError,
                logLevel::ERROR);
            return false;
        }
    }
    this->log(
        "Kerberos policy " + this->policyName + " is persistent and effective",
        logLevel::INFO);
    return true;
}
