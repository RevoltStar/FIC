#pragma once
#include "rollback/MutationJournal.h"
#include "service/sssd/SssdVerifiedActivationAdapter.h"

namespace fic::service::sssd {
enum class SssdTransactionOperation { Apply, Refresh };
enum class SssdManagedParameter { OfflineCredentialsExpiration, CacheCredentials, AccountCacheExpiration };
struct SssdTransactionRequest {
    SssdTransactionOperation operation;
    PolicyRef policy;
    SssdManagedParameter parameter;
    SemanticValue value; // explicit Days or fixed true; no account default
    Deadline deadline;
};
enum class SssdTransactionStatus {
    Refused, OwnershipConflict, Unresolved, JournalFailed, CasRefused,
    PersistentFailed, ActivationFailed, FinalizationFailed, Success
};
struct SssdTransactionResult {
    SssdTransactionStatus status=SssdTransactionStatus::Refused;
    rollback::MutationId mutation=0;
    bool prepared=false, casRefused=false, installed=false, durable=false;
    bool sameValue=false, finalized=false, ownershipRetained=false, unresolved=false;
    SssdVerifiedActivationResult activation;
    std::vector<rollback::SssdAssignment> required, confirmed;
    std::string diagnostic;
    bool success() const {return status==SssdTransactionStatus::Success&&finalized&&durable&&activation.success();}
};
enum class SssdRecoveryClassification {
    NoTransition, NoEffectPrepared, PreviousImage, TargetImage,
    DurableTarget, ForeignDrift, JournalIndeterminate, RuntimeUnknown,
    ResidualMounts, UnsupportedSchema, TargetBytesUnattributed
};
struct SssdRecoveryInspection {
    SssdRecoveryClassification classification=SssdRecoveryClassification::JournalIndeterminate;
    rollback::MutationId mutation=0;
    rollback::SssdTransitionPhase phase=rollback::SssdTransitionPhase::Prepared;
    bool previousMatches=false, targetMatches=false, publicationDurable=false;
    bool activationPossible=false, noEffectResolvable=false;
    bool targetBytesMatch=false;
    std::vector<std::string> residuals;
    std::string diagnostic;
};
struct SssdReleaseRequest {
    PolicyRef policy;
    SssdManagedParameter parameter;
    rollback::SssdReleaseIntent intent=rollback::SssdReleaseIntent::ReleaseOnly;
    Deadline deadline;
};
enum class SssdReleaseStatus {
    Refused, OwnershipConflict, Unresolved, PersistentReleased, RuntimeVerified,
    ReleasedOffline, ReleasedAwaitingDisable, CleanupFailed, JournalFailed, Completed
};
struct SssdReleaseResult {
    SssdReleaseStatus status=SssdReleaseStatus::Refused;
    rollback::MutationId mutation=0;
    bool prepared=false, physicalReleased=false, casRefused=false, durable=false;
    bool offline=false, offlineVerified=false, finalized=false, unresolved=false;
    bool disableAcknowledged=false;
    SssdVerifiedActivationResult activation;
    std::vector<rollback::SssdAssignment> released, surviving;
    std::string diagnostic, stagedPath;
    bool success() const {
        return finalized&&!unresolved&&physicalReleased&&durable&&
            (offline?offlineVerified:activation.success())&&
            (status==SssdReleaseStatus::Completed||status==SssdReleaseStatus::ReleasedOffline);
    }
};
// Every API acquires the same deadline-bounded process-local resource mutex.
// Caller must hold daemon admission for the whole call; this is NOT a new
// interprocess lock or an authority to bypass daemon.lock/package state.
class SssdTransactionCoordinator {
public:
    explicit SssdTransactionCoordinator(rollback::MutationJournal& journal):journal_(journal){}
    SssdTransactionResult execute(const SssdTransactionRequest&);
    SssdRecoveryInspection inspect(Deadline);
    SssdRecoveryInspection resolveNoEffect(Deadline);
    SssdReleaseResult release(const SssdReleaseRequest&);
    // Inspection/no-effect resolution use the same shared-resource gate above.
    // No production DisableRelease acknowledgement API exists before I6.
private:
    rollback::MutationJournal& journal_;
};
namespace detail_i4 {
PolicyRef policyIdentity(SssdManagedParameter);
std::vector<rollback::SssdAssignment> targetAssignments(const DomainScopeReference&, SssdManagedParameter,const SemanticValue&);
std::string scopeIdentity(const DomainScopeReference&);
std::string renderAssignments(const std::vector<rollback::SssdAssignment>&);
#ifdef FIC_ACTIVATOR_TESTING
struct TransactionTestHooks {
    std::function<void(const std::string&)> checkpoint;
    const detail_i3::AdapterTestHooks* adapter=nullptr;
};
SssdTransactionResult executeForTests(rollback::MutationJournal&,const SssdTransactionRequest&,const TransactionTestHooks&);
SssdReleaseResult releaseForTests(rollback::MutationJournal&,const SssdReleaseRequest&,const TransactionTestHooks&);
#endif
}
} // namespace fic::service::sssd
