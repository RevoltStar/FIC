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
// Every API acquires the same deadline-bounded process-local resource mutex.
// Caller must hold daemon admission for the whole call; this is NOT a new
// interprocess lock or an authority to bypass daemon.lock/package state.
class SssdTransactionCoordinator {
public:
    explicit SssdTransactionCoordinator(rollback::MutationJournal& journal):journal_(journal){}
    SssdTransactionResult execute(const SssdTransactionRequest&);
    SssdRecoveryInspection inspect(Deadline);
    SssdRecoveryInspection resolveNoEffect(Deadline);
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
#endif
}
} // namespace fic::service::sssd
