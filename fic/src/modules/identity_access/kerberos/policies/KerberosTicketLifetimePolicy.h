#ifndef FIC_KERBEROS_TICKET_LIFETIME_POLICY_H
#define FIC_KERBEROS_TICKET_LIFETIME_POLICY_H

#include "modules/identity_access/kerberos/KerberosPolicy.h"
#include "modules/identity_access/kerberos/KerberosRollback.h"

#include <functional>

namespace fic::rollback {
class MutationJournal;
}

class KerberosTicketLifetimePolicy final : public KerberosPolicy {
public:
    KerberosTicketLifetimePolicy();
    explicit KerberosTicketLifetimePolicy(
        fic::identity::kerberos::KerberosConfigurationOptions options);

    static void setReusedProofHookForTests(std::function<void()> hook);

private:
    bool applyKerberos(
        fic::identity::kerberos::KerberosConfiguration& configuration,
        const std::string& expectedValue) override;

    // Journal reconciliation BEFORE anything is mutated: crash recovery,
    // active value change (ownership-safe release) and drift detection.
    enum class ReconciliationOutcome { Proceed, Reused, Failed };
    ReconciliationOutcome reconcileKerberosJournal(
        fic::identity::kerberos::KerberosConfiguration& configuration,
        fic::rollback::MutationJournal* journal,
        const PolicyRef& policyRef,
        const std::string& profileValue,
        bool& ok);

    // Same-value re-apply under the reused active record: no new provenance.
    bool reapplyExistingRelation(
        fic::identity::kerberos::KerberosConfiguration& configuration,
        const std::string& profileValue);

    // Fresh mutation: inspect exact BEFORE → Prepared → CAS structured edit
    // → full-graph reparse → effective verification → Applied.
    bool applyFreshMutation(
        fic::identity::kerberos::KerberosConfiguration& configuration,
        const std::string& profileValue,
        fic::rollback::MutationJournal* journal,
        const PolicyRef& policyRef);

    KerberosRollbackOptions rollbackOptions_;
};

#endif // FIC_KERBEROS_TICKET_LIFETIME_POLICY_H
