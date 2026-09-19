#ifndef FIC_SSSD_OFFLINE_CREDENTIALS_EXPIRATION_POLICY_H
#define FIC_SSSD_OFFLINE_CREDENTIALS_EXPIRATION_POLICY_H

#include "modules/identity_access/sssd/SssdPolicy.h"
#include "modules/identity_access/sssd/SssdRollback.h"
#include "modules/identity_access/sssd/SssdRuntime.h"

namespace fic::rollback {
class MutationJournal;
}

class SssdOfflineCredentialsExpirationPolicy final : public SssdPolicy {
public:
    explicit SssdOfflineCredentialsExpirationPolicy(
        const fic::platform::PlatformExecutableResolver& executables);

    SssdOfflineCredentialsExpirationPolicy(
        fic::identity::sssd::SssdConfigurationOptions configurationOptions,
        const fic::platform::PlatformExecutableResolver& executables,
        std::vector<std::string> serviceUnits,
        fic::identity::sssd::SssdCommandRunner runner);

private:
    bool applySssd(
        fic::identity::sssd::SssdConfiguration& configuration,
        const std::string& expectedValue) override;

    // Same-value re-apply under the reused active record: no new
    // provenance, runtime effectiveness is re-enforced.
    bool reapplyExistingManagedValue(
        fic::identity::sssd::SssdConfiguration& configuration,
        const std::string& expectedValue);

    // Fresh mutation: Prepared provenance → FIC drop-in install →
    // effective verification → SSSD restart verification → Applied.
    bool applyFreshManagedValue(
        fic::identity::sssd::SssdConfiguration& configuration,
        const std::string& expectedValue,
        fic::rollback::MutationJournal* journal,
        const PolicyRef& policyRef);

    fic::identity::sssd::SssdRuntime runtime_;
    SssdRollbackOptions rollbackOptions_;
};

#endif // FIC_SSSD_OFFLINE_CREDENTIALS_EXPIRATION_POLICY_H
