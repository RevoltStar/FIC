#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"
#include "modules/identity_access/sssd/SssdDaysPolicyTypeValue.h"
SssdOfflineCredentialsExpirationPolicy::SssdOfflineCredentialsExpirationPolicy(
    const fic::platform::PlatformExecutableResolver&)
    :SssdPolicy(fic::service::sssd::SssdManagedParameter::OfflineCredentialsExpiration) {
    policyTypeValue=std::make_unique<SssdDaysPolicyTypeValue>(30);
    addRecommendedDependency({"IDENTITY_ACCESS","SSSD","sssd_cache_credentials"});
}
