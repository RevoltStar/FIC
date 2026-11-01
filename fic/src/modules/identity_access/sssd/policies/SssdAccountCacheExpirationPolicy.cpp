#include "modules/identity_access/sssd/policies/SssdAccountCacheExpirationPolicy.h"
#include "modules/identity_access/sssd/SssdDaysPolicyTypeValue.h"
SssdAccountCacheExpirationPolicy::SssdAccountCacheExpirationPolicy()
    :SssdPolicy(fic::service::sssd::SssdManagedParameter::AccountCacheExpiration) {
    policyTypeValue=std::make_unique<SssdDaysPolicyTypeValue>();
}
