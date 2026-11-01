#include "modules/identity_access/sssd/policies/SssdCacheCredentialsPolicy.h"
SssdCacheCredentialsPolicy::SssdCacheCredentialsPolicy()
    :SssdPolicy(fic::service::sssd::SssdManagedParameter::CacheCredentials) {
    policyTypeValue=std::make_unique<FixedPolicyTypeValue>("true");
}
