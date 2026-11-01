#pragma once
#include "modules/identity_access/sssd/SssdPolicy.h"
#include "platform/PlatformExecutableResolver.h"
class SssdOfflineCredentialsExpirationPolicy final : public SssdPolicy {
public:
    explicit SssdOfflineCredentialsExpirationPolicy(const fic::platform::PlatformExecutableResolver&);
};
