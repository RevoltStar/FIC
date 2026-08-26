#ifndef FIC_SSSD_OFFLINE_CREDENTIALS_EXPIRATION_POLICY_H
#define FIC_SSSD_OFFLINE_CREDENTIALS_EXPIRATION_POLICY_H

#include "modules/identity_access/sssd/SssdPolicy.h"
#include "modules/identity_access/sssd/SssdRuntime.h"

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

    fic::identity::sssd::SssdRuntime runtime_;
};

#endif // FIC_SSSD_OFFLINE_CREDENTIALS_EXPIRATION_POLICY_H
