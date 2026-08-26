#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"

#include <utility>

SssdOfflineCredentialsExpirationPolicy::
SssdOfflineCredentialsExpirationPolicy(
    const fic::platform::PlatformExecutableResolver& executables)
    : SssdOfflineCredentialsExpirationPolicy(
          fic::identity::sssd::SssdConfigurationOptions::production(),
          executables,
          {"sssd.service"},
          {}) {
}

SssdOfflineCredentialsExpirationPolicy::
SssdOfflineCredentialsExpirationPolicy(
    fic::identity::sssd::SssdConfigurationOptions configurationOptions,
    const fic::platform::PlatformExecutableResolver& executables,
    std::vector<std::string> serviceUnits,
    fic::identity::sssd::SssdCommandRunner runner)
    : SssdPolicy(std::move(configurationOptions)),
      runtime_(executables, std::move(serviceUnits), std::move(runner)) {
    this->policyName = "sssd_offline_credentials_expiration";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(0, 3650, 30);
}

bool SssdOfflineCredentialsExpirationPolicy::applySssd(
    fic::identity::sssd::SssdConfiguration& configuration,
    const std::string& expectedValue) {
    auto prepared = configuration.prepareSetValue(
        "pam", "offline_credentials_expiration", expectedValue);
    if (!prepared.ok()) {
        this->log(
            "SSSD policy preflight failed for " + this->policyName + ": " +
                prepared.error,
            logLevel::ERROR);
        return false;
    }
    prepared = runtime_.attach(std::move(prepared.change));
    if (!prepared.ok()) {
        this->log(
            "SSSD runtime preflight failed for " + this->policyName + ": " +
                prepared.error,
            logLevel::ERROR);
        return false;
    }

    std::string error;
    if (!fic::identity::executePreparedFileChange(
            std::move(prepared.change), error)) {
        this->log(
            "Could not apply SSSD policy " + this->policyName + ": " + error,
            logLevel::ERROR);
        return false;
    }
    this->log(
        "SSSD policy " + this->policyName + " is persistent and effective",
        logLevel::INFO);
    return true;
}
