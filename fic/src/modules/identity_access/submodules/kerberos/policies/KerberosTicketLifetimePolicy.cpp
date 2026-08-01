#include "modules/identity_access/submodules/kerberos/policies/KerberosTicketLifetimePolicy.h"

#include <utility>

KerberosTicketLifetimePolicy::KerberosTicketLifetimePolicy()
    : KerberosTicketLifetimePolicy(
          fic::identity::kerberos::KerberosConfigurationOptions::production()) {
}

KerberosTicketLifetimePolicy::KerberosTicketLifetimePolicy(
    fic::identity::kerberos::KerberosConfigurationOptions options)
    : KerberosPolicy(std::move(options)) {
    this->policyName = "kerberos_ticket_lifetime";
    this->policyTypeValue =
        std::make_unique<IntPolicyTypeValue>(60, 86400, 36000);
}

bool KerberosTicketLifetimePolicy::applyKerberos(
    fic::identity::kerberos::KerberosConfiguration& configuration,
    const std::string& expectedValue) {
    const std::string profileValue = expectedValue + "s";
    std::string error;
    if (!configuration.setScalar(
            "libdefaults", "ticket_lifetime", profileValue, error)) {
        this->log(
            "Could not apply Kerberos policy " + this->policyName + ": " +
                error,
            logLevel::ERROR);
        return false;
    }
    std::optional<std::string> observed;
    if (!configuration.tryGetScalarValue(
            "libdefaults", "ticket_lifetime", observed, error) ||
        observed != profileValue) {
        this->log(
            "Kerberos policy postcondition failed for " + this->policyName +
                ": " + (error.empty() ? "unexpected effective value" : error),
            logLevel::ERROR);
        return false;
    }
    this->log(
        "Kerberos policy " + this->policyName + " is persistent and effective",
        logLevel::INFO);
    return true;
}
