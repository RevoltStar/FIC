#ifndef FIC_KERBEROS_TICKET_LIFETIME_POLICY_H
#define FIC_KERBEROS_TICKET_LIFETIME_POLICY_H

#include "modules/identity_access/kerberos/KerberosPolicy.h"

class KerberosTicketLifetimePolicy final : public KerberosPolicy {
public:
    KerberosTicketLifetimePolicy();
    explicit KerberosTicketLifetimePolicy(
        fic::identity::kerberos::KerberosConfigurationOptions options);

private:
    bool applyKerberos(
        fic::identity::kerberos::KerberosConfiguration& configuration,
        const std::string& expectedValue) override;
};

#endif // FIC_KERBEROS_TICKET_LIFETIME_POLICY_H
