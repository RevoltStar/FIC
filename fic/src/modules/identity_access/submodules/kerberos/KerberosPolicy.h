#ifndef FIC_IDENTITY_ACCESS_KERBEROS_POLICY_H
#define FIC_IDENTITY_ACCESS_KERBEROS_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/submodules/kerberos/KerberosConfiguration.h"

#include <string>

class KerberosPolicy : public IdentityAccessPolicy {
public:
    ~KerberosPolicy() override = default;
    bool apply() final;

protected:
    explicit KerberosPolicy(
        fic::identity::kerberos::KerberosConfigurationOptions options =
            fic::identity::kerberos::KerberosConfigurationOptions::production());

    virtual bool applyKerberos(
        fic::identity::kerberos::KerberosConfiguration& configuration,
        const std::string& expectedValue) = 0;

private:
    fic::identity::kerberos::KerberosConfiguration configuration_;
};

#endif // FIC_IDENTITY_ACCESS_KERBEROS_POLICY_H
