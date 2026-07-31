#ifndef FIC_IDENTITY_ACCESS_KERBEROS_POLICY_H
#define FIC_IDENTITY_ACCESS_KERBEROS_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"

#include <string>

class KerberosPolicy : public IdentityAccessPolicy {
public:
    ~KerberosPolicy() override = default;
    bool apply() final;

protected:
    KerberosPolicy();

    virtual bool applyKerberos(const std::string& expectedValue) = 0;
};

#endif // FIC_IDENTITY_ACCESS_KERBEROS_POLICY_H
