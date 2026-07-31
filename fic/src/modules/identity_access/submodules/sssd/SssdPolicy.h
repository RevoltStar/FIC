#ifndef FIC_IDENTITY_ACCESS_SSSD_POLICY_H
#define FIC_IDENTITY_ACCESS_SSSD_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"

#include <string>

class SssdPolicy : public IdentityAccessPolicy {
public:
    ~SssdPolicy() override = default;
    bool apply() final;

protected:
    SssdPolicy();

    virtual bool applySssd(const std::string& expectedValue) = 0;
};

#endif // FIC_IDENTITY_ACCESS_SSSD_POLICY_H
