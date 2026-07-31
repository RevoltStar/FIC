#ifndef FIC_IDENTITY_ACCESS_NSS_POLICY_H
#define FIC_IDENTITY_ACCESS_NSS_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"

#include <string>

class NssPolicy : public IdentityAccessPolicy {
public:
    ~NssPolicy() override = default;
    bool apply() final;

protected:
    NssPolicy();

    virtual bool applyNss(const std::string& expectedValue) = 0;
};

#endif // FIC_IDENTITY_ACCESS_NSS_POLICY_H
