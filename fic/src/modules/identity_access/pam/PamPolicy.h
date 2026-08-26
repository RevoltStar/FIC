#ifndef FIC_IDENTITY_ACCESS_PAM_POLICY_H
#define FIC_IDENTITY_ACCESS_PAM_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"

#include <string>

class PamPolicy : public IdentityAccessPolicy {
public:
    ~PamPolicy() override = default;
    bool apply() final;

protected:
    PamPolicy();

    virtual bool applyPam(const std::string& expectedValue) = 0;
};

#endif // FIC_IDENTITY_ACCESS_PAM_POLICY_H
