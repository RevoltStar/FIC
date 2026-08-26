#ifndef FIC_IDENTITY_ACCESS_NSS_POLICY_H
#define FIC_IDENTITY_ACCESS_NSS_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/nss/NssConfiguration.h"

#include <string>

class NssPolicy : public IdentityAccessPolicy {
public:
    ~NssPolicy() override = default;
    bool apply() final;

protected:
    explicit NssPolicy(
        fic::identity::nss::NssConfigurationOptions options =
            fic::identity::nss::NssConfigurationOptions::production());

    virtual bool applyNss(
        fic::identity::nss::NssConfiguration& configuration,
        const std::string& expectedValue) = 0;

private:
    fic::identity::nss::NssConfiguration configuration_;
};

#endif // FIC_IDENTITY_ACCESS_NSS_POLICY_H
