#ifndef FIC_IDENTITY_ACCESS_SSSD_POLICY_H
#define FIC_IDENTITY_ACCESS_SSSD_POLICY_H

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/submodules/sssd/SssdConfiguration.h"

#include <string>

class SssdPolicy : public IdentityAccessPolicy {
public:
    ~SssdPolicy() override = default;
    bool apply() final;

protected:
    explicit SssdPolicy(
        fic::identity::sssd::SssdConfigurationOptions options =
            fic::identity::sssd::SssdConfigurationOptions::production());

    virtual bool applySssd(
        fic::identity::sssd::SssdConfiguration& configuration,
        const std::string& expectedValue) = 0;

private:
    fic::identity::sssd::SssdConfiguration configuration_;
};

#endif // FIC_IDENTITY_ACCESS_SSSD_POLICY_H
