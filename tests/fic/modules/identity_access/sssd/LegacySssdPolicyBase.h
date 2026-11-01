// Historical pre-I6 specimen, TEST ONLY; not a production policy path.
#ifndef FIC_TEST_LEGACY_SSSD_POLICY_BASE_H
#define FIC_TEST_LEGACY_SSSD_POLICY_BASE_H

#include "modules/identity_access/IdentityAccessPolicy.h"
#include "modules/identity_access/sssd/SssdConfiguration.h"

#include <string>

class LegacySssdPolicyBase : public IdentityAccessPolicy {
public:
    ~LegacySssdPolicyBase() override = default;
    bool apply() final;

protected:
    explicit LegacySssdPolicyBase(
        fic::identity::sssd::SssdConfigurationOptions options =
            fic::identity::sssd::SssdConfigurationOptions::production());

    virtual bool applySssd(
        fic::identity::sssd::SssdConfiguration& configuration,
        const std::string& expectedValue) = 0;

    const fic::identity::sssd::SssdConfigurationOptions&
    configurationOptions() const {
        return configurationOptions_;
    }

private:
    fic::identity::sssd::SssdConfigurationOptions configurationOptions_;
    fic::identity::sssd::SssdConfiguration configuration_;
};

#endif // FIC_TEST_LEGACY_SSSD_POLICY_BASE_H
