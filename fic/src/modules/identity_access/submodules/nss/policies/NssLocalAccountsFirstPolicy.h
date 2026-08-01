#ifndef FIC_NSS_LOCAL_ACCOUNTS_FIRST_POLICY_H
#define FIC_NSS_LOCAL_ACCOUNTS_FIRST_POLICY_H

#include "modules/identity_access/submodules/nss/NssPolicy.h"

class NssLocalAccountsFirstPolicy final : public NssPolicy {
public:
    NssLocalAccountsFirstPolicy();
    explicit NssLocalAccountsFirstPolicy(
        fic::identity::nss::NssConfigurationOptions options);

private:
    bool applyNss(
        fic::identity::nss::NssConfiguration& configuration,
        const std::string& expectedValue) override;
};

#endif // FIC_NSS_LOCAL_ACCOUNTS_FIRST_POLICY_H
