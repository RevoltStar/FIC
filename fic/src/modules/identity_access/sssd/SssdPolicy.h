#pragma once
#include "modules/identity_access/IdentityAccessPolicy.h"
#include "service/sssd/SssdTransactionCoordinator.h"

// The only production SSSD policy writer is the I4/I5 coordinator. Legacy
// configuration/runtime helpers remain for historical provenance tests only.
class SssdPolicy : public IdentityAccessPolicy {
    const fic::service::sssd::SssdManagedParameter parameter_;
protected:
    explicit SssdPolicy(fic::service::sssd::SssdManagedParameter);
public:
    bool apply() final;
    fic::service::sssd::SssdManagedParameter managedParameter() const { return parameter_; }
};
