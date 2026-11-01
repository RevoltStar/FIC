#pragma once
#include "service/sssd/SssdTransactionCoordinator.h"
#include <fic/policy/Policy.h>
#include "policy/registry/PolicyRegistry.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <charconv>

class SssdPolicy;
namespace fic::service::sssd {
namespace detail_i6 {
inline void verifyRegisteredPolicySet(const PolicyRegistry& registry) {
    unsigned count=0;
    for(const auto& ref:registry.policyRefs())if(ref.moduleName=="IDENTITY_ACCESS"&&ref.submoduleName=="SSSD") {
        ++count;bool known=false;
        for(const auto parameter:{SssdManagedParameter::OfflineCredentialsExpiration,SssdManagedParameter::CacheCredentials,SssdManagedParameter::AccountCacheExpiration})
            known|=ref==detail_i4::policyIdentity(parameter);
        if(!known)throw std::runtime_error("SSSD registry contains an unsupported policy; complete coverage cannot be asserted");
    }
    if(count!=3)throw std::runtime_error("SSSD registry requires all three production policies");
}
}
// Sealed production binding; raw I4 backend requests retain their standalone
// contract. Every production SssdPolicy supplies this guard. No config reader,
// migration, registry cache or caller-supplied ENABLE boolean.
class SssdApplyIntent {
    friend class ::SssdPolicy;
    Policy* policy_;
    std::string path_, value_;
    AtomicTargetState state_;
    SssdApplyIntent(Policy& policy, std::string value):policy_(&policy),value_(std::move(value)) {
        std::string error;
        if(!policy.captureConfigurationVersion(path_,state_,error))throw std::runtime_error(error);
    }
public:
    void verify(const SssdTransactionRequest& request) const {
        std::string currentPath,error;AtomicTargetState current;
        const auto currentValue=policy_->getValue();
        const auto expected=std::get_if<Days>(&request.value);
        const auto cache=std::get_if<bool>(&request.value);
        unsigned days=0;const auto parsed=std::from_chars(value_.data(),value_.data()+value_.size(),days);
        const bool matchesValue=expected?(parsed.ec==std::errc{}&&parsed.ptr==value_.data()+value_.size()&&days==expected->value):
            cache&&*cache&&value_=="true";
        const auto config=(fic::core::FicRuntimePaths::get().configDir/"IDENTITY_ACCESS.conf").string();
        const auto* registry=policy_->ownerRegistry();
        if(!registry||registry->findPolicy(request.policy)!=policy_)
            throw std::runtime_error("SSSD apply requires its current owning PolicyRegistry");
        detail_i6::verifyRegisteredPolicySet(*registry);
        for(const auto parameter:{SssdManagedParameter::OfflineCredentialsExpiration,SssdManagedParameter::CacheCredentials,SssdManagedParameter::AccountCacheExpiration}) {
            const auto* member=registry->findPolicy(detail_i4::policyIdentity(parameter));
            std::string memberPath;AtomicTargetState memberState;
            if(!member||member->ownerRegistry()!=registry||!member->captureConfigurationVersion(memberPath,memberState,error)||memberPath!=path_)
                throw std::runtime_error("complete current SSSD registry/configuration generation unproven: "+error);
        }

        if(policy_->policyRef()!=request.policy||!policy_->isEnabled()||!currentValue||*currentValue!=value_||!matchesValue||
           path_!=config||state_.owner!=0||(state_.mode&0022)||
           !policy_->captureConfigurationVersion(currentPath,current,error)||currentPath!=path_||
           !AtomicFileWriter::targetStateMatches(path_,state_,&error)||
           !AtomicFileWriter::ensureTargetDurableIfCurrentState(path_,state_,&error))
            throw std::runtime_error("SSSD authoritative ENABLE/value/configuration generation unproven: "+error);
    }
};
}
