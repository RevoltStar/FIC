#include "service/sssd/SssdRelationValidator.h"
namespace fic::service::sssd {
RelationResult validateRelations(const EffectiveConfiguration& cfg){
    RelationResult out;out.issues=cfg.issues;
    for(const auto& name:cfg.scope.data().selected){
        auto found=cfg.scope.data().domains.find(name);if(found==cfg.scope.data().domains.end())continue;
        const auto& domain=found->second;if(!domain.enabled)continue;
        auto status=SemanticStatus::Validated;const auto sec="domain/"+name;
        const auto& values=cfg.domains.at(name);
        if(domain.provider!=ProviderClass::LdapPassword)status=SemanticStatus::UnsupportedProvider;
        else if(!domain.issues.empty())status=SemanticStatus::UnknownSemantics;
        else if(cfg.offlineDays.status!=SemanticStatus::Validated||values.accountDays.status!=SemanticStatus::Validated||values.cacheCredentials.status!=SemanticStatus::Validated||values.cachedAuthSeconds.status!=SemanticStatus::Validated)status=SemanticStatus::UnknownSemantics;
        else {
            auto offline=std::get_if<Days>(&cfg.offlineDays.value);auto account=std::get_if<Days>(&values.accountDays.value);
            if(!offline||!account)status=SemanticStatus::UnknownSemantics;
            else if(account->value!=0&&(offline->value==0||account->value<offline->value)){
                status=SemanticStatus::Conflict;out.issues.push_back({status,sec,"account_cache_expiration","LDAP relation conflict: account="+std::to_string(account->value)+", offline="+std::to_string(offline->value)+"; require account=0 or offline>0 and account>=offline (independent of cache_credentials)"});
            }
        }
        out.domains[name]=status;
        if(status!=SemanticStatus::Validated&&status!=SemanticStatus::Conflict)out.issues.push_back({status,sec,"relation","LDAP semantic relation not proven for selected domain"});
    }
    if(!out.issues.empty())out.status=out.issues.front().status;
    // Preserve a discovered conflict even alongside unsupported coverage; never global PASS.
    for(const auto& issue:out.issues)if(issue.status==SemanticStatus::Conflict)out.status=SemanticStatus::Conflict;
    return out;
}
}
