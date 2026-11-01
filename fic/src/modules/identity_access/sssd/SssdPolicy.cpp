#include "modules/identity_access/sssd/SssdPolicy.h"
#include "service/sssd/SssdApplyIntent.h"
#include "rollback/DaemonMutationJournal.h"
#include <charconv>

SssdPolicy::SssdPolicy(fic::service::sssd::SssdManagedParameter parameter)
    :IdentityAccessPolicy("SSSD"),parameter_(parameter) {
    policyName=fic::service::sssd::detail_i4::policyIdentity(parameter).policyName;
}
bool SssdPolicy::apply() {
    namespace s=fic::service::sssd;namespace r=fic::rollback;
    try {
        const auto value=getValue();
        if(!value)throw std::runtime_error("SSSD policy value is missing/invalid");
        s::SemanticValue logical;
        if(parameter_==s::SssdManagedParameter::CacheCredentials) {
            if(*value!="true")throw std::runtime_error("SSSD cache policy requires fixed true");
            logical=true;
        } else {
            unsigned days=0;const auto parsed=std::from_chars(value->data(),value->data()+value->size(),days);
            if(value->empty()||parsed.ec!=std::errc{}||parsed.ptr!=value->data()+value->size()||days>3650)
                throw std::runtime_error("SSSD policy requires an explicit integer in [0,3650]");
            logical=s::Days{days};
        }
        s::SssdApplyIntent intent(*this,*value);
        std::string error;auto* journal=r::DaemonMutationJournal::instance().tryGet(error);
        if(!journal)throw std::runtime_error("SSSD requires healthy daemon journal: "+error);
        auto operation=s::SssdTransactionOperation::Apply;
        for(const auto& record:journal->activeRecords(policyRef()))
            if(record.status==r::MutationStatus::Applied&&std::holds_alternative<r::SssdJournalOwnership>(record.undo.payload))
                operation=s::SssdTransactionOperation::Refresh;
        s::SssdTransactionRequest request{operation,policyRef(),parameter_,logical,
            std::chrono::steady_clock::now()+std::chrono::seconds(60),&intent};
        s::SssdTransactionCoordinator coordinator(*journal);
        const auto result=coordinator.execute(request);
        if(!result.success())throw std::runtime_error("SSSD verified transaction failed: "+result.diagnostic+
            "; prepared="+std::to_string(result.prepared)+"; installed="+std::to_string(result.installed)+
            "; durable="+std::to_string(result.durable)+"; unresolved="+std::to_string(result.unresolved));
        log("SSSD verified policy transaction completed",logLevel::INFO);return true;
    } catch(const std::exception& error) {log(error.what(),logLevel::ERROR);return false;}
}
