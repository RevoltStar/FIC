#include "modules/oss/display_manager/policies/OSS_disable_autologin.h"
#include "rollback/DaemonMutationJournal.h"
OSS_disable_autologin::OSS_disable_autologin(ControlledDisplayManagerScope& scope,std::shared_ptr<DisplayManagerInventory> inventory,
    std::shared_ptr<DisplayManagerConfigTransaction> backend,fic::rollback::MutationJournal* journal)
    :scope_(scope),inventory_(std::move(inventory)),backend_(std::move(backend)),journal_(journal){
    policyName="disable_autologin";policyTypeValue=std::make_unique<FixedPolicyTypeValue>("ENABLE");
    addRequiredDependency({"OSS","DisplayManager","controlled_display_managers"});
}
bool OSS_disable_autologin::apply(){
    std::string error;std::vector<std::string> target;DisplayManagerSnapshot inventory;
    std::string path;AtomicTargetState version;
    if(!captureConfigurationVersion(path,version,error)){log(error,logLevel::ERROR);return false;}
    if(!isEnabled() || getValue()!=std::optional<std::string>("ENABLE") || !scope_.ready(error) || !scope_.configured(target,error) ||
        !inventory_->inspect(inventory,error)||!inventory.complete){log("DM apply blocked: "+error,logLevel::ERROR);return false;}
    auto* journal=journal_?journal_:fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    if(!journal){log(error,logLevel::ERROR);return false;}
    // Alternate entrypoint is observational; only the authorized scope
    // coordinator can enroll/mutate resources.
    for(const auto& dm:target){auto entry=inventory.managers.find(dm);
        if(entry==inventory.managers.end()){log("incomplete DM inventory",logLevel::ERROR);return false;}
        if(!entry->second.installed)continue;
        if(!entry->second.configurationSupported){log("DM custom execution/configuration cannot be proven",logLevel::ERROR);return false;}
        bool applied=false;for(const auto& r:journal->records())if(r.isActive()&&r.undo.backend==fic::rollback::MutationBackend::DisplayManager&&
            r.resource=="DM/"+dm+"/autologin"&&r.status==fic::rollback::MutationStatus::Applied)applied=true;
        if(!applied || !backend_->verifyApplied(dm,*journal,error)){log("DM enforcement not proven: "+error,logLevel::ERROR);return false;}
    }
    log("DM native persistent configuration verified; live runtime verification=NOT_VERIFIED (no DM restart performed)",logLevel::INFO);
    return true;
}
