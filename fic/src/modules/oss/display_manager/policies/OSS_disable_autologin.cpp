#include "modules/oss/display_manager/policies/OSS_disable_autologin.h"
#include "rollback/DaemonMutationJournal.h"
OSS_disable_autologin::OSS_disable_autologin(ControlledDisplayManagerScope& scope,std::shared_ptr<DisplayManagerInventory> inventory,
    std::shared_ptr<DisplayManagerConfigTransaction> backend,fic::rollback::MutationJournal* journal)
    :scope_(scope),inventory_(std::move(inventory)),backend_(std::move(backend)),journal_(journal){
    policyName="disable_autologin";policyTypeValue=std::make_unique<FixedPolicyTypeValue>("ENABLE");
    addRequiredDependency({"OSS","DisplayManager","controlled_display_managers"});
}
bool OSS_disable_autologin::apply(){
    reconciliationError_.clear();
    auto& error = reconciliationError_;
    if (!isEnabled() || getValue()!=std::optional<std::string>("ENABLE") ||
        !scope_.ready(error) || !scope_.reconcile(*this,error)) {
        log("DM reconciliation failed: " + error,logLevel::ERROR); return false;
    }
    log("DM native persistent configuration verified; live runtime verification=NOT_VERIFIED (no DM restart performed)",logLevel::INFO);
    return true;
}
