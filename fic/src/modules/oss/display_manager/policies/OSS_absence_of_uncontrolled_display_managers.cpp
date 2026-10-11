#include "modules/oss/display_manager/policies/OSS_absence_of_uncontrolled_display_managers.h"
#include <algorithm>
OSS_absence_of_uncontrolled_display_managers::OSS_absence_of_uncontrolled_display_managers(
    ControlledDisplayManagerScope& scope,std::shared_ptr<DisplayManagerInventory> inventory):scope_(scope),inventory_(std::move(inventory)){
    policyName="absence_of_uncontrolled_display_managers";policyTypeValue=std::make_unique<FixedPolicyTypeValue>("ENABLE");
    addRequiredDependency({"OSS","DisplayManager","controlled_display_managers"});
}
bool OSS_absence_of_uncontrolled_display_managers::evaluate(const DisplayManagerSnapshot& inventory,std::string& error){
    std::vector<std::string> target;if(!scope_.ready(error)||!scope_.configured(target,error))return false;
    if(target.empty()||!inventory.complete){error="DM scope/inventory is incomplete";return false;}
    if(!inventory.unknownSelectedOrRunning.empty()){error="unknown selected/running DM: "+inventory.unknownSelectedOrRunning.front();return false;}
    for(const auto& [dm,state]:inventory.managers) if((state.running||state.selected)&&std::find(target.begin(),target.end(),dm)==target.end()){
        error="uncontrolled selected/running DM: "+dm;return false;
    }
    error.clear();return true;
}
bool OSS_absence_of_uncontrolled_display_managers::apply(){DisplayManagerSnapshot snapshot;std::string error;
    if(!inventory_->inspect(snapshot,error)||!evaluate(snapshot,error)){log(error,logLevel::ERROR);return false;}return true;}
