#include "modules/oss/display_manager/policies/OSS_controlled_display_managers.h"
#include "modules/oss/display_manager/ControlledDisplayManagersPolicyTypeValue.h"
#include "rollback/ScopeTransition.h"
#include "rollback/DaemonMutationJournal.h"
#include "policy/registry/PolicyRegistry.h"
#include <algorithm>
using namespace fic::rollback;
OSS_controlled_display_managers::OSS_controlled_display_managers(std::shared_ptr<DisplayManagerInventory> inventory,
    std::shared_ptr<DisplayManagerConfigTransaction> backend,MutationJournal* journal)
    :inventory_(std::move(inventory)),backend_(std::move(backend)),journal_(journal){
    policyName="controlled_display_managers";policyTypeValue=std::make_unique<ControlledDisplayManagersPolicyTypeValue>();
}
bool OSS_controlled_display_managers::configured(std::vector<std::string>& target,std::string& error){
    if(!isEnabled()){error="Required DM scope is disabled";return false;}
    auto value=getValue();if(!value||!ControlledDisplayManagersPolicyTypeValue::parse(*value,target)){error="invalid controlled_display_managers";return false;}
    error.clear();return true;
}
bool OSS_controlled_display_managers::ready(std::string& error){
    std::vector<std::string> target;
    if (!configured(target,error)) return false;
    if (target.empty()) { error="controlled_display_managers is empty (UNCONFIGURED)"; return false; }
    error.clear(); return true;
}
bool OSS_controlled_display_managers::apply(){std::string error;if(ready(error))return true;log(error,logLevel::ERROR);return false;}
bool OSS_controlled_display_managers::reconcile(Policy& autologin,std::string& error){
    std::vector<std::string> target;if(!configured(target,error))return false;
    auto* journal=journal_?journal_:DaemonMutationJournal::instance().tryGet(error);if(!journal)return false;
    ScopeTransition transition(*journal,ScopeTransition::Domain::DisplayManager);
    DisplayManagerSnapshot snapshot;
    std::map<std::string,AtomicTargetState> versions;
    std::set<std::string> enforce;
    const auto preflight=[&](std::string& e){
        for(auto* policy:{static_cast<Policy*>(this),&autologin}){
            std::string path;AtomicTargetState state;if(!policy->captureConfigurationVersion(path,state,e))return false;
            versions[path]=state;
        }
        if(!inventory_->inspect(snapshot,e)||!snapshot.complete){if(e.empty())e="incomplete DM inventory";return false;}
        // Unknown running/selected DMs belong to the observational compliance
        // policy. They do not authorize guessing a route for native mutation.
        if(autologin.isEnabled()) {
            if(autologin.getValue()!=std::optional<std::string>("ENABLE")){e="disable_autologin value must be ENABLE";return false;}
            for(const auto& dm:target){auto found=snapshot.managers.find(dm);if(found==snapshot.managers.end()){e="missing typed DM inventory entry";return false;}if(found->second.installed){if(!found->second.configurationSupported){e="controlled DM has unsupported executable/configuration override: "+dm;return false;}enforce.insert(dm);}}
        }
        for(const auto* dm:{"SDDM","GDM","LIGHTDM"})if(!backend_->preflight(dm,enforce.count(dm),*journal,e))return false;
        return true;
    };
    const auto ensure=[&](std::string& e){for(const auto& dm:enforce)if(!backend_->reconcile(dm,true,*journal,e))return false;return true;};
    const auto release=[&](std::string& e){for(const auto* dm:{"SDDM","GDM","LIGHTDM"})if(!enforce.count(dm)&&!backend_->reconcile(dm,false,*journal,e))return false;return true;};
    const auto verify=[&](std::string& e){
        for(const auto* dm:{"SDDM","GDM","LIGHTDM"})if(!(enforce.count(dm) ? backend_->verifyApplied(dm,*journal,e) : backend_->verifyReleased(dm,*journal,e)))return false;
        DisplayManagerSnapshot current;if(!inventory_->inspect(current,e)||!current.complete)return false;
        for(const auto& [dm,state]:snapshot.managers){auto found=current.managers.find(dm);if(found==current.managers.end()||state.installed!=found->second.installed || state.configurationSupported!=found->second.configurationSupported){e="DM installation inventory changed during transition";return false;}}
        for(const auto& [path,state]:versions)if(!AtomicFileWriter::targetStateMatches(path,state,&e))return false;
        return true;
    };
    return transition.reconcile(target,preflight,ensure,release,verify,error);
}
bool reconcileDisplayManagerScope(PolicyRegistry& registry,std::string& error){
    Policy* policy=registry.findPolicy({"OSS","DisplayManager","controlled_display_managers"});
    Policy* autologin=registry.findPolicy({"OSS","DisplayManager","disable_autologin"});
    auto* scope=dynamic_cast<OSS_controlled_display_managers*>(policy);
    if(!policy||!policy->isEnabled()){
        for(const auto& name:{"disable_autologin","absence_of_uncontrolled_display_managers"}){auto* consumer=registry.findPolicy({"OSS","DisplayManager",name});if(consumer&&consumer->isEnabled()){error="Required DM scope is disabled";return false;}}
        error.clear();return true;
    }
    if(!scope||!autologin){error="DM registry contract incomplete";return false;}
    return scope->reconcile(*autologin,error);
}
