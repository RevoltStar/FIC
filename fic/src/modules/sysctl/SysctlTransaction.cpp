#include "modules/sysctl/SysctlTransaction.h"
#include "modules/sysctl/SysctlKey.h"
#include <stdexcept>
bool proveSysctlOwnership(fic::rollback::MutationJournal& journal,const SysctlConfiguration& config,
    SysctlContainerAuthority& authority,std::string& error,const std::string& releasing) {
    using namespace fic::rollback;
    if(!journal.usable()||!journal.lifecycleInitialized()){error="SYSCTL journal/witness unavailable";return false;}
    std::map<std::string,std::string> owned;bool any=false;
    for(const auto& r:journal.records())if(r.isActive()&&r.undo.backend==MutationBackend::Sysctl) {
        const auto* p=std::get_if<UndoRemoveManagedSetting>(&r.undo.payload);
        if(!p||r.policy.moduleName!="SYSCTL"||p->key!=r.resource||
           (r.status==MutationStatus::Prepared&&(p->sysctl||fic::sysctl::internalKeyToCanonicalPath(p->key)!=releasing))||(p->sysctl&&(p->sysctl->pending||p->sysctl->release))) {error="unresolved/invalid shared SYSCTL provenance";return false;}
        const auto key=fic::sysctl::internalKeyToCanonicalPath(p->key);
        if(!owned.emplace(key,p->appliedValue).second){error="multiple SYSCTL owners for one parameter";return false;}
        any=true;
        if(!p->sysctl) {if(!authority.legacyOrigin)authority.legacyOrigin=r.id;}
        else {
            if(p->sysctl->containerCreated&&config.snapshot()) {
                const auto& identity=p->sysctl->containerIdentity;
                if(!identity||identity->device!=config.snapshot()->identity.device||identity->inode!=config.snapshot()->identity.inode) {
                    error="SYSCTL created container replaced; no adoption/deletion";return false;
                }
            }
            authority.created|=p->sysctl->containerCreated;
            if(p->sysctl->legacyContainerOrigin) {
                const auto id=p->sysctl->legacyContainerOrigin;const MutationRecord* origin=nullptr;
                for(const auto& candidate:journal.records())if(candidate.id==id)origin=&candidate;
                const auto* old=origin?std::get_if<UndoRemoveManagedSetting>(&origin->undo.payload):nullptr;
                if(!old||old->sysctl||origin->undo.backend!=MutationBackend::Sysctl){error="legacy SYSCTL release delegation lost provenance";return false;}
                if(!authority.legacyOrigin)authority.legacyOrigin=id;
            }
        }
    }
    if(authority.created)authority.legacyOrigin=0;
    if(config.existed()&&!any){error="orphan FIC sysctl artifact, no adoption";return false;}
    for(const auto& [key,value]:config.managedValues()) {
        auto owner=owned.find(key);if(owner==owned.end()&&!releasing.empty()&&key!=releasing)continue;
        if(owner==owned.end()||owner->second!=value){error="unattributable/drifted SYSCTL assignment: "+key;return false;}
    }
    for(const auto& [key,value]:owned)if(key!=releasing) {
        auto actual=config.managedValues().find(key);
        if(actual==config.managedValues().end()||actual->second!=value){error="owned SYSCTL assignment missing/drifted; no reconstruction";return false;}
    }
    return true;
}
SysctlOperationResult applySysctlOwned(fic::rollback::MutationJournal& journal,const PolicyRef& policy,
    const std::string& key,const std::string& value,SysctlConfigurationOptions options,SysctlRuntimeOptions runtimeOptions,
    const std::function<bool(std::string&)>& admission,const std::function<void()>& beforePublish) {
    using namespace fic::rollback;
    std::lock_guard<std::mutex> lock(SysctlConfiguration::mutationMutex());
    SysctlOperationResult result;std::string error;MutationId id=0;
    const auto require=[](bool ok,const std::string& message){if(!ok)throw std::runtime_error(message);};
    try {
        if(admission)require(admission(error),error);
        SysctlConfiguration config(options);require(config.load(error),error);
        SysctlContainerAuthority authority;require(proveSysctlOwnership(journal,config,authority,error),error);
        const auto active=journal.activeRecords(policy);
        require(active.size()<=1,"multiple active SYSCTL policy records");
        if(!active.empty())require(active.front().resource==key&&active.front().status==MutationStatus::Applied,"SYSCTL predecessor not Applied/exact resource");
        SysctlRuntime runtime(runtimeOptions);std::string live;require(runtime.readValue(key,live,error),error);
        const auto managed=config.inspectManagedValue(key);
        const bool persistentChange=!managed.found||managed.value!=value;
        if(!persistentChange) {
            require(!active.empty(),"matching SYSCTL without this policy ownership");
            const auto applied=runtime.ensureValue(key,value);require(applied.ok,applied.message);
            require(config.verifyCurrent(error)&&config.verifyPriority(error),error);
            if(admission)require(admission(error),error);
            result.ok=true;result.changed=applied.changed;result.message=applied.message;return result;
        }
        // If this container was absent, this operation must create it exclusively.
        bool created=!config.existed()||authority.created;
        if(!active.empty()) {
            const auto& old=std::get<UndoRemoveManagedSetting>(active.front().undo.payload);
            if(old.sysctl){created=old.sysctl->containerCreated;authority.legacyOrigin=old.sysctl->legacyContainerOrigin;}
        }
        require(journal.prepareSysctl(policy,key,value,created,created?0:authority.legacyOrigin,config.snapshot(),id,error),error);
        if(beforePublish)beforePublish();
        if(admission&&!admission(error)) {
            std::string abort;journal.abortSysctlNoEffect(id,abort);throw std::runtime_error(error+"; "+abort);
        }
        if(!journal.noteSysctlAttempt(id,error)) {
            std::string abort;journal.abortSysctlNoEffect(id,abort);
            throw std::runtime_error(error+"; "+abort);
        }
        result.noEffect=false; // exceptions during publication are not evidence of no effect
        const auto publication=config.ensureManagedValue(key,value);
        result.noEffect=publication.noEffect;
        if(!publication.ok) {
            if(publication.noEffect){std::string abort;if(!journal.abortSysctlNoEffect(id,abort,true))error="; no-effect abort failed: "+abort;}
            throw std::runtime_error(publication.message+error);
        }
        const auto applied=runtime.ensureValue(key,value);require(applied.ok,applied.message);
        require(config.verifyCurrent(error)&&config.verifyPriority(error),error);
        if(admission)require(admission(error),error);
        require(config.snapshot()&&journal.finishSysctl(id,*config.snapshot(),error),error);
        result.ok=true;result.changed=publication.changed||applied.changed;result.message="FIC SYSCTL ownership and runtime verified";
    } catch(const std::exception& e){result.message=e.what();}
    return result;
}

SysctlOperationResult releaseSysctlOwned(fic::rollback::MutationJournal& journal,fic::rollback::MutationId id,
    SysctlConfigurationOptions options,const std::function<bool(const std::string&,std::string&)>& reapply) {
    using namespace fic::rollback;
    SysctlOperationResult result;std::string error;
    try {
    if(!journal.usable()||!journal.lifecycleInitialized()){result.message="SYSCTL release requires a healthy reloaded journal";return result;}
    const MutationRecord* record=nullptr;for(const auto& r:journal.records())if(r.id==id)record=&r;
    const auto* setting=record?std::get_if<UndoRemoveManagedSetting>(&record->undo.payload):nullptr;
    if(!setting||record->undo.backend!=MutationBackend::Sysctl){result.message="SYSCTL release identity unavailable";return result;}
    const auto undo=*setting;
    if(!record->isActive()){result.ok=true;result.targetMissing=true;return result;}
    SysctlConfiguration config(options);SysctlContainerAuthority authority;
    if(!config.loadManaged(error)){result.message=error;return result;}
    const auto equal=[](const std::optional<AtomicTargetState>& a,const std::optional<AtomicTargetState>& b) {
        return bool(a)==bool(b)&&(!a||(a->identity.device==b->identity.device&&a->identity.inode==b->identity.inode&&
            a->content==b->content&&a->mode==b->mode&&a->owner==b->owner&&a->group==b->group));
    };
    const bool continuing=undo.sysctl&&undo.sysctl->release;
    if(!continuing) {
        const auto found=config.inspectManagedValue(undo.key);
        if(found.found&&found.value!=undo.appliedValue){result.conflict=true;result.message="owned SYSCTL assignment drift";return result;}
        if(!proveSysctlOwnership(journal,config,authority,error,fic::sysctl::internalKeyToCanonicalPath(undo.key))){result.message=error;return result;}
        std::optional<AtomicTargetState> planned;
        if(!SysctlConfiguration::planRemoval(config.snapshot(),undo.key,undo.appliedValue,authority.created||authority.legacyOrigin,planned,error)||
           !journal.beginSysctlRelease(id,config.snapshot(),planned,error)){result.message=error;return result;}
    }
    const MutationRecord* current=nullptr;for(const auto& r:journal.records())if(r.id==id)current=&r;
    const auto state=*std::get<UndoRemoveManagedSetting>(current->undo.payload).sysctl;
    const auto intent=*state.release;
    std::optional<AtomicTargetState> planned;
    if(!SysctlConfiguration::planRemoval(intent.before,undo.key,undo.appliedValue,state.containerCreated||state.legacyContainerOrigin,planned,error)||!equal(planned,intent.target)) {
        result.message="unresolved SYSCTL release: invalid deterministic plan: "+error;return result;
    }
    if(equal(config.snapshot(),intent.before)) {
        result=config.removeManagedKey(undo.key,undo.appliedValue,state.containerCreated||state.legacyContainerOrigin,
            [&](const AtomicTargetState& prepared,std::string& why){return journal.noteSysctlReleasePrepared(id,prepared,why);});
        if(!result.ok)return result;
    } else if((!intent.target&&!config.snapshot())||(intent.prepared&&equal(config.snapshot(),intent.prepared))) {
        result.ok=config.confirmDurable(error);result.targetMissing=true;
        result.message=result.ok?"SYSCTL prepared release result recovered without rewriting":error;
        if(!result.ok)return result;
    } else {
        result.message="unresolved SYSCTL release: neither original state nor exact prepared publication; no adoption";return result;
    }
    if(!config.verifyCurrent(error)||!journal.finishSysctlRelease(id,config.snapshot(),error)) {
        result.ok=false;result.message="SYSCTL release intent retained; completion failed: "+error;return result;
    }
    bool reapplied=false;
    try {
        if(reapply)reapplied=reapply(undo.key,error);
        else error="native SYSCTL reapply callback unavailable";
    } catch(const std::exception& e){error=e.what();}
      catch(...){error="unknown native SYSCTL helper exception";}
    if(!reapplied) {
        result.message+="; WARNING: ownership released; native prefix reapply failed: "+error;
        result.diagnostics.push_back(result.message);
    }
    } catch(const std::exception& exception) {
        result.ok=false;result.noEffect=false;result.message="unresolved SYSCTL release: "+std::string(exception.what());
    }
    return result;
}
