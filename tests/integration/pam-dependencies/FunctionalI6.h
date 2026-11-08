// Closed test actions over existing production policy/registry/rollback paths.
#include "modules/identity_access/pam/PamManagedPasswordSlotBootstrap.h"
#include <fic/core/integrity/CommandHashStore.h>
json functionalI6(const PlatformProfile& profile, const PlatformExecutableResolver& executables) {
    const auto request=json::parse(read("/var/tmp/fic-pam-i6-request.json"));
    const std::string action=request.at("action");
    std::string error;json result;
    if(action=="bootstrap") {
        if(profile.id!="alt-p11") {
            p::PamManagedPasswordSlotBootstrap bootstrap("/etc/pam.d");
            p::PamManagedPasswordSlotBootstrapResult outcome;
            need(bootstrap.run(outcome,error) && outcome.complete(),error);
            need(CommandHashStore::saveHash("/usr/sbin/pam-auth-update",error),error);
        }
        result["ok"]=true;
    } else if(action=="configure") {
        ModuleConfigFileHandler config("IDENTITY_ACCESS");
        need(config.loadConfig(),"load existing config before mutation");
        for(auto it=request.at("statuses").begin();it!=request.at("statuses").end();++it)
            need(config.setPolicyStatus(it.key(),it.value()),"status write");
        for(auto it=request.at("values").begin();it!=request.at("values").end();++it)
            need(config.setPolicyValue(it.key(),it.value()),"value write");
        need(config.saveConfig(),"save config");result["ok"]=true;
    } else {
        auto registry=registryFor(profile,executables);
        const std::string name=request.at("policy");
        auto* policy=registry.findPolicy(pamRef(name));need(policy!=nullptr,"policy unregistered: "+name);
        if(action=="apply") {
            auto summary=applyPolicy(registry,"IDENTITY_ACCESS",name);
            result["ok"]=isPolicyApplySuccessful(summary,"IDENTITY_ACCESS",name);
            result["results"]=json::array();
            for(const auto& r:summary.getResults())result["results"].push_back({{"name",r.policyName},
                {"applied",r.isApplied()},{"detail",r.message},{"own_attempted",r.ownApplyAttempted}});
        } else if(action=="rollback") {
            auto deps=fic::rollback::productionRollbackDeps(profile,executables,&registry);
            deps.pamManagerFactory=[&](const auto& capability,const auto& services,std::string& why) {
                return p::createPamTopologyManager(profile.pam,capability,services,executables,why);
            };
            auto report=fic::rollback::rollbackPolicyBeforeDisable(pamRef(name),"",deps);
            result={{"ok",report.rollbackCompleted()},{"status",fic::rollback::rollbackStatusToString(report.status)},
                {"detail",report.message}};
        } else throw std::runtime_error("unknown I6 action");
    }
    const auto& paths=fic::core::FicRuntimePaths::get();
    result["physical"]=json::object();
    for(const auto* file:{"/etc/security/pwquality.conf","/etc/security/pwhistory.conf",
        "/etc/security/faillock.conf","/etc/security/fic-pwhistory.conf","/etc/passwdqc.conf",
        "/etc/pam.d/common-password","/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth-local-only","/etc/pam.d/system-auth-use_first_pass-local-only"})
        if(fs::exists(file))result["physical"][file]=read(file);
    result["journal"]=read(paths.mutationJournalFile);
    result["config"]=read(paths.configDir/"IDENTITY_ACCESS.conf");
    return result;
}
