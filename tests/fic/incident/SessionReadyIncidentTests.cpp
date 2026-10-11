#include "session/SessionPolicyReconciler.h"
#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"
#include "modules/oss/desktop_environment/policies/OSS_absence_of_uncontrolled_desktop_environments.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <unistd.h>
#include <sys/stat.h>

using fic::core::IncidentSeverity;
using namespace fic::incident;
namespace fs=std::filesystem;
namespace {
void require(bool ok,const std::string& message) { if(!ok) throw std::runtime_error(message); }
struct Sessions final : fic::session::SessionContainmentBackend {
    int inventories=0;
    fic::session::SessionInventoryResult listSessions() override { ++inventories; return {true,{},{}}; }
    fic::session::UserInventoryResult listUsers() override { return {true,{},{}}; }
    fic::session::SessionKind classifySession(const fic::session::LoginSession&) override { return fic::session::SessionKind::Graphical; }
    fic::session::ContainmentOutcome lockSession(const fic::session::LoginSession&) override { return {true,{}}; }
    bool verifySessionLocked(const fic::session::LoginSession&,std::string&) override { return true; }
    fic::session::ContainmentOutcome terminateSession(const fic::session::LoginSession&) override { return {true,{}}; }
    fic::session::ContainmentOutcome terminateUser(const fic::session::LoginUser&) override { return {true,{}}; }
    bool verifySessionsGone(const std::vector<fic::session::LoginSession>&,std::string&) override { return true; }
    bool verifyUserRuntimeGone(const fic::session::LoginUser&,std::string&) override { return true; }
    RegisteredUserLookup lookupProvenUser(uid_t,const std::string&) override { return {}; }
};
struct Network final : IncidentNetworkBackend { bool applyQuarantine(bool,std::string&) override { return true; } };
struct Scope final : Policy, ControlledDesktopEnvironmentScope {
    bool valid=true;
    DesktopEnvironmentSet target{DesktopEnvironmentKind::Kde};
    Scope() { moduleName="OSS";submoduleName="DesktopEnvironment";policyName="controlled_desktop_environments";
        moduleConf=std::make_unique<ModuleConfigFileHandler>(moduleName);require(moduleConf->loadConfig(),"scope load"); }
    bool readyForApply(std::string& error) override { DesktopEnvironmentSet out; return controlledDesktopEnvironments(out,error); }
    bool controlledDesktopEnvironments(DesktopEnvironmentSet& out,std::string& error) override {
        out=target;if(!isEnabled()||!valid){error="invalid/disabled configured scope";return false;}error.clear();return true; }
    bool apply() override { std::string e;return readyForApply(e); }
};
struct Inventory final : GraphicalSessionInventory {
    bool currentSessions(std::vector<ClassifiedGraphicalSession>&,std::string&) override { throw std::runtime_error("targeted compliance re-enumerated sessions"); }
};
struct SessionPolicy final : SessionAwareDesktopEnvironmentPolicy {
    int calls=0; bool nativeOk=true,relevant=true,throws=false,unsupported=false,emptyError=false;
    SessionPolicy(Scope& scope,std::shared_ptr<Inventory> inventory,const std::string& name)
        :SessionAwareDesktopEnvironmentPolicy(scope,inventory) { policyName=name;addRequiredDependency({"OSS","DesktopEnvironment","controlled_desktop_environments"}); }
    bool prepare(std::string&) override { return true; }
    bool relevantTo(DesktopEnvironmentKind) const override { return relevant; }
    EnforcementMode modeFor(DesktopEnvironmentKind desktop) const override {
        if(unsupported)return EnforcementMode::Unsupported;
        return (desktop==DesktopEnvironmentKind::Gnome||desktop==DesktopEnvironmentKind::Fly)?EnforcementMode::MandatoryGlobal:EnforcementMode::SessionOnly; }
    bool reconcileControlledSession(const SessionReconcileContext&,std::string& error) override {
        ++calls;if(throws)throw std::runtime_error("native exception");if(!nativeOk&&!emptyError)error=policyName+" native failure";return nativeOk; }
};
fs::path root;
int sequence=0;
struct Fixture {
    PolicyRegistry registry; Scope* scope; SessionPolicy *a,*b;
    std::shared_ptr<Sessions> sessions=std::make_shared<Sessions>();
    std::shared_ptr<Inventory> inventory=std::make_shared<Inventory>();
    IncidentController controller;
    ClassifiedGraphicalSession target;
    std::vector<ClassifiedGraphicalSession> snapshot;
    DesktopGlobalReconcileReport global;
    std::vector<std::string> audits,notificationReasons; int notifications=0;
    Fixture(bool aEnabled=true,bool bEnabled=false,bool compliance=false,bool scopeEnabled=true,const char* severity="SOFT")
        :controller(IncidentStateStore(root/("state"+std::to_string(++sequence))),sessions,std::make_shared<Network>()) {
        const auto state=root/("state"+std::to_string(sequence));std::ofstream(state)<<"UNLOCKED\n";::chmod(state.c_str(),0640);
        std::ofstream(root/"config/OSS.conf")<<"controlled_desktop_environments.status="<<(scopeEnabled?"ENABLE":"DISABLE")
            <<"\ncontrolled_desktop_environments.violation_severity=NONE\nscreenlock_timeout.status="<<(aEnabled?"ENABLE":"DISABLE")
            <<"\nscreenlock_timeout.violation_severity="<<severity<<"\ndisable_kde_lock_screen_media_controls.status="<<(bEnabled?"ENABLE":"DISABLE")
            <<"\ndisable_kde_lock_screen_media_controls.violation_severity=HARD\nabsence_of_uncontrolled_desktop_environments.status="<<(compliance?"ENABLE":"DISABLE")
            <<"\nabsence_of_uncontrolled_desktop_environments.violation_severity=HARD\n";
        std::string error;require(registry.addModule("OSS",ModuleView::Standard,0,error),error);
        auto s=std::make_unique<Scope>();scope=s.get();require(registry.addPolicy(std::move(s),error),error);
        auto first=std::make_unique<SessionPolicy>(*scope,inventory,"screenlock_timeout");a=first.get();require(registry.addPolicy(std::move(first),error),error);
        auto second=std::make_unique<SessionPolicy>(*scope,inventory,"disable_kde_lock_screen_media_controls");b=second.get();require(registry.addPolicy(std::move(second),error),error);
        require(registry.addPolicy(std::make_unique<OSS_absence_of_uncontrolled_desktop_environments>(*scope,inventory),error),error);
        target.session.id="7";target.session.uid=1000;target.desktop=DesktopEnvironmentKind::Kde;snapshot={target};
        controller.setModeResolver([] { return IncidentResponseModeResult{IncidentResponseMode::Active,true,"test"}; });
        controller.setAccessGateVerifier([](std::string&){return true;});
        controller.setBootIdProviderForTests([] { return "00000000-0000-0000-0000-000000000001"; });
        controller.setAuditSink([&](const std::string& line){audits.push_back(line);});
        controller.setNotifySink([&](IncidentSeverity,const std::string& reason){++notifications;notificationReasons.push_back(reason);});
    }
    PolicyApplySummary run(bool contextAvailable=true,bool complete=true) {
        const SessionReconcileContext context{target,snapshot,complete};
        return fic::session::reconcileSessionReadyPolicies(registry,controller,target,contextAvailable?&context:nullptr,
            snapshot,complete,complete?"":"inventory unavailable",global);
    }
    void gnome(bool verified) {
        target.desktop=DesktopEnvironmentKind::Gnome;snapshot={target};scope->target={target.desktop};
        for(const auto* name:{"screenlock_timeout","disable_kde_lock_screen_media_controls"})
            global.policies[{"OSS","DesktopEnvironment",name}][target.desktop]={true,verified,{"gnome"},verified?"":"global native proof failed"};
    }
};
const PolicyApplyResult& find(const PolicyApplySummary& summary,const std::string& name) {
    for(const auto& result:summary.getResults())if(result.policyName==name)return result;
    throw std::runtime_error("missing policy result: "+name);
}
void scenarios() {
    {Fixture f(true,false,false,true,"HARD");f.scope->target.insert(DesktopEnvironmentKind::Gnome);
        require(f.run().hasFailures()&&f.controller.status().severity==IncidentSeverity::Hard&&f.notifications==1,
                "screenlock global failure ignored own HARD severity");}
    {Fixture f(false);f.global.policies[{"OSS","DesktopEnvironment","screenlock_timeout"}][DesktopEnvironmentKind::Gnome]={true,false,{"gnome"},"disabled owner failure"};
        require(!f.run().hasFailures()&&f.notifications==0&&f.a->calls==0,"disabled global owner caused incident");}

    for (const auto phase : {"global_preflight","global_ensure","global_release","global_verify"}) {
        Fixture f; f.scope->target.insert(DesktopEnvironmentKind::Gnome);
        f.global.phase=phase; f.global.requirementsValid=false; f.global.stageADiagnostic="GNOME injected failure";
        const auto summary=f.run();const auto& r=find(summary,"screenlock_timeout");
        require(r.isFailure()&&f.a->calls==1&&f.notifications==1&&f.controller.status().severity==IncidentSeverity::Soft,
                "owned GNOME failure lost after successful KDE apply");
        require(r.message.find(phase)!=std::string::npos&&r.message.find("session_reconciliation SUCCESS")!=std::string::npos,
                "actual global phase or successful session result lost");
        f.run();require(f.notifications==1&&f.a->calls==2,"global failure repeat not deduplicated");
    }
    for (bool globalOK : {false,true}) for (bool sessionOK : {false,true}) {
        Fixture f;f.scope->target.insert(DesktopEnvironmentKind::Gnome);f.a->nativeOk=sessionOK;
        f.global.policies[{"OSS","DesktopEnvironment","screenlock_timeout"}][DesktopEnvironmentKind::Gnome]=
            {true,globalOK,{"gnome"},globalOK?"":"GNOME verify failed"};
        const auto summary=f.run();const auto& r=find(summary,"screenlock_timeout");
        require(r.isFailure()==(!globalOK||!sessionOK)&&f.a->calls==1&&f.notifications==(!globalOK||!sessionOK),"global/session matrix failed");
        if(!globalOK)require(r.message.find("GNOME verify failed")!=std::string::npos,"global cause lost");
        if(!sessionOK)require(r.message.find("native failure")!=std::string::npos,"session cause lost");
    }
    {Fixture f;f.target.desktop=DesktopEnvironmentKind::Xfce;f.snapshot={f.target};
        f.scope->target={DesktopEnvironmentKind::Xfce,DesktopEnvironmentKind::Fly};
        f.global.policies[{"OSS","DesktopEnvironment","screenlock_timeout"}][DesktopEnvironmentKind::Fly]={true,false,{"fly"},"FLY ensure failed"};
        auto summary=f.run();require(summary.hasFailures()&&f.a->calls==1&&f.notifications==1&&find(summary,"screenlock_timeout").message.find("FLY")!=std::string::npos,"FLY failure lost after XFCE success");}
    {Fixture f;f.scope->target.insert(DesktopEnvironmentKind::Gnome);f.scope->target.insert(DesktopEnvironmentKind::Fly);
        for(auto de:{DesktopEnvironmentKind::Gnome,DesktopEnvironmentKind::Fly})
            f.global.policies[{"OSS","DesktopEnvironment","screenlock_timeout"}][de]={true,true,{},""};
        require(!f.run().hasFailures()&&f.a->calls==1&&f.notifications==0,"verified global requirements caused incident");}
    {Fixture f;f.a->relevant=false;
        f.global.policies[{"OSS","DesktopEnvironment","screenlock_timeout"}][DesktopEnvironmentKind::Gnome]={true,false,{"gnome"},"owned failure"};
        require(f.run().hasFailures()&&f.a->calls==0&&f.notifications==1,"NotApplicable target hid owned global failure");}
    {Fixture f(true,true);f.global.policies[{"OSS","DesktopEnvironment","disable_kde_lock_screen_media_controls"}][DesktopEnvironmentKind::Gnome]={true,false,{"gnome"},"foreign failure"};
        auto summary=f.run();require(!find(summary,"screenlock_timeout").isFailure()&&find(summary,"disable_kde_lock_screen_media_controls").isFailure()&&f.controller.status().severity==IncidentSeverity::Hard&&f.notifications==1,"global ownership or HARD severity lost");}

    {Fixture f;auto s=f.run();require(!s.hasFailures()&&f.a->calls==1&&f.audits.empty()&&f.notifications==0,"success raised incident");}
    {Fixture f;f.a->nativeOk=false;auto s=f.run();require(s.hasFailures()&&f.controller.status().severity==IncidentSeverity::Soft&&f.notifications==1&&f.audits.size()==1,"session failure did not reach common reporter");
        require(f.audits[0].find("session=7 uid=1000 desktop=KDE")!=std::string::npos&&f.audits[0].find("native failure")!=std::string::npos,"incident lost context or cause: "+f.audits[0]);}
    {Fixture f;f.a->nativeOk=false;f.a->emptyError=true;auto s=f.run();require(find(s,"screenlock_timeout").isFailure()&&
        find(s,"screenlock_timeout").message.find("failed without")!=std::string::npos&&f.notifications==1,
        "empty backend diagnostic falsely claimed success");}
    {Fixture f(true,true);f.a->nativeOk=f.b->nativeOk=false;f.run();require(f.controller.status().severity==IncidentSeverity::Hard&&f.notifications==1&&f.audits.size()==1&&f.sessions->inventories>0,"aggregate max/active containment pipeline failed");
        require(f.notificationReasons[0].find("screenlock_timeout native failure")!=std::string::npos&&f.notificationReasons[0].find("disable_kde_lock_screen_media_controls native failure")!=std::string::npos,"aggregate reporter lost one failure");
        const auto summary=f.run();
        require(find(summary,"screenlock_timeout").message=="screenlock_timeout native failure" &&
                find(summary,"disable_kde_lock_screen_media_controls").message=="disable_kde_lock_screen_media_controls native failure",
                "structured per-policy diagnostics lost a cause");
        require(f.notifications==1&&f.a->calls==2&&f.b->calls==2,"repeat notifications not deduplicated or retry suppressed");}
    {Fixture f(false);f.a->nativeOk=false;f.run();require(f.a->calls==0&&f.audits.empty(),"disabled policy caused incident");}
    {Fixture f;f.a->relevant=false;f.a->nativeOk=false;require(!f.run().hasFailures()&&f.audits.empty()&&f.a->calls==0,"NotApplicable caused incident");}
    {Fixture f;f.gnome(true);f.a->nativeOk=false;auto s=f.run();require(!s.hasFailures()&&f.audits.empty()&&find(s,"screenlock_timeout").diagnostics.front().level=="WARN","MandatoryGlobal warning raised incident");}
    {Fixture f;f.gnome(false);require(f.run().hasFailures()&&f.a->calls==0&&f.notifications==1,"global failure not reported for its policy");}
    {Fixture f;f.global.requirementsValid=false;f.global.stageADiagnostic="unrelated GNOME failure";require(!f.run().hasFailures()&&f.a->calls==1&&f.audits.empty(),"KDE inherited unrelated global failure");}
    {Fixture f(true,false,true);f.target.desktop=DesktopEnvironmentKind::Xfce;f.snapshot={f.target};auto s=f.run();require(find(s,"absence_of_uncontrolled_desktop_environments").isFailure()&&f.controller.status().severity==IncidentSeverity::Hard,"new uncontrolled desktop did not raise compliance incident");}
    {Fixture f;f.a->relevant=false;f.target.desktop=DesktopEnvironmentKind::Xfce;f.snapshot={f.target};f.run();require(f.audits.empty(),"disabled compliance raised incident");}
    {Fixture f(true,true);f.b->throws=true;auto s=f.run();require(s.hasFailures()&&f.a->calls==1&&f.notifications==1,"exception stopped independent policies or missed reporter");}
    {Fixture f(true,false,false,false);auto s=f.run();const auto& r=find(s,"screenlock_timeout");require(r.failureOrigin==PolicyFailureOrigin::RequiredDependencyBlocked&&!r.ownApplyAttempted&&f.a->calls==0&&f.controller.status().severity==IncidentSeverity::Soft,"disabled Required bypassed planner/owner severity");}
    {Fixture f;f.scope->valid=false;auto s=f.run();require(find(s,"screenlock_timeout").failureOrigin==PolicyFailureOrigin::RequiredDependencyBlocked&&f.notifications==1,"invalid Required skipped incident reporting");}
    {Fixture f;f.a->unsupported=true;require(f.run().hasFailures()&&f.notifications==1,"applicable Unsupported silently succeeded");}
    {Fixture f;f.a->nativeOk=false;f.run(false);require(f.audits.empty()&&f.a->calls==0,"unvalidated event became arbitrary policy failure");}
    {Fixture f(false,false,true);f.snapshot[0].desktop=DesktopEnvironmentKind::Unknown;f.snapshot[0].classificationError="agent unavailable";f.run(false);require(f.controller.status().severity==IncidentSeverity::Hard,"trusted unclassified inventory missed compliance");}
}
}
int main() {
    root=fs::temp_directory_path()/("fic-session-ready-incident-"+std::to_string(getpid()));fs::remove_all(root);fs::create_directories(root/"config");fs::create_directories(root/"log");::chmod(root.c_str(),0700);
    std::ofstream(root/"config/AUDIT.conf")<<"log_level=NoLog\n";
    auto paths=fic::core::FicProductPaths::production();paths.configDir=root/"config";paths.logDir=root/"log";paths.runtimeDir=root/"run";paths.dataDir=root/"data";
    std::string error;require(fic::core::FicRuntimePaths::initialize(paths,error),error);
    IncidentStateStore::setOwnershipExpectationForTests(getuid(),getuid());
    IncidentSessionTargetStore::setOwnershipExpectationForTests(getuid(),getuid());
    try {scenarios();} catch(...) {fs::remove_all(root);throw;}
    fs::remove_all(root);
}
