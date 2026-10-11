#include "session/SessionPolicyReconciler.h"
#include "modules/oss/desktop_environment/SessionAwareDesktopEnvironmentPolicy.h"
#include "modules/oss/desktop_environment/policies/OSS_absence_of_uncontrolled_desktop_environments.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include "modules/oss/desktop_environment/backends/GnomeSystemBackend.h"
#include "modules/oss/desktop_environment/backends/FlySystemBackend.h"
#include "rollback/ScopeTransition.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <sstream>
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
std::string read(const fs::path& path) { std::ifstream f(path); return {std::istreambuf_iterator<char>(f),{}}; }
void write(const fs::path& path,const std::string& text) { fs::create_directories(path.parent_path());std::ofstream(path)<<text; }
DesktopManagedSettings requirements(unsigned seconds=300) {
    return {{{"/org/gnome/desktop/session/idle-delay"},"uint32 "+std::to_string(seconds)},
            {{"/org/gnome/desktop/screensaver/lock-enabled"},"true"},
            {{"/org/gnome/desktop/screensaver/lock-delay"},"uint32 0"},
            {{"/org/gnome/desktop/lockdown/disable-lock-screen"},"false"}};
}
#include "../modules/oss/desktop_environment/GnomeFixtureCommands.h"
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
    void refreshForTests() {require(moduleConf->loadConfig(),"scope refresh");}
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
struct SessionPolicy final : SessionAwareDesktopEnvironmentPolicy, GlobalDesktopPolicyContributor {
    bool contribute=false;
    void refreshForTests() {require(moduleConf->loadConfig(),"policy refresh");}
    void disableForTests() {require(moduleConf->disablePolicy(policyName)&&moduleConf->saveConfig(),"test disable");}
    int calls=0,appliedSetting=0; bool nativeOk=true,relevant=true,throws=false,unsupported=false,emptyError=false;
    SessionPolicy(Scope& scope,std::shared_ptr<Inventory> inventory,const std::string& name)
        :SessionAwareDesktopEnvironmentPolicy(scope,inventory) { policyName=name;addRequiredDependency({"OSS","DesktopEnvironment","controlled_desktop_environments"}); }
    std::vector<PolicyCapability> capabilities() const override {
        auto result=SessionAwareDesktopEnvironmentPolicy::capabilities();
        if(contribute) result.push_back(PolicyCapability::GlobalDesktopConfiguration);
        return result;
    }
    bool globalDesktopPolicyContributions(std::vector<GlobalDesktopPolicyContribution>& out,std::string& error) override {
        out.clear();error.clear();
        for(auto de:{DesktopEnvironmentKind::Gnome,DesktopEnvironmentKind::Fly}) {
            if(sessionApplicability(de,error)!=SessionApplicability::Applicable)continue;
            const PolicyRef owner{moduleName,submoduleName,policyName};
            if(de==DesktopEnvironmentKind::Gnome)for(const auto& [key,value]:requirements())out.push_back({"gnome",de,owner,key,value});
            else out.push_back({"fly",de,owner,{"themerc/Variables/ScreenSaverDelay"},"300"});
        }
        return true;
    }
    bool prepare(std::string&) override { return true; }
    bool relevantTo(DesktopEnvironmentKind) const override { return relevant; }
    EnforcementMode modeFor(DesktopEnvironmentKind desktop) const override {
        if(unsupported)return EnforcementMode::Unsupported;
        return (desktop==DesktopEnvironmentKind::Gnome||desktop==DesktopEnvironmentKind::Fly)?EnforcementMode::MandatoryGlobal:EnforcementMode::SessionOnly; }
    bool reconcileControlledSession(const SessionReconcileContext&,std::string& error) override {
        ++calls;if(throws)throw std::runtime_error("native exception");if(!nativeOk&&!emptyError)error=policyName+" native failure";if(nativeOk)appliedSetting=300;return nativeOk; }
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
    Fixture(bool aEnabled=true,bool bEnabled=false,bool compliance=false,bool scopeEnabled=true,const char* severity="SOFT",bool globalContributor=false)
        :controller(IncidentStateStore(root/("state"+std::to_string(++sequence))),sessions,std::make_shared<Network>()) {
        const auto state=root/("state"+std::to_string(sequence));std::ofstream(state)<<"UNLOCKED\n";::chmod(state.c_str(),0640);
        std::ofstream(root/"config/OSS.conf")<<"controlled_desktop_environments.status="<<(scopeEnabled?"ENABLE":"DISABLE")
            <<"\ncontrolled_desktop_environments.violation_severity=NONE\nscreenlock_timeout.status="<<(aEnabled?"ENABLE":"DISABLE")
            <<"\nscreenlock_timeout.violation_severity="<<severity<<"\ndisable_kde_lock_screen_media_controls.status="<<(bEnabled?"ENABLE":"DISABLE")
            <<"\ndisable_kde_lock_screen_media_controls.violation_severity=HARD\nabsence_of_uncontrolled_desktop_environments.status="<<(compliance?"ENABLE":"DISABLE")
            <<"\nabsence_of_uncontrolled_desktop_environments.violation_severity=HARD\n";
        std::string error;require(registry.addModule("OSS",ModuleView::Standard,0,error),error);
        auto s=std::make_unique<Scope>();scope=s.get();require(registry.addPolicy(std::move(s),error),error);
        auto first=std::make_unique<SessionPolicy>(*scope,inventory,"screenlock_timeout");a=first.get();a->contribute=globalContributor;require(registry.addPolicy(std::move(first),error),error);
        auto second=std::make_unique<SessionPolicy>(*scope,inventory,"disable_kde_lock_screen_media_controls");b=second.get();b->contribute=globalContributor;require(registry.addPolicy(std::move(second),error),error);
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
// Delegate all physical work to production backends; inject drift only after
// coordinator preflight to exercise the real release refusal path.
struct PhysicalBackend final : DesktopSystemBackend {
    std::shared_ptr<DesktopSystemBackend> native;
    std::function<void()> beforeRelease,afterVerify;
    DesktopEnvironmentKind desktop() const override {return native->desktop();}
    std::string backendName() const override {return native->backendName();}
    bool verifiedEnforcementAvailable(std::string& e) const override {return native->verifiedEnforcementAvailable(e);}
    bool ensureManagedSettings(const DesktopManagedSettings& r,std::string& e) override {return native->ensureManagedSettings(r,e);}
    bool verifyManagedSettings(const DesktopManagedSettings& r,std::string& e) override {
        const bool ok=native->verifyManagedSettings(r,e);if(ok&&afterVerify)afterVerify();return ok;
    }
    bool preflightJournaled(const DesktopGlobalConfigRequirements& r,fic::rollback::MutationJournal& j,std::string& e) override {return native->preflightJournaled(r,j,e);}
    bool reconcileJournaled(const DesktopGlobalConfigRequirements& r,fic::rollback::MutationJournal& j,std::string& e) override {
        if(r.empty()&&beforeRelease)beforeRelease();return native->reconcileJournaled(r,j,e);
    }
};
void releaseScenarios() {
    using namespace fic::rollback;
    for(const auto de:{DesktopEnvironmentKind::Gnome,DesktopEnvironmentKind::Fly})
    for(const auto scenario:{"NONE","SOFT","HARD","ISOLATE","disabled","unknown","corrupt","shared","preflight","session_failure","progress_failure","checkpoint","checkpoint_desired"}) {
        const std::string mode=scenario;
        const char* severity=(mode=="NONE"||mode=="SOFT"||mode=="HARD"||mode=="ISOLATE")?scenario:"HARD";
        Fixture f(true,mode=="shared",false,true,severity,true);
        f.scope->target.insert(de);
        const auto physical=root/("physical"+std::to_string(sequence));fs::create_directories(physical);::chmod(physical.c_str(),0755);
        MutationJournal journal(physical/"journal.json");std::string error;require(journal.initializeOrLoad(error),error);
        FakeCommands commands;
        auto backend=std::make_shared<PhysicalBackend>();fs::path resource;
        if(de==DesktopEnvironmentKind::Gnome) {
            GnomeSystemBackendOptions options;options.trustedRoot=physical;options.profilePath=physical/"dconf/profile/user";
            options.databaseRoot=physical/"dconf/db";options.trustedOwner=getuid();options.trustedGroup=getgid();options.lockPath=physical/"lock";
            resource=options.databaseRoot/"fic.d/99-fic.conf";
            write(options.profilePath,"user-db:user\nsystem-db:fic\n");
            write(resource,"[org/gnome/desktop/session]\nidle-delay=uint32 600\n[org/gnome/desktop/screensaver]\nlock-enabled=false\nlock-delay=uint32 10\n[org/gnome/desktop/lockdown]\ndisable-lock-screen=true\n");
            write(options.databaseRoot/"fic.d/locks/99-fic","");
            commands.compiledPath=options.databaseRoot/"fic";
            write(commands.compiledPath,FakeCommands::nativeBytes(resource.parent_path()));commands.inspectSources();
            backend->native=std::make_shared<GnomeSystemBackend>(commands.dependencies(),options);
        } else {
            FlySystemBackendOptions options;options.trustedRoot=physical;options.configPath=physical/"themerc";
            options.trustedOwner=getuid();options.trustedGroup=getgid();options.lockPath=physical/"lock";
            resource=options.configPath;write(resource,"[Variables]\nScreenSaverDelay=600\nforeign=keep\n");
            backend->native=std::make_shared<FlySystemBackend>(options);
        }
        DesktopGlobalConfigReconciler coordinator({backend},&journal);
        const auto initial=coordinator.reconcile(f.registry);require(initial.successful(),"initial real global apply failed: "+initial.diagnostic());
        const auto owned=read(resource);require(owned.find("# FIC-DE")!=std::string::npos,"test did not create physical FIC ownership");
        f.scope->target={DesktopEnvironmentKind::Kde};
        if(de==DesktopEnvironmentKind::Fly){f.target.desktop=DesktopEnvironmentKind::Xfce;f.snapshot={f.target};f.scope->target={f.target.desktop};}
        if(mode=="disabled") {f.a->disableForTests();f.scope->refreshForTests();f.a->refreshForTests();f.b->refreshForTests();}
        if(mode=="unknown"||mode=="corrupt") {
            MutationJournal unproven(physical/"unproven.json");
            if(mode=="corrupt") {write(physical/"unproven.json","broken journal");require(!unproven.initializeOrLoad(error),"corrupt journal accepted");}
            else require(unproven.initializeOrLoad(error),error);
            f.global=DesktopGlobalConfigReconciler({backend},&unproven).reconcile(f.registry);
            require(!f.global.successful()&&f.global.releaseFailures.empty()&&!f.run().hasFailures()&&f.notifications==0,
                    "unproven ownership falsely attributed to policy");
            require(read(resource)==owned,"unproven preflight modified physical resource");continue;
        }
        if(mode=="checkpoint"||mode=="checkpoint_desired") {
            if(mode=="checkpoint_desired") {f.scope->target.insert(de);f.target.desktop=de;f.snapshot={f.target};}
            backend->afterVerify=[&] {AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){return path!=(physical/"journal.json").string();});};
            f.global=coordinator.reconcile(f.registry);AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
            require(!f.global.successful()&&f.global.phase=="checkpoint_commit"&&f.global.releaseFailures.empty(),"checkpoint commit invented backend release failure");
            require(!f.run().hasFailures()&&f.a->calls==1&&f.notifications==0,"checkpoint-only error invented owner incident");
            require(!journal.usable(),"commit durability failure remained healthy");
            require(journal.initializeOrLoad(error),error);backend->afterVerify={};
            require(coordinator.reconcile(f.registry).successful(),"checkpoint commit recovery failed");continue;
        }
        const auto drift=de==DesktopEnvironmentKind::Gnome?"uint32 300":"ScreenSaverDelay=300";
        backend->beforeRelease=[&] {auto content=owned;const auto offset=content.find(drift);require(offset!=std::string::npos,"missing owned scalar");content.replace(offset,std::string(drift).size(),"foreign-invalid-value");write(resource,content);};
        if(mode=="progress_failure") backend->beforeRelease=[&] {
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){return path!=(physical/"journal.json").string();});
        };
        if(mode=="preflight") {backend->beforeRelease();backend->beforeRelease={};}
        if(mode=="session_failure")f.a->nativeOk=false;
        f.global=coordinator.reconcile(f.registry);AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
        require(!f.global.successful()&&f.global.phase==(mode=="preflight"?"global_preflight":"global_release")&&!f.global.releaseFailures.empty(),"release-only failure attribution missing");
        const auto afterFailure=read(resource);
        if(mode=="disabled") {
            require(!f.run().hasFailures()&&f.notifications==0&&!f.global.diagnostic().empty()&&read(resource)==afterFailure,
                    "disabled release owner caused incident or erased global diagnosis");
            backend->beforeRelease={};write(resource,owned);require(coordinator.reconcile(f.registry).successful(),"disabled owner release retry failed");continue;
        }
        auto summary=f.run();const auto& result=find(summary,"screenlock_timeout");
        require(result.isFailure()&&result.failureOrigin==PolicyFailureOrigin::OwnApplyFailure&&f.a->calls==1,
                "journal-backed release failure did not aggregate with independent session success");
        require(f.a->appliedSetting==(mode=="session_failure"?0:300),"release incident undid independently applied session setting");
        require(result.message.find(mode=="preflight"?"global_preflight":"global_release")!=std::string::npos&&result.message.find(mode=="session_failure"?"session_reconciliation FAILED":"session_reconciliation SUCCESS")!=std::string::npos,"release/session diagnostics missing");
        if(mode=="shared") {
            require(find(summary,"disable_kde_lock_screen_media_controls").isFailure(),"shared owner lost release incident");
            std::set<std::pair<PolicyRef,MutationId>> identities;
            for(const auto& failure:f.global.releaseFailures)require(identities.emplace(failure.owner,failure.mutation).second,"duplicate release attribution");
            require(identities.size()==(de==DesktopEnvironmentKind::Gnome?8u:2u),"shared physical ownership identity lost");
        }
        const auto expected=std::string(severity)=="NONE"?IncidentSeverity::Unlocked:std::string(severity)=="SOFT"?IncidentSeverity::Soft:std::string(severity)=="HARD"?IncidentSeverity::Hard:IncidentSeverity::Isolate;
        require(f.controller.status().severity==expected&&f.notifications==(expected==IncidentSeverity::Unlocked?0:1),"release incident severity incorrect");
        f.run();require(f.notifications==(expected==IncidentSeverity::Unlocked?0:1)&&read(resource)==afterFailure,"repeat incident duplicated or adapter changed resource");
        require(std::any_of(journal.records().begin(),journal.records().end(),[](const auto& r){return r.isActive()&&std::holds_alternative<UndoRestoreDesktopScalar>(r.undo.payload);}),"failed release lost journal record");
        if(mode=="progress_failure") {
            require(!journal.usable(),"release progress fault did not poison journal");
            require(journal.initializeOrLoad(error),error);
            require(std::any_of(journal.records().begin(),journal.records().end(),[](const auto& record){
                const auto* scalar=std::get_if<UndoRestoreDesktopScalar>(&record.undo.payload);
                return record.isActive()&&scalar&&scalar->phase=="release"&&scalar->owners.empty();
            }),"test failed to exercise owner-clearing release progress");
        }
        backend->beforeRelease={};f.a->nativeOk=true;write(resource,owned);
        f.global=coordinator.reconcile(f.registry);require(f.global.successful()&&f.global.releaseFailures.empty(),"retry did not finish ownership-safe release");
        require(!f.run().hasFailures(),"successful release left false obligation");
    }
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
    try {scenarios();releaseScenarios();} catch(...) {fs::remove_all(root);throw;}
    fs::remove_all(root);
}
