#include "modules/oss/display_manager/policies/OSS_disable_autologin.h"
#include "modules/oss/display_manager/policies/OSS_absence_of_uncontrolled_display_managers.h"
#include "modules/oss/display_manager/ControlledDisplayManagersPolicyTypeValue.h"
#include "rollback/ScopeTransition.h"
#include "policy/execution/PolicyExecutionPlanner.h"
#include "policy/execution/PolicyDependencyGraph.h"
#include "policy/registry/PolicyRegistryMutation.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <nlohmann/json.hpp>
namespace fs=std::filesystem;
using namespace fic::rollback;
using fic::platform::ExecutableId;
void require(bool ok,const std::string& error){if(!ok)throw std::runtime_error(error);}
void put(const fs::path& p,const std::string& text){fs::create_directories(p.parent_path());std::ofstream(p)<<text;::chmod(p.c_str(),0644);}
std::string get(const fs::path& p){std::ifstream in(p);return {std::istreambuf_iterator<char>(in),{}};}
struct Inventory final:DisplayManagerInventory{
    DisplayManagerSnapshot value;bool fail=false;
    Inventory(){value.complete=true;for(const auto* dm:{"SDDM","GDM","LIGHTDM"})value.managers[dm]={true,false,false};}
    bool inspect(DisplayManagerSnapshot& out,std::string& error)const override{out=value;if(fail){error="injected inventory error";return false;}return true;}
};
struct Fixture{
    fs::path root;
    fic::platform::DisplayManagerPlatformConfig config;
    std::shared_ptr<Inventory> inventory=std::make_shared<Inventory>();
    std::shared_ptr<DisplayManagerConfigTransaction> backend;
    MutationJournal journal;
    bool failNative=false;
    std::function<void()> inspectHook;
    Fixture(const std::string& label):root(fs::temp_directory_path()/("fic-dm-"+label+"-"+std::to_string(getpid()))),journal(root/"journal.json"){
        fs::remove_all(root);fs::create_directories(root);
        config.sddmConfigPath=root/"etc/sddm.conf";
        config.lightDmConfigPath=root/"etc/lightdm/lightdm.conf";
        config.gdmConfigCandidates={root/"etc/gdm/custom.conf"};
        config.gdmRuntimeConfigPath=root/"run/gdm/custom.conf";
        config.sddmConfigDirectories={root/"usr/lib/sddm/sddm.conf.d",root/"etc/sddm.conf.d"};
        config.lightDmConfigDirectories={root/"usr/share/lightdm/lightdm.conf.d",root/"etc/lightdm/lightdm.conf.d"};
        fs::create_directories(config.sddmConfigPath.parent_path());fs::create_directories(config.lightDmConfigPath.parent_path());fs::create_directories(config.gdmConfigCandidates[0].parent_path());
        std::string error;require(journal.initializeOrLoad(error),error);
        backend=std::make_shared<DisplayManagerConfigTransaction>([this](ExecutableId id,const std::vector<std::string>& args){
            ProcessResult r;r.started=true;r.exitCode=failNative?1:0;
            r.standardOutput=id==ExecutableId::PackageQuery?"installed 0.20.0\n":id==ExecutableId::Gdm?"GDM 43.0\n":"[Seat:*]\nA autologin-user=\nA autologin-guest=false\n";
            if(inspectHook){auto hook=std::move(inspectHook);inspectHook={};hook();}return r;
        },config,(root/"dm.lock").string());
    }
    ~Fixture(){AtomicFileWriter::setDirectoryFsyncHookForTests({});AtomicFileWriter::setPreInstallHookForTests({});fs::remove_all(root);}
};
void filesystemLifecycle(){
    Fixture f("lifecycle");std::string error;
    const std::string sddm="[Autologin]\r\nUser=admin\r\nSession=plasma\r\nRelogin=true\r\n# tail";
    const std::string gdm="[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=admin\nTimedLoginEnable=true\nTimedLogin=second\n";
    put(f.config.sddmConfigPath,sddm);put(f.config.gdmConfigCandidates[0],gdm);
    put(f.config.lightDmConfigDirectories[0]/"10-autologin.conf","[Seat:seat0]\nautologin-user=admin\nautologin-guest=true\nautologin-session=xfce\n");
    for(const auto* dm:{"SDDM","GDM","LIGHTDM"})require(f.backend->preflight(dm,true,f.journal,error),error);
    for(const auto* dm:{"SDDM","GDM","LIGHTDM"})require(f.backend->reconcile(dm,true,f.journal,error),error);
    require(get(f.config.sddmConfigPath).find(sddm)==0,"SDDM administrator bytes changed");
    require(get(f.config.sddmConfigPath).find("Session=plasma")!=std::string::npos,"SDDM Session lost");
    require(get(f.config.gdmConfigCandidates[0]).find(gdm)==0,"GDM user names changed");
    require(get(f.config.lightDmConfigPath).find("[Seat:seat0]\nautologin-user=\nautologin-guest=false")!=std::string::npos,"specific seat not protected");
    put(f.config.sddmConfigPath,get(f.config.sddmConfigPath)+"[Theme]\nCurrent=foreign\n");
    put(f.config.lightDmConfigPath,get(f.config.lightDmConfigPath)+"[LightDM]\n# foreign-created-file-content\n");
    MutationJournal reopened(f.root/"journal.json");require(reopened.load(error),error);
    require(f.backend->releaseAll(reopened,error),error);
    require(get(f.config.sddmConfigPath)==sddm+"\n[Theme]\nCurrent=foreign\n","foreign edit lost on release");
    require(get(f.config.gdmConfigCandidates[0])==gdm,"GDM inverse lost original flags");
    require(fs::exists(f.config.lightDmConfigPath)&&get(f.config.lightDmConfigPath)=="[LightDM]\n# foreign-created-file-content\n","created file foreign content lost");
    require(f.backend->releaseAll(reopened,error),"repeat release failed: "+error);
    require(f.backend->reconcile("GDM",true,reopened,error),error);
    require(f.backend->reconcile("GDM",false,reopened,error),error);
}
void alreadyDisabledStillOwned() {
    Fixture f("already-disabled"); std::string error;
    const std::map<std::string,std::pair<fs::path,std::string>> cases = {
        {"SDDM", {f.config.sddmConfigPath,"[Autologin]\nUser=\nRelogin=false\n"}},
        {"GDM", {f.config.gdmConfigCandidates[0],"[daemon]\nAutomaticLoginEnable=false\nTimedLoginEnable=false\n"}},
        {"LIGHTDM", {f.config.lightDmConfigPath,"[Seat:*]\nautologin-user=\nautologin-guest=false\n"}}
    };
    for (const auto& [dm, fixture] : cases) {
        const auto& [path, original] = fixture;
        put(path,original);
        require(f.backend->reconcile(dm,true,f.journal,error),error);
        require(get(path).find(original) == 0 && get(path) != original,
                "already disabled foreign state skipped FIC enrollment: " + dm);
        require(f.backend->verifyApplied(dm,f.journal,error),error);
        require(f.backend->reconcile(dm,false,f.journal,error),error);
        require(get(path)==original,"release changed already-disabled administrator state");
    }
}

void conflicts(){
    Fixture f("conflicts");std::string error;
    put(f.config.gdmConfigCandidates[0],"[daemon]\nAutomaticLogin=admin\n");
    put(f.config.gdmRuntimeConfigPath,"[daemon]\nTimedLoginEnable=true\n");
    require(!f.backend->preflight("GDM",true,f.journal,error),"runtime override accepted");
    require(get(f.config.gdmConfigCandidates[0]).find("FIC-DM")==std::string::npos,"preflight wrote primary");
    fs::remove(f.config.gdmRuntimeConfigPath);
    f.failNative=true;require(!f.backend->reconcile("GDM",true,f.journal,error),"native failure accepted");f.failNative=false;
    require(f.backend->reconcile("GDM",true,f.journal,error),error);
    const auto correct=get(f.config.gdmConfigCandidates[0]);
    put(f.config.gdmConfigCandidates[0],correct+"[daemon]\nTimedLoginEnable=true\n");
    require(!f.backend->preflight("GDM",true,f.journal,error),"foreign override claimed disabled");
    require(f.backend->reconcile("GDM",false,f.journal,error),"foreign override should not block owned release: "+error);
    require(get(f.config.gdmConfigCandidates[0]).find("TimedLoginEnable=true")!=std::string::npos,"foreign override erased");
    require(f.backend->reconcile("GDM",true,f.journal,error),error);
    const auto owned=get(f.config.gdmConfigCandidates[0]);auto changed=owned;auto at=changed.find("# FIC-DM BEGIN ");changed.replace(at+15,1,"9");
    put(f.config.gdmConfigCandidates[0],changed);require(!f.backend->releaseAll(f.journal,error),"ID mismatch release accepted");
    require(get(f.config.gdmConfigCandidates[0])==changed,"ID mismatch resource touched");
    put(f.config.gdmConfigCandidates[0],owned);require(f.backend->releaseAll(f.journal,error),error);
    put(f.config.sddmConfigPath,"# FIC-DM BEGIN 999 SDDM\n[Autologin]\nUser=\n");
    require(!f.backend->releaseAll(f.journal,error),"orphan accepted");
    fs::remove(f.config.sddmConfigPath);fs::create_symlink(f.config.gdmConfigCandidates[0],f.config.sddmConfigPath);
    require(!f.backend->reconcile("SDDM",true,f.journal,error),"symlink accepted");
    fs::remove(f.config.sddmConfigPath);put(f.config.sddmConfigPath,"[Autologin]\nUser=admin\n");
    const auto unsafeOriginal=get(f.config.sddmConfigPath);
    require(::chmod(f.config.sddmConfigPath.c_str(),0666)==0,"cannot prepare unsafe permission fixture");
    require(!f.backend->reconcile("SDDM",true,f.journal,error)&&get(f.config.sddmConfigPath)==unsafeOriginal,
        "writable foreign DM configuration accepted or changed");
    require(::chmod(f.config.sddmConfigPath.c_str(),0644)==0 &&
                ::chown(f.config.sddmConfigPath.c_str(),65534,65534)==0,"cannot prepare foreign ownership fixture");
    require(!f.backend->reconcile("SDDM",true,f.journal,error)&&get(f.config.sddmConfigPath)==unsafeOriginal,
        "non-root DM configuration accepted or changed");
    require(::chown(f.config.sddmConfigPath.c_str(),0,0)==0,"cannot restore fixture ownership");
}
void durabilityAndCrash(){
    Fixture f("crash");std::string error;
    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& p){return p!=f.config.sddmConfigPath.string();});
    require(!f.backend->reconcile("SDDM",true,f.journal,error),"post-write fsync failure accepted");
    require(get(f.config.sddmConfigPath).find("FIC-DM")!=std::string::npos,"fault did not happen after publish");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    MutationJournal restarted(f.root/"journal.json");require(restarted.load(error),error);
    require(f.backend->reconcile("SDDM",true,restarted,error),error);
    require(f.backend->reconcile("SDDM",false,restarted,error),error);
    require(!fs::exists(f.config.sddmConfigPath),"created main not deleted");
    pid_t pid=fork();require(pid>=0,"fork failed");if(pid==0){
        AtomicFileWriter::setPreInstallHookForTests([&](const std::string& p){if(p==f.config.sddmConfigPath.string())_exit(91);});
        f.backend->reconcile("SDDM",true,restarted,error);_exit(99);
    }
    int status=0;waitpid(pid,&status,0);require(WIFEXITED(status)&&WEXITSTATUS(status)==91,"prewrite crash seam missed");
    MutationJournal prewrite(f.root/"journal.json");require(prewrite.load(error),error);
    require(f.backend->reconcile("SDDM",false,prewrite,error),error);
    require(!fs::exists(f.config.sddmConfigPath),"abort of unpublished creation created a file");
    pid=fork();require(pid>=0,"fork failed");if(pid==0){
        AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& p){if(p==f.config.sddmConfigPath.string())_exit(92);return true;});
        f.backend->reconcile("SDDM",true,prewrite,error);_exit(99);
    }
    waitpid(pid,&status,0);require(WIFEXITED(status)&&WEXITSTATUS(status)==92,"postwrite crash seam missed");
    MutationJournal postwrite(f.root/"journal.json");require(postwrite.load(error),error);
    require(f.backend->reconcile("SDDM",true,postwrite,error),error);
    require(f.backend->releaseAll(postwrite,error),error);
}
void actualProofAndReleaseRetry(){
    Fixture f("actual-proof");std::string error;
    require(f.backend->preflight("SDDM",true,f.journal,error),error);
    require(!f.backend->verifyApplied("SDDM",f.journal,error),"hypothetical preflight passed as actual protection");
    require(f.backend->reconcile("SDDM",true,f.journal,error),error);
    const auto protectedMain=get(f.config.sddmConfigPath);
    f.inspectHook=[&]{put(f.config.sddmConfigPath,protectedMain+"[Autologin]\nUser=foreign\n");};
    require(!f.backend->verifyApplied("SDDM",f.journal,error),"native inspection-time input drift falsely verified");
    put(f.config.sddmConfigPath,protectedMain);
    require(f.backend->verifyApplied("SDDM",f.journal,error),error);
    MutationId before=0;for(const auto& r:f.journal.records())if(r.isActive()&&r.resource=="DM/SDDM/autologin")before=r.id;
    AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){return path!=f.config.sddmConfigPath.string();});
    require(!f.backend->reconcile("SDDM",false,f.journal,error),"release durability failure accepted");
    require(!f.backend->verifyReleased("SDDM",f.journal,error),"unresolved release verified");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(f.backend->preflight("SDDM",true,f.journal,error),error);
    require(f.backend->reconcile("SDDM",true,f.journal,error),error);
    require(f.backend->verifyApplied("SDDM",f.journal,error),error);
    MutationId after=0;for(const auto& r:f.journal.records())if(r.isActive()&&r.resource=="DM/SDDM/autologin")after=r.id;
    require(before!=after,"completed release reconstructed old mutation identity");
    const auto content=get(f.config.sddmConfigPath);
    put(f.root/"replacement",content);fs::rename(f.root/"replacement",f.config.sddmConfigPath);
    require(f.backend->reconcile("SDDM",false,f.journal,error),error);
    require(fs::exists(f.config.sddmConfigPath)&&get(f.config.sddmConfigPath).empty(),"transferred replacement inode was deleted");
    require(f.backend->verifyReleased("SDDM",f.journal,error),error);
    put(f.config.sddmConfigDirectories[0]/"foreign.conf","# FIC-DM BEGIN 999 SDDM\n");
    require(!f.backend->releaseAll(f.journal,error),"orphan secondary-route marker ignored");
}
void journalGuards(){
    Fixture f("journal-guards");std::string error;MutationId id=0;
    MutationRecord r;r.policy={"OSS","DisplayManager","disable_autologin"};r.resource="DM/GDM/autologin";
    UndoRemoveDisplayManagerBlock payload;payload.manager="GDM";
    payload.hadApplied=true;r.undo={MutationBackend::DisplayManager,payload};
    require(!f.journal.prepareMutation(r,id,error),"fresh record invented applied authority");
    payload.hadApplied=false;payload.phase="release";r.undo.payload=payload;
    require(!f.journal.prepareMutation(r,id,error),"fresh record invented release authority");
    payload.phase="ensure";payload.manager="../GDM";r.undo.payload=payload;
    require(!f.journal.prepareMutation(r,id,error),"path-like manager accepted");
    payload.manager="GDM";payload.route=8;r.undo.payload=payload;
    require(!f.journal.prepareMutation(r,id,error),"untrusted route accepted");
    payload.route=0;payload.seats={"Seat:*"};r.undo.payload=payload;
    require(!f.journal.prepareMutation(r,id,error),"foreign backend seats accepted");
    payload.seats={};r.undo={MutationBackend::Desktop,payload};
    require(!f.journal.prepareMutation(r,id,error),"cross-backend payload accepted");
    payload.createdFile=true;payload.creationInode=99;r.undo={MutationBackend::DisplayManager,payload};
    require(!f.journal.prepareMutation(r,id,error),"fresh creation inode authority invented");
    payload.creationInode=0;r.undo.payload=payload;
    require(f.journal.prepareMutation(r,id,error),error);
    require(!f.journal.setStatus(id,MutationStatus::Applied,error),"Applied without physical proof accepted");
    payload.hadApplied=true;payload.creationDevice=1;payload.creationInode=99;r.undo.payload=payload;
    require(f.journal.prepareMutation(r,id,error)&&f.journal.setStatus(id,MutationStatus::Applied,error),error);
    payload.creationInode=100;r.undo.payload=payload;
    require(!f.journal.prepareMutation(r,id,error),"immutable creation inode refreshed");
    payload.creationInode=99;payload.createdFile=false;r.undo.payload=payload;
    require(!f.journal.prepareMutation(r,id,error),"creation proof discarded");
    MutationRecord scope;scope.policy={"OSS","DesktopEnvironment","controlled_desktop_environments"};scope.resource="scope/de";
    scope.undo={MutationBackend::Scope,ScopeTransitionCheckpoint{{},{"GDM"},"pending"}};
    require(!f.journal.prepareMutation(scope,id,error),"DM names crossed DE checkpoint");
    scope.policy={"OSS","DisplayManager","controlled_display_managers"};scope.resource="scope/dm";
    scope.undo={MutationBackend::Scope,ScopeTransitionCheckpoint{{},{"KDE"},"pending"}};
    require(!f.journal.prepareMutation(scope,id,error),"DE names crossed DM checkpoint");
    MutationJournal reload(f.root/"journal.json");require(reload.load(error),error);
    require(reload.records().size()==1,"refused records leaked into journal");
    const auto original=get(f.root/"journal.json");
    const auto document=nlohmann::json::parse(original);
    for(const auto& [key,value]:std::vector<std::pair<std::string,nlohmann::json>>{
        {"route",9},{"route",std::uint64_t{1}<<32},{"manager","../GDM"},{"backend","desktop"},
        {"phase","release"},{"had_applied",false},{"creation_inode",0}}) {
        auto corrupt=document;corrupt["records"][0]["undo"][key]=value;
        put(f.root/"journal.json",corrupt.dump());
        MutationJournal refused(f.root/"journal.json");
        require(!refused.load(error)&&!refused.usable(),"corrupt DM provenance loaded: "+key);
    }
    put(f.root/"journal.json",original);
}
void inventoryProof(){
    Fixture f("inventory");std::string error;
    auto runner=[](ExecutableId id,const std::vector<std::string>& args){
        ProcessResult r;r.started=true;r.exitCode=0;
        if(id==ExecutableId::PackageQuery){r.standardOutput="sddm\tinstalled\nlightdm\tinstalled\n";return r;}
        if(id==ExecutableId::Loginctl){r.standardOutput="";return r;}
        if(args[0]=="list-unit-files"){r.standardOutput="sddm.service enabled\nlightdm.service disabled\nodd.service enabled\n";return r;}
        if(args[0]=="list-units"){r.standardOutput="odd.service loaded active running Weird display manager\n";return r;}
        if(args[1]=="sddm.service")r.standardOutput="Id=sddm.service\nNames=sddm.service\nLoadState=loaded\nActiveState=inactive\nExecStart={ path=/usr/bin/sddm ; }\n";
        else if(args[1]=="lightdm.service")r.standardOutput="Id=lightdm.service\nLoadState=loaded\nActiveState=inactive\nExecStart={ path=/usr/sbin/lightdm ; }\n";
        else if(args[1]=="odd.service")r.standardOutput="Id=odd.service\nLoadState=loaded\nActiveState=active\nDescription=Weird Display Manager\nExecStart={ path=/usr/bin/weird ; }\n";
        else r.standardOutput="LoadState=not-found\nActiveState=inactive\n";
        return r;
    };
    SystemDisplayManagerInventory inventory(runner,f.config);DisplayManagerSnapshot snapshot;
    require(inventory.inspect(snapshot,error),error);
    require(snapshot.managers["SDDM"].selected&&!snapshot.managers["SDDM"].running,"enabled inactive DM not selected");
    require(snapshot.managers["LIGHTDM"].installed&&!snapshot.managers["LIGHTDM"].selected,"installed unused not classified");
    require(!snapshot.unknownSelectedOrRunning.empty(),"unknown independently active DM missed");
    require(SystemDisplayManagerInventory::canonicalName("gdm3.service")=="GDM","GDM3 normalization failed");
    SystemDisplayManagerInventory custom([&](ExecutableId id,const std::vector<std::string>& args){
        auto result=runner(id,args);
        if(id==ExecutableId::Systemctl && args.front()=="show" && args[1]=="sddm.service")
            result.standardOutput="Id=sddm.service\nLoadState=loaded\nActiveState=inactive\nExecStart={ path=/usr/bin/custom-wrapper ; }\n";
        return result;
    },f.config);
    require(custom.inspect(snapshot,error)&&!snapshot.managers["SDDM"].configurationSupported,
        "inactive custom DM wrapper falsely proved native configuration");
    SystemDisplayManagerInventory headless([](ExecutableId,const std::vector<std::string>& args){
        ProcessResult result;result.started=true;result.exitCode=0;
        require(args.front()!="show","headless inventory queried a nonexistent unit");return result;
    },f.config);
    require(headless.inspect(snapshot,error)&&snapshot.complete,"complete headless inventory rejected");
    require(!snapshot.managers["SDDM"].installed&&!snapshot.managers["GDM"].installed,"headless inventory invented installation");
    SystemDisplayManagerInventory incomplete([](ExecutableId,const std::vector<std::string>&){return ProcessResult{};},f.config);
    require(!incomplete.inspect(snapshot,error)&&!snapshot.complete,"inventory failure accepted headless");
}
void scopeLifecycle(){
    Fixture f("scope");std::string error;
    auto paths=fic::core::FicProductPaths::production();paths.configDir=f.root/"config";paths.defaultConfigDir=f.root/"defaults";paths.logDir=f.root/"log";
    paths.runtimeDir=f.root/"run";paths.dataDir=f.root/"data";paths.commandHashFile=f.root/"data/hash";paths.deviceDatabaseFile=f.root/"data/db";
    paths.deviceDatabaseLockFile=f.root/"log/db.lock";paths.lockDebugLogFile=f.root/"log/lock.log";
    require(fic::core::FicRuntimePaths::initialize(paths,error),error);
    auto configure=[&](const std::string& target,const std::string& status="ENABLE"){
        put(paths.configDir/"OSS.conf","controlled_display_managers.status="+status+"\ncontrolled_display_managers.value="+target+
            "\ndisable_autologin.status=ENABLE\ndisable_autologin.value=ENABLE\nabsence_of_uncontrolled_display_managers.status=ENABLE\nabsence_of_uncontrolled_display_managers.value=ENABLE\n");
    };
    configure("[]");
    {OSS_controlled_display_managers scope(f.inventory,f.backend,&f.journal);OSS_disable_autologin ban(scope,f.inventory,f.backend,&f.journal);
        require(!scope.reconcile(ban,error)&&!scope.apply(),"empty DM scope committed");}
    configure("[\"SDDM\",\"GDM\"]");
    {OSS_controlled_display_managers scope(f.inventory,f.backend,&f.journal);OSS_disable_autologin ban(scope,f.inventory,f.backend,&f.journal);
        require(scope.apply() && !fs::exists(f.config.gdmConfigCandidates[0]),"scope validation mutated files");
        require(ban.apply(),"dependent apply did not reconcile fresh scope");
        require(scope.reconcile(ban,error),error);require(scope.apply()&&ban.apply(),"committed DM scope refused");
        ScopeTransition de(f.journal);ScopeTransitionState state;require(de.state(state,error)&&!state.id,"DM checkpoint confused with DE");}
    configure("[\"SDDM\"]");
    {OSS_controlled_display_managers scope(f.inventory,f.backend,&f.journal);OSS_disable_autologin ban(scope,f.inventory,f.backend,&f.journal);
        require(fs::exists(f.config.gdmConfigCandidates[0]),"saving scope released old manager");
        require(scope.apply() && fs::exists(f.config.gdmConfigCandidates[0]),"scope validation released GDM");
        require(scope.reconcile(ban,error),error);require(!fs::exists(f.config.gdmConfigCandidates[0]),"removed GDM ownership remains");
        OSS_absence_of_uncontrolled_display_managers compliance(scope,f.inventory);
        require(compliance.evaluate(f.inventory->value,error),"installed unused outside scope rejected");
        auto snapshot=f.inventory->value;snapshot.managers["GDM"].selected=true;require(!compliance.evaluate(snapshot,error),"uncontrolled next-boot manager accepted");
        snapshot=f.inventory->value;snapshot.unknownSelectedOrRunning={"weird"};require(!compliance.evaluate(snapshot,error),"unknown active accepted");
        snapshot={};snapshot.complete=true;require(compliance.evaluate(snapshot,error),"proven headless failed");
        snapshot.complete=false;require(!compliance.evaluate(snapshot,error),"incomplete headless accepted");
        f.inventory->fail=true;require(!scope.reconcile(ban,error)&&!ban.apply(),"failed transition authorized consumer");f.inventory->fail=false;
    }
    configure("[\"SDDM\",\"GDM\"]");
    {OSS_controlled_display_managers scope(f.inventory,f.backend,&f.journal);OSS_disable_autologin ban(scope,f.inventory,f.backend,&f.journal);
        require(scope.reconcile(ban,error),error);require(fs::exists(f.config.gdmConfigCandidates[0]),"added GDM absent");
        f.inspectHook=[&]{configure("[\"LIGHTDM\"]");};require(!scope.reconcile(ban,error),"intent change committed stale target");require(scope.apply(),"partial global state invalidated declaration");}
    configure("[\"SDDM\"]","DISABLE");
    {PolicyRegistry registry;require(registry.addModule("OSS",ModuleView::Standard,0,error),error);
        auto scope=std::make_unique<OSS_controlled_display_managers>(f.inventory,f.backend,&f.journal);auto* s=scope.get();
        require(registry.addPolicy(std::move(scope),error),error);
        require(registry.addPolicy(std::make_unique<OSS_disable_autologin>(*s,f.inventory,f.backend,&f.journal),error),error);
        PolicyExecutionRequest request;request.requestedRoots={{"OSS","DisplayManager","disable_autologin"}};
        const auto result=PolicyExecutionPlanner(registry).execute(request);require(result.failedCount()>0,"disabled Required did not block planner");
        bool blocked=false;for(const auto& item:result.getResults())if(item.policyName=="disable_autologin")blocked=item.failureOrigin==PolicyFailureOrigin::RequiredDependencyBlocked&&!item.ownApplyAttempted;
        require(blocked,"planner attempted Required-dependent apply");
        require(enabledRequiredDependents(registry,{"OSS","DisplayManager","controlled_display_managers"}).size()==1,"reverse dependency guard misses autologin");
        const auto before=get(f.config.sddmConfigPath);
        require(setPolicyValue(registry,"OSS","controlled_display_managers","LIGHTDM",error),error);
        require(get(f.config.sddmConfigPath)==before,"set_value mutated DM configuration");}
    require(f.backend->releaseAll(f.journal,error),error);
}
int main(){try{
    require(geteuid()==0,"DM filesystem tests require disposable root container");
    ControlledDisplayManagersPolicyTypeValue type;std::vector<std::string> names;
    require(type.validate("")&&type.postProcessingValue("")=="[]","empty typed scope invalid");
    require(type.postProcessingValue("sddm,GDM,lightdm")=="[\"GDM\",\"LIGHTDM\",\"SDDM\"]","canonical list invalid");
    require(!type.validate("SDDM,SDDM")&&!type.validate("GDM3")&&!type.validate("weird")&&!type.validate("SDDM,"),"invalid tokens accepted");
    filesystemLifecycle();alreadyDisabledStillOwned();conflicts();durabilityAndCrash();actualProofAndReleaseRetry();journalGuards();inventoryProof();scopeLifecycle();
    std::cout<<"PASS: DM transaction, ownership, native failure, crash recovery, scope and inventory contracts\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
