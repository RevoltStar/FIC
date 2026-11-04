#include "modules/sysctl/SysctlTransaction.h"
#include "modules/sysctl/SysctlSystemd.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using namespace fic::rollback;
namespace fs=std::filesystem;
void require(bool ok,const std::string& message){if(!ok)throw std::runtime_error(message);}
void write(const fs::path& p,const std::string& s){fs::create_directories(p.parent_path());std::ofstream f(p);f<<s;require(f.good(),"fixture write failed");}
std::string read(const fs::path& p){std::ifstream f(p);return {std::istreambuf_iterator<char>(f),{}};}
constexpr auto header="# Managed by FIC. Manual changes may be overwritten.\n";
const PolicyRef first{"SYSCTL","Global","first"},second{"SYSCTL","Global","second"};
struct Fixture {
    fs::path root;
    SysctlConfigurationOptions options;
    SysctlRuntimeOptions runtime;
    std::unique_ptr<MutationJournal> journal;
    Fixture(){
        char pattern[]="/tmp/fic-sysctl-owner-XXXXXX";root=::mkdtemp(pattern);
        options.enforceOwnership=false;options.directories.clear();
        for(const auto* d:{"etc","run","usr/local/lib","usr/lib","lib"}){
            auto dir=root/d/"sysctl.d";fs::create_directories(dir);options.directories.push_back(dir);
        }
        options.platform.managedConfigPath=root/"etc/sysctl.d/zzzz-fic.conf";
        runtime.root=root/"proc/sys";write(runtime.root/"vm/swappiness","10");write(runtime.root/"vm/test","0");
        journal=std::make_unique<MutationJournal>(root/"journal.json");std::string error;
        require(journal->initializeOrLoad(error),error);
    }
    ~Fixture(){
        AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
        AtomicFileWriter::setPreInstallHookForTests(nullptr);
        AtomicFileWriter::setRemovePreunlinkHookForTests(nullptr);fs::remove_all(root);
    }
    fs::path managed()const{return options.platform.managedConfigPath;}
    SysctlOperationResult apply(const std::string& value){return applySysctlOwned(*journal,first,"vm.swappiness",value,options,runtime);}
    SysctlOperationResult release(MutationId id,const std::function<bool(const std::string&,std::string&)>& callback=[](const auto&,auto&){return true;}){
        std::lock_guard<std::mutex> lock(SysctlConfiguration::mutationMutex());
        return releaseSysctlOwned(*journal,id,options,callback);
    }
};

// Fail an actual journal rename (not the in-memory state) at one protocol boundary.
void testReleaseRecovery(bool legacy,bool last,bool beforePublication,int foreignReplacement) {
    Fixture f;std::string error;
    if(legacy) {
        write(f.managed(),std::string(header)+"vm.swappiness = 10\n");
        MutationRecord old;old.policy=first;old.resource="vm.swappiness";old.undo={MutationBackend::Sysctl,UndoRemoveManagedSetting{"vm.swappiness","10"}};
        MutationId id;require(f.journal->prepareMutation(old,id,error)&&f.journal->setStatus(id,MutationStatus::Applied,error),error);
    } else require(f.apply("10").ok,"recovery setup A");
    if(!last)require(applySysctlOwned(*f.journal,second,"vm.test","1",f.options,f.runtime).ok,"recovery setup B");
    const auto id=f.journal->activeRecords(first).front().id;const auto original=read(f.managed());
    const auto path=f.root/"journal.json",backup=f.root/"journal.blocked";
    bool physical=false,blocked=false;int journalWrites=0,calls=0;
    AtomicFileWriter::setRemovePreunlinkHookForTests([&](const auto&){physical=true;});
    AtomicFileWriter::setPreInstallHookForTests([&](const auto& target){
        if(target==f.managed())physical=true;
        if(target==path){
            ++journalWrites;
            if(!blocked&&((beforePublication&&journalWrites==2)||(!beforePublication&&physical))){
                blocked=true;fs::rename(path,backup);fs::create_directory(path);
            }
        }
    });
    const auto failed=f.release(id,[&](const auto&,auto&){++calls;return true;});
    AtomicFileWriter::setPreInstallHookForTests(nullptr);AtomicFileWriter::setRemovePreunlinkHookForTests(nullptr);
    require(blocked&&!failed.ok&&calls==0,"release fault did not block helper/completion");
    if(beforePublication)require(read(f.managed())==original,"receipt refusal mutated target");
    fs::remove(path);fs::rename(backup,path);
    f.journal=std::make_unique<MutationJournal>(path);require(f.journal->initializeOrLoad(error),error);
    require(f.journal->activeRecords(first).front().status==MutationStatus::Prepared,"pending release lost Prepared provenance");
    require(!f.journal->discard(id,error)&&!f.journal->setStatus(id,MutationStatus::RollbackFailed,error),"generic lifecycle erased release intent");
    const auto journalBefore=read(path);
    require(!applySysctlOwned(*f.journal,first,"vm.swappiness","20",f.options,f.runtime).ok&&read(path)==journalBefore,"apply adopted pending release");
    require(!applySysctlOwned(*f.journal,second,"vm.test","2",f.options,f.runtime).ok&&read(path)==journalBefore,"another SYSCTL apply crossed pending release");
    if(foreignReplacement){
        if(foreignReplacement==1){write(f.managed().string()+".foreign",read(f.managed()));fs::rename(f.managed().string()+".foreign",f.managed());}
        else fs::permissions(f.managed(),fs::perms::owner_read);
        const auto foreign=read(f.managed());
        require(!f.release(id).ok&&read(f.managed())==foreign&&read(path)==journalBefore,"byte-identical foreign inode adopted on release recovery");return;
    }
    auto retry=f.release(id,[&](const auto&,auto&){++calls;return true;});require(retry.ok,"recovery failed: "+retry.message);
    require(calls==1&&f.journal->activeRecords(first).empty(),"helper before terminal release");
    require(f.release(id,[&](const auto&,auto&){++calls;return true;}).ok&&calls==1,"completed release reran helper");
    if(!last){
        const auto other=f.journal->activeRecords(second).front();
        if(legacy){const auto& state=*std::get<UndoRemoveManagedSetting>(other.undo.payload).sysctl;
            require(!state.containerCreated&&state.legacyContainerOrigin==id&&!f.journal->discard(id,error),"legacy delegation lost origin/claimed creation");}
        require(f.release(other.id).ok&&!fs::exists(f.managed()),"surviving owner lost container authority");
    } else require(!fs::exists(f.managed()),"last release did not resolve durable absence");
}

int main(){try{
    {Fixture f;write(f.root/"etc/sysctl.d/10-foreign.conf","invalid foreign content must not be parsed\n");
     require(f.apply("10").ok,"compliant runtime failed ownership enrollment");
     auto id=f.journal->activeRecords(first).front().id;auto doc=read(f.root/"journal.json"),file=read(f.managed());
     struct stat before{},after{};::stat(f.managed().c_str(),&before);
     auto result=f.apply("10");::stat(f.managed().c_str(),&after);
     require(result.ok&&!result.changed&&before.st_ino==after.st_ino&&doc==read(f.root/"journal.json")&&file==read(f.managed()),"no-op rewrote persistent state");
     require(f.apply("20").ok,"REFRESH failed");auto active=f.journal->activeRecords(first);
     require(active.size()==1&&active[0].id==id&&std::get<UndoRemoveManagedSetting>(active[0].undo.payload).appliedValue=="20","REFRESH lost identity");}
    {Fixture f;require(f.apply("10").ok,"setup");auto doc=read(f.root/"journal.json");
     write(f.runtime.root/"vm/swappiness","0");auto result=f.apply("10");
     require(result.ok&&read(f.root/"journal.json")==doc&&read(f.runtime.root/"vm/swappiness")=="10","runtime-only repair changed journal");}
    {Fixture f;require(f.apply("10").ok,"setup");auto id=f.journal->activeRecords(first).front().id;
     AtomicFileWriter::setPreInstallHookForTests([&](const auto& p){if(p==f.managed())write(f.managed(),read(f.managed())+"\n");});
     auto result=f.apply("20");AtomicFileWriter::setPreInstallHookForTests(nullptr);require(!result.ok,"CAS failure accepted");
     auto active=f.journal->activeRecords(first);
     require(active.size()==1&&active[0].id==id&&active[0].status==MutationStatus::Applied&&std::get<UndoRemoveManagedSetting>(active[0].undo.payload).appliedValue=="10","no-effect REFRESH lost predecessor");
     require(f.apply("20").ok,"no-effect retry blocked");}
    {Fixture f;require(f.apply("10").ok,"setup");
     AtomicFileWriter::setDirectoryFsyncHookForTests([&](const auto& p){return p!=f.managed();});
     auto result=f.apply("20");AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);require(!result.ok&&!result.noEffect,"uncertain publication accepted/classified as no-effect");
     auto active=f.journal->activeRecords(first);require(active.size()==1&&active[0].status==MutationStatus::Prepared,"uncertainty lost provenance");
     MutationJournal restarted(f.root/"journal.json");std::string error;require(restarted.initializeOrLoad(error),error);
     require(!applySysctlOwned(restarted,second,"vm.test","1",f.options,f.runtime).ok,"restart adopted Prepared");
     require(!restarted.abortSysctlNoEffect(active[0].id,error),"restart invented a NotInstalled observation");
     require(!f.journal->discard(active[0].id,error),"generic discard erased Prepared");}
    {Fixture f;write(f.root/"run/sysctl.d/zzzzz-late.conf","");auto before=read(f.root/"journal.json");
     require(!f.apply("10").ok&&!fs::exists(f.managed())&&before==read(f.root/"journal.json"),"late unrelated source mutated state");
     fs::remove(f.root/"run/sysctl.d/zzzzz-late.conf");fs::create_symlink("/dev/null",f.root/"etc/sysctl.d/zzzzz-late.conf");
     write(f.root/"usr/lib/sysctl.d/zzzzz-late.conf","invalid masked vendor");require(f.apply("10").ok,"higher priority null mask ignored");}
    {Fixture f;write(f.managed(),header);require(!f.apply("10").ok&&f.journal->records().empty(),"orphan header adopted");}
    {Fixture f;require(f.apply("10").ok,"setup");
     require(applySysctlOwned(*f.journal,second,"vm.test","1",f.options,f.runtime).ok,"sibling apply");
     const auto id=f.journal->activeRecords(first).front().id;bool called=false;
     const auto released=f.release(id,[&](const std::string& key,std::string&){called=true;require(key=="vm.swappiness","wrong key");require(f.journal->activeRecords(first).empty(),"native reapply before terminal journal");return false;});
     require(released.ok&&called&&!released.diagnostics.empty(),"auxiliary failure cancelled release");
     require(read(f.managed()).find("vm.test = 1")!=std::string::npos&&read(f.managed()).find("swappiness")==std::string::npos,"release lost sibling");
     require(read(f.runtime.root/"vm/swappiness")=="10","release changed fake runtime");
     require(f.release(id).ok,"repeat release");require(f.release(f.journal->activeRecords(second).front().id).ok&&!fs::exists(f.managed()),"last creator did not delete container");}
    {Fixture f;require(f.apply("10").ok,"setup");auto id=f.journal->activeRecords(first).front().id;
     AtomicFileWriter::setRemovePreunlinkHookForTests([&](const auto& p){write(p+".replacement",read(p)+"\n");fs::rename(p+".replacement",p);});
     const auto result=f.release(id);AtomicFileWriter::setRemovePreunlinkHookForTests(nullptr);
     require(!result.ok&&f.journal->activeRecords(first).size()==1&&fs::exists(f.managed()),"failed unlink finalized release");
     write(f.managed(),header);auto replacement=read(f.managed());
     require(!f.release(id).ok&&replacement==read(f.managed())&&f.journal->activeRecords(first).size()==1,"retry deleted foreign replacement using stale creation authority");}
    {Fixture f;write(f.managed(),std::string(header)+"vm.swappiness = 10\n");
     MutationRecord old;old.policy=first;old.resource="vm.swappiness";old.undo={MutationBackend::Sysctl,UndoRemoveManagedSetting{"vm.swappiness","10"}};
     MutationId id=0;std::string error;require(f.journal->prepareMutation(old,id,error)&&f.journal->setStatus(id,MutationStatus::Applied,error),error);
     require(applySysctlOwned(*f.journal,second,"vm.test","1",f.options,f.runtime).ok,"legacy sibling admission");
     require(f.release(id).ok,"legacy release");const auto fresh=f.journal->activeRecords(second).front();
     const auto& state=*std::get<UndoRemoveManagedSetting>(fresh.undo.payload).sysctl;
     require(!state.containerCreated&&state.legacyContainerOrigin==id,"legacy permission promoted to creation proof");
     require(!f.journal->discard(id,error),"active legacy delegation lost its origin");
     require(f.release(fresh.id).ok&&!fs::exists(f.managed()),"legacy delegation lost last-container permission");}
    {Fixture f;require(f.apply("10").ok,"setup");const auto id=f.journal->activeRecords(first).front().id;
     auto result=f.release(id,[](const auto&,auto&)->bool{throw std::runtime_error("native launch exception");});
     require(result.ok&&!result.diagnostics.empty()&&f.journal->activeRecords(first).empty(),"auxiliary exception cancelled durable release");}
    {Fixture f;require(f.apply("10").ok,"setup");auto id=f.journal->activeRecords(first).front().id;
     write(f.managed(),read(f.managed())+"# foreign data\n");require(!f.release(id).ok&&fs::exists(f.managed()),"foreign data deleted");}
    {Fixture f;auto doc=read(f.root/"journal.json");
     AtomicFileWriter::setPreInstallHookForTests([&](const auto& p){if(p==f.managed())write(f.managed(),header);});
     require(!f.apply("10").ok,"fresh exclusive-create collision accepted");AtomicFileWriter::setPreInstallHookForTests(nullptr);
     require(f.journal->activeRecords(first).empty(),"known fresh no-effect retained fake ownership");
     require(!f.apply("10").ok,"fresh collision artifact adopted");}
    {Fixture f;require(f.apply("10").ok,"setup");auto id=f.journal->activeRecords(first).front().id;bool called=false;
     bool physical=false;AtomicFileWriter::setRemovePreunlinkHookForTests([&](const auto&){physical=true;});
     AtomicFileWriter::setDirectoryFsyncHookForTests([&](const auto& p){return p!=f.root/"journal.json"||!physical;});
     auto result=f.release(id,[&](const auto&,auto&){called=true;return true;});AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
     require(!result.ok&&!called&&!f.journal->usable()&&f.journal->records().size()==1&&!fs::exists(f.managed()),"release journal uncertainty lost provenance or ran helper");
     require(!f.release(id).ok,"indeterminate in-memory terminal state allowed success before reload");
     AtomicFileWriter::setRemovePreunlinkHookForTests(nullptr);
     f.journal=std::make_unique<MutationJournal>(f.root/"journal.json");std::string error;require(f.journal->initializeOrLoad(error),error);
     require(f.release(id).ok,"durable journal reread did not resolve finalization uncertainty");}
    {Fixture f;require(f.apply("10").ok,"setup");auto id=f.journal->activeRecords(first).front().id;
     write(f.managed(),read(f.managed())+"vm.foreign = 7\n");
     require(f.release(id).ok&&read(f.managed()).find("vm.foreign = 7")!=std::string::npos,"per-key release removed unknown sibling");
     require(!f.apply("10").ok,"orphan sibling adopted after release");}
    {Fixture f;require(f.apply("10").ok,"crash setup A");
     require(applySysctlOwned(*f.journal,second,"vm.test","1",f.options,f.runtime).ok,"crash setup B");
     auto id=f.journal->activeRecords(first).front().id;bool published=false,blocked=false;int calls=0;
     auto path=f.root/"journal.json";auto backup=f.root/"journal.blocked";
     AtomicFileWriter::setPreInstallHookForTests([&](const auto& target){
         if(target==f.managed())published=true;
         if(target==path&&published&&!blocked){blocked=true;fs::rename(path,backup);fs::create_directory(path);}
     });
     auto failed=f.release(id,[&](const auto&,auto&){++calls;return true;});
     AtomicFileWriter::setPreInstallHookForTests(nullptr);
     require(blocked&&!failed.ok&&calls==0,"fault did not interrupt physical release before journal completion");
     fs::remove(path);fs::rename(backup,path);
     f.journal=std::make_unique<MutationJournal>(path);std::string error;require(f.journal->initializeOrLoad(error),error);
     auto retry=f.release(id,[&](const auto&,auto&){++calls;return true;});
     require(retry.ok,"RED crash consistency: restart cannot finish A release: "+retry.message);
     require(calls==1&&f.journal->activeRecords(first).empty(),"release completion/helper ordering");
     require(f.release(f.journal->activeRecords(second).front().id).ok&&!fs::exists(f.managed()),"survivor B retained stale container identity");}
    {Fixture f;require(f.apply("10").ok,"intent failure setup");auto id=f.journal->activeRecords(first).front().id;
     const auto original=read(f.managed());auto path=f.root/"journal.json",backup=f.root/"journal.blocked";int calls=0;
     AtomicFileWriter::setPreInstallHookForTests([&](const auto& target){if(target==path){fs::rename(path,backup);fs::create_directory(path);}});
     auto failed=f.release(id,[&](const auto&,auto&){++calls;return true;});AtomicFileWriter::setPreInstallHookForTests(nullptr);
     require(!failed.ok&&!calls&&read(f.managed())==original&&f.journal->activeRecords(first).front().status==MutationStatus::Applied,"intent persistence failure mutated target/predecessor");
     fs::remove(path);fs::rename(backup,path);require(f.release(id).ok,"intent refusal blocked retry");}
    {Fixture f;require(f.apply("10").ok&&applySysctlOwned(*f.journal,second,"vm.test","1",f.options,f.runtime).ok,"pre-rename setup");
     auto id=f.journal->activeRecords(first).front().id;auto saved=f.root/"original";
     AtomicFileWriter::setPreInstallHookForTests([&](const auto& target){if(target==f.managed()){fs::rename(f.managed(),saved);fs::create_directory(f.managed());}});
     require(!f.release(id).ok,"CAS refusal after prepared receipt accepted");AtomicFileWriter::setPreInstallHookForTests(nullptr);
     fs::remove(f.managed());fs::rename(saved,f.managed());f.journal=std::make_unique<MutationJournal>(f.root/"journal.json");std::string error;
     require(f.journal->initializeOrLoad(error)&&f.release(id).ok,"restart could not resume original state after refused rename: "+error);}
    {Fixture f;require(f.apply("10").ok&&applySysctlOwned(*f.journal,second,"vm.test","1",f.options,f.runtime).ok,"receipt uncertainty setup");
     auto id=f.journal->activeRecords(first).front().id;const auto original=read(f.managed());int writes=0,calls=0;
     AtomicFileWriter::setDirectoryFsyncHookForTests([&](const auto& path){return path!=f.root/"journal.json"||++writes<2;});
     auto failed=f.release(id,[&](const auto&,auto&){++calls;return true;});AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
     require(!failed.ok&&!f.journal->usable()&&read(f.managed())==original&&!calls,"uncertain prepared receipt allowed rename/helper");
     f.journal=std::make_unique<MutationJournal>(f.root/"journal.json");std::string error;require(f.journal->initializeOrLoad(error),error);
     require(f.release(id,[&](const auto&,auto&){++calls;return true;}).ok&&calls==1,"original-state recovery after receipt uncertainty failed");}
    testReleaseRecovery(false,false,false,false);
    testReleaseRecovery(false,false,true,false);
    testReleaseRecovery(false,true,false,false);
    testReleaseRecovery(false,false,false,true);
    testReleaseRecovery(false,false,false,2);
    testReleaseRecovery(true,false,false,false);
    require(sysctlNativePrefix("net/ipv4/conf/eth.10/forwarding")=="/net/ipv4/conf/eth.10/forwarding","literal interface dot lost");
    std::cout<<"PASS: SYSCTL owned apply/refresh, no-effect/uncertain journal, release and legacy authority\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
