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
     AtomicFileWriter::setDirectoryFsyncHookForTests([&](const auto& p){return p!=f.root/"journal.json";});
     auto result=f.release(id,[&](const auto&,auto&){called=true;return true;});AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
     require(!result.ok&&!called&&!f.journal->usable()&&f.journal->records().size()==1&&!fs::exists(f.managed()),"release journal uncertainty lost provenance or ran helper");}
    {Fixture f;require(f.apply("10").ok,"setup");auto id=f.journal->activeRecords(first).front().id;
     write(f.managed(),read(f.managed())+"vm.foreign = 7\n");
     require(f.release(id).ok&&read(f.managed()).find("vm.foreign = 7")!=std::string::npos,"per-key release removed unknown sibling");
     require(!f.apply("10").ok,"orphan sibling adopted after release");}
    require(sysctlNativePrefix("net/ipv4/conf/eth.10/forwarding")=="/net/ipv4/conf/eth.10/forwarding","literal interface dot lost");
    std::cout<<"PASS: SYSCTL owned apply/refresh, no-effect/uncertain journal, release and legacy authority\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
