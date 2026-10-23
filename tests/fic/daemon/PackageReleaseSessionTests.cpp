#include "daemon/PackageReleaseSession.h"
#include "daemon/PackagePamHooks.h"
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace fic::daemon;
namespace fs=std::filesystem;
namespace {
bool quiescent=true,hookFailure=false,hookCrash=false,hookProof=true,resourceProof=true;int crashDomain=-1;int failedDomain=-1;std::vector<int> releaseOrder;std::filesystem::path lockDirectory;
void require(bool yes,const std::string& error){if(!yes)throw std::runtime_error(error);}
std::string bytes(const fs::path& path){std::ifstream in(path);return std::string(std::istreambuf_iterator<char>(in),{});}
}
// Link-time fixed-domain doubles, ONLY in this test executable. No production
// arbitrary executor/callback/force API is added. Real domain backends have
// their own physical rollback/native gates; here faults exercise orchestration.
namespace fic::daemon {
bool PackagePamHooks::detach(const DaemonInstanceLock& guard,std::chrono::steady_clock::time_point,std::string& error) const {
    require(guard.heldByCurrentProcess(),"hook detach lost admission");
    if(hookCrash)::kill(::getpid(),SIGKILL);
    if(hookFailure){error="injected partial hook detach failure";return false;}
    return true;
}
bool PackagePamHooks::proveDetached(std::string& error) const {
    if(!hookProof){error="injected hook proof failure";return false;}return true;
}
bool PackageReleaseResources::proveReleased(PackageReleaseDomain,fic::rollback::MutationJournal& journal,std::string& error) const {
    if(!resourceProof){error="injected resource proof failure";return false;}
    for(const auto& record:journal.records())if(record.isActive()){error="retained active ownership";return false;}
    return true;
}
bool PackageReleaseResources::supports(PackageReleaseDomain,std::string& error) const {error.clear();return true;}
bool PackageReleaseResources::preflight(PackageReleaseDomain,fic::rollback::MutationJournal& journal,
    PackageResourceReleaseReport&,std::string& error) const {error.clear();return journal.usable();}
bool PackageReleaseResources::release(const DaemonInstanceLock& guard,PackageReleaseDomain domain,
    fic::rollback::MutationJournal& journal,PackageResourceReleaseReport&,std::string& error) const {
    require(guard.heldByCurrentProcess()&&journal.lifecycleInitialized(),"release lost admitted operational journal");
    // Prove the same guard remains held during EACH domain, not merely between
    // calls in an external shell sequence.
    const auto contender=::fork();require(contender>=0,"fork contender");
    if(contender==0){DaemonInstanceLock other;::_exit(other.tryAcquire(lockDirectory,error)?2:0);}
    int status=0;require(::waitpid(contender,&status,0)==contender&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"package lock gap");
    const auto index=static_cast<int>(domain);releaseOrder.push_back(index);
    if(index==failedDomain){error="injected topology release failure";return false;}
    const auto key="vm.fixture_"+std::to_string(index);
    bool existing=false;
    for(const auto& record:journal.records())if(record.resource==key){existing=true;require(record.status==fic::rollback::MutationStatus::RolledBack,"cross-domain compensation");}
    if(!existing) {
        fic::rollback::MutationRecord record;record.policy={"SYSCTL","Global","kernel_test_policy"};record.resource=key;
        record.undo={fic::rollback::MutationBackend::Sysctl,fic::rollback::UndoRemoveManagedSetting{key,"10"}};
        fic::rollback::MutationId id;
        require(journal.prepareMutation(record,id,error)&&journal.setStatus(id,fic::rollback::MutationStatus::Applied,error)&&
            journal.setStatus(id,fic::rollback::MutationStatus::RolledBack,error),error);
    }
    if(crashDomain==index)::kill(::getpid(),SIGKILL);
    return true;
}
bool PackageWritersQuiescence::stopAndProve(const DaemonInstanceLock& guard,const PackageUnitMasks& masks,
    const std::string& id,const std::vector<LegacyWriterImage>&,std::chrono::steady_clock::time_point,std::string& error) const {
    require(guard.heldByCurrentProcess(),"quiescence lacks admission");
    if(!quiescent){error="injected unresolved writer";return false;}
    return masks.provePublished(id,error);
}
}
int main() {
    if(::geteuid()!=0)return 77;
    ::alarm(30);std::string pattern="/run/fic-session-test-XXXXXX";char* made=::mkdtemp(pattern.data());if(!made)return 1;
    const fs::path root=made;
    struct Cleanup {fs::path root;~Cleanup(){std::error_code e;fs::remove_all(root,e);}} cleanup{root};
    try {
        const std::string id(32,'a');auto platform=fic::platform::makeBuildPlatformProfile();
        for(const bool alt:{false,true}) {
        if(alt)platform.id="alt-p11";
        for(int crash=-1;crash<(alt?6:4);++crash) {
            const auto dir=root/((alt?"alt-":"deb-")+std::to_string(crash+1));fs::create_directory(dir);
            auto paths=fic::core::FicProductPaths::production();paths.mutationJournalFile=dir/"journal";
            paths.runtimeDir=dir/"runtime";paths.lockDebugLogFile=dir/"locks.log";lockDirectory=paths.runtimeDir;
            PackageReleaseSessionPaths lifecycle{dir/"fence",dir/"operations",dir/"units"};
            fs::create_directory(lifecycle.maskDirectory);::chmod(lifecycle.maskDirectory.c_str(),0700);fs::create_directory(lifecycle.systemUnitDirectory);
            PackageReleaseSession session(platform,paths,lifecycle);std::string error;
            PackageLifecycleStore store(lifecycle.fenceFile);std::optional<PackageLifecycleState> state;
            {
                DaemonInstanceLock guard,empty;require(guard.tryAcquire(paths.runtimeDir,error),error);
                require(!session.preflight(error)&&!fs::exists(paths.mutationJournalFile),"virgin preflight initialized journal");
                require(store.create(guard,{PackageOperation::Remove,PackagePhase::Fencing,id,"1",0,id},error),error);
                PackageUnitMasks masks(lifecycle.maskDirectory,lifecycle.systemUnitDirectory);
                require(masks.prepare(guard,id,error)&&writeLegacyWriterInventory(guard,lifecycle.maskDirectory/id/"writers.json",id,{},error)&&
                    masks.publish(guard,id,error),error);
                require(!session.releaseManagedResources(empty,id,error),"unguarded release");
                quiescent=false;require(!session.releaseManagedResources(guard,id,error)&&!fs::exists(paths.mutationJournalFile),"writer proof failed after journal mutation");
                require(store.inspect(state,error)&&state->phase==PackagePhase::Fencing,"failed quiescence advanced lifecycle");quiescent=true;
                fic::rollback::MutationJournal initial(paths.mutationJournalFile);require(initial.initializeOrLoad(error),error);
                const auto before=bytes(paths.mutationJournalFile);
                require(session.preflight(error)&&bytes(paths.mutationJournalFile)==before,"preflight changed journal");
                require(!session.releaseManagedResources(guard,std::string(32,'b'),error),"release admitted a different operation");
            }
            if(alt) {
                for(const auto failure:{4,5}) {
                    DaemonInstanceLock guard;require(guard.tryAcquire(paths.runtimeDir,error),error);
                    releaseOrder.clear();failedDomain=failure;
                    require(!session.releaseManagedResources(guard,id,error),"topology failure accepted");
                    require(releaseOrder==std::vector<int>(failure==4?std::initializer_list<int>{4}:std::initializer_list<int>{4,5}),
                            "topology failure reached later resource domain");
                    require(store.inspect(state,error)&&state->phase==PackagePhase::Quiescent,"topology failure advanced resource phase");
                }
                failedDomain=-1;
            }
            crashDomain=crash;
            if(crash>=-1) {
                const auto child=::fork();require(child>=0,"fork release");
                if(child==0){DaemonInstanceLock guard;if(!guard.tryAcquire(paths.runtimeDir,error))::_exit(2);
                    if(crash==-1){hookCrash=true;(void)session.completeRelease(guard,id,error);}
                    else (void)session.releaseManagedResources(guard,id,error);::_exit(3);}
                int status=0;require(::waitpid(child,&status,0)==child&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL,"release crash barrier");
                require(store.inspect(state,error),error);
                const PackagePhase expected[]={PackagePhase::Quiescent,PackagePhase::DmReleased,PackagePhase::DeReleased,PackagePhase::ProviderReleased};
                require(state->phase==(crash==-1?PackagePhase::PasswordReleased:crash>=4?PackagePhase::Quiescent:expected[crash]),"crash advanced/lost last durable phase");
            }
            crashDomain=-1;DaemonInstanceLock restarted;require(restarted.tryAcquire(paths.runtimeDir,error),error);
            releaseOrder.clear();
            require(session.releaseManagedResources(restarted,id,error),error);
            require(releaseOrder==(alt?std::vector<int>{4,5,0,1,2,3}:std::vector<int>{0,1,2,3}),"platform release ordering changed");
            require(store.inspect(state,error)&&state->phase==PackagePhase::PasswordReleased,"resources completion cleared/overadvanced fence");
            fic::rollback::MutationJournal verified(paths.mutationJournalFile);require(verified.validatePersistentStateReadOnly(error)&&verified.records().size()==(alt?6u:4u),error);
            for(const auto& record:verified.records())require(record.status==fic::rollback::MutationStatus::RolledBack,"completed domain compensated/reconstructed");
            require(session.releaseManagedResources(restarted,id,error),"resource replay failed");
            hookFailure=true;
            require(!session.completeRelease(restarted,id,error),"failed hook detach completed release");
            require(store.inspect(state,error)&&state->phase==PackagePhase::PasswordReleased,"partial hook detach lost durable phase");
            hookFailure=false;hookProof=false;
            require(!session.completeRelease(restarted,id,error),"missing final hook proof completed release");
            require(store.inspect(state,error)&&state->phase==PackagePhase::HooksDetached,"hook proof failure advanced completion");
            hookProof=true;resourceProof=false;
            require(!session.completeRelease(restarted,id,error),"missing final resource proof completed release");
            resourceProof=true;releaseOrder.clear();
            require(session.completeRelease(restarted,id,error),error);
            require(releaseOrder.empty(),"post-detach replay mutated resource domains");
            require(store.inspect(state,error)&&state->phase==PackagePhase::ReleaseComplete,"release completion cleared fence or proved removal");
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& path){return path!=lifecycle.fenceFile.string();});
            require(!session.completeRelease(restarted,id,error),"visible ReleaseComplete without durability accepted");
            AtomicFileWriter::setDirectoryFsyncHookForTests({});
            require(session.completeRelease(restarted,id,error),"repeat complete release failed");
            const auto provenJournal=bytes(paths.mutationJournalFile),provenFence=bytes(lifecycle.fenceFile);
            releaseOrder.clear();hookFailure=true;failedDomain=0;
            require(session.proveReleased(restarted,error),error);
            DaemonInstanceLock absent;
            require(!session.proveReleased(absent,error),"unadmitted deferred proof accepted");
            resourceProof=false;
            require(!session.proveReleased(restarted,error),"deferred proof ignored resource drift");
            resourceProof=true;hookProof=false;
            require(!session.proveReleased(restarted,error),"deferred proof ignored physical hook drift");
            hookProof=true;hookFailure=false;failedDomain=-1;
            require(releaseOrder.empty()&&bytes(paths.mutationJournalFile)==provenJournal&&bytes(lifecycle.fenceFile)==provenFence,
                "read-only deferred proof performed release/journal/fence mutation");
            require(store.inspect(state,error),error);
            require(store.begin(restarted,*state,{PackageOperation::Recover,PackagePhase::Recovering,std::string(32,'c'),"1",0,id},error),error);
            require(!session.releaseManagedResources(restarted,std::string(32,'c'),error),"resource release admitted recovery operation");
        }
        }
        std::cout<<"PASS: one admission across fixed domains; preflight/quiescence before journal; DEB/ALT SIGKILL/retry and topology failure boundaries; fence remains active\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
