#include "daemon/PackageLifecycleState.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <csignal>
using namespace fic::daemon;
void require(bool value,const std::string& error) {if(!value)throw std::runtime_error(error);}
int main() {
    if(::geteuid()!=0)return 77;
    std::string name="/run/fic-lifecycle-test-XXXXXX";
    char* created=::mkdtemp(name.data());if(!created)return 1;
    std::filesystem::path root=created;
    struct Cleanup {std::filesystem::path root;~Cleanup(){std::error_code e;std::filesystem::remove_all(root,e);}} cleanup{root};
    try {
        DaemonInstanceLock guard,empty;std::string error;
        require(guard.tryAcquire(root/"runtime",error),error);
        PackageLifecycleStore store(root/"state");std::optional<PackageLifecycleState> state;
        require(store.inspect(state,error)&&!state,"virgin inspection");
        PackageLifecycleState initial{PackageOperation::Remove,PackagePhase::Fencing,std::string(32,'a'),"test-version",0,std::string(32,'a')};
        require(!store.create(empty,initial,error),"unadmitted create");
        auto noMask=initial;noMask.maskOperationId.clear();
        require(!store.create(guard,noMask,error),"implicit mask identity fallback");
        noMask.maskOperationId=std::string(32,'c');
        require(!store.create(guard,noMask,error),"initial foreign mask identity");
        require(store.create(guard,initial,error),error);
        require(!store.create(guard,initial,error),"exclusive create replaced existing fence");
        require(store.inspect(state,error)&&state&&state->generation==0,"read durable fence");
        require(!store.advance(guard,*state,PackagePhase::Installed,error),"release bypass");
        require(store.advance(guard,*state,PackagePhase::Quiescent,error),error);
        require(!store.advance(guard,*state,PackagePhase::Quiescent,error),"stale replay");
        require(store.inspect(state,error)&&state->generation==1,"generation");
        for(auto phase:{PackagePhase::DmReleased,PackagePhase::DeReleased,PackagePhase::ProviderReleased,
                       PackagePhase::PasswordReleased,PackagePhase::HooksDetached,PackagePhase::ReleaseComplete}) {
            auto prior=*state;require(store.advance(guard,prior,phase,error),error);
            require(store.inspect(state,error)&&state->phase==phase,"phase persistence");
            PackageLifecycleStore restarted(root/"state");std::optional<PackageLifecycleState> observed;
            require(restarted.inspect(observed,error)&&observed&&observed->generation==state->generation,"restart retained state");
        }
        require(!store.advance(guard,*state,PackagePhase::Installed,error),"tombstone cleared without recovery");
        const std::string boot="12345678-1234-1234-1234-123456789abc";
        require(store.admitFinalizerAttempt(guard,*state,boot,1,error)==FinalizerAdmission::Admitted,"release completion falsely treated as removed proof");
        require(store.inspect(state,error),error);
        require(store.advance(guard,*state,PackagePhase::RemovedTombstone,error),error);
        require(store.inspect(state,error)&&state->phase==PackagePhase::RemovedTombstone,"post-transaction tombstone persistence");
        require(store.admitFinalizerAttempt(guard,*state,boot,100000,error)==FinalizerAdmission::Terminal,"final tombstone retried");
        auto removed=*state;
        PackageLifecycleState recovery{PackageOperation::Recover,PackagePhase::Recovering,std::string(32,'b'),"next-version",0,std::string(32,'a')};
        auto invalid=recovery; invalid.operation=PackageOperation::Install;
        require(!store.begin(guard,removed,invalid,error),"incompatible operation/phase");
        invalid=recovery; invalid.operationId=removed.operationId;
        require(!store.begin(guard,removed,invalid,error),"operation identity reuse");
        require(!store.begin(empty,removed,recovery,error),"unadmitted recovery");
        auto lostMasks=recovery;lostMasks.maskOperationId=lostMasks.operationId;
        require(!store.begin(guard,removed,lostMasks,error),"recovery discarded retained masks");
        require(store.begin(guard,removed,recovery,error),error);
        require(!store.begin(guard,removed,recovery,error),"stale recovery replay");
        require(store.inspect(state,error)&&state->phase==PackagePhase::Recovering&&state->maskOperationId==removed.maskOperationId&&state->operationId!=removed.operationId,"recovery lost retained mask provenance");
        require(!store.advance(guard,*state,PackagePhase::Installed,error),"recovery bypassed package proof");
        require(!store.advance(guard,*state,PackagePhase::InfrastructureProven,error),"recovery skipped InstalledButFenced");
        require(store.advance(guard,*state,PackagePhase::InstalledButFenced,error),error);
        require(store.inspect(state,error)&&state->phase==PackagePhase::InstalledButFenced,"pending package proof durable");
        require(!store.advance(guard,*state,PackagePhase::Installed,error),"half configured treated as installed");
        require(store.advance(guard,*state,PackagePhase::InfrastructureProven,error),error);
        require(store.inspect(state,error),error);
        require(store.advance(guard,*state,PackagePhase::Installed,error),error);
        require(store.inspect(state,error),error);
        PackageLifecycleState upgrading{PackageOperation::Upgrade,PackagePhase::Fencing,std::string(32,'d'),"next-version",0,std::string(32,'d')};
        require(store.begin(guard,*state,upgrading,error),error);
        require(store.inspect(state,error),error);
        require(store.advance(guard,*state,PackagePhase::Quiescent,error),error);
        require(store.inspect(state,error),error);
        require(!store.advance(guard,*state,PackagePhase::DmReleased,error),"upgrade entered destructive release chain");
        require(!store.advance(guard,*state,PackagePhase::ReleaseComplete,error),"upgrade claimed removal release");
        require(store.advance(guard,*state,PackagePhase::Recovering,error),error);
        require(store.inspect(state,error),error);
        for(const auto phase:{PackagePhase::InstalledButFenced,PackagePhase::InfrastructureProven,PackagePhase::Installed}) {
            require(store.advance(guard,*state,phase,error),error);require(store.inspect(state,error),error);
        }
        PackageLifecycleState removing{PackageOperation::Remove,PackagePhase::Fencing,std::string(32,'c'),"next-version",0,std::string(32,'c')};
        require(store.begin(guard,*state,removing,error),error);
        const auto child=::fork(); require(child>=0,"fork");
        if(child==0) {
            std::optional<PackageLifecycleState> observed;
            if(!store.inspect(observed,error)) ::_exit(2);
            ::_exit(store.advance(guard,*observed,PackagePhase::Quiescent,error) ? 3 : 0);
        }
        int status=0;require(::waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"fork inherited authority");
        std::ifstream validInput(root/"state");
        const std::string validBytes((std::istreambuf_iterator<char>(validInput)),{});
        auto oldSchema=validBytes;
        const auto schemaAt=oldSchema.find("\"version\":2");require(schemaAt!=std::string::npos,"schema fixture");
        oldSchema.replace(schemaAt,11,"\"version\":1");
        {std::ofstream old(root/"state");old<<oldSchema;}
        require(!store.inspect(state,error),"obsolete development schema adopted");
        auto duplicate=validBytes; duplicate.insert(1,"\"version\":2,");
        {std::ofstream invalidJson(root/"state");invalidJson<<duplicate;}
        require(!store.inspect(state,error),"duplicate lifecycle key accepted");
        auto floating=validBytes;
        const auto versionAt=floating.find("\"version\":2");
        require(versionAt!=std::string::npos,"version fixture");
        floating.replace(versionAt,11,"\"version\":2.0");
        {std::ofstream invalidJson(root/"state");invalidJson<<floating;}
        require(!store.inspect(state,error),"floating schema version accepted");
        {std::ofstream oversized(root/"state");oversized<<std::string(5000,'x');}
        require(!store.inspect(state,error),"unbounded state accepted");
        {std::ofstream corrupt(root/"state");corrupt<<"broken";}
        require(!store.inspect(state,error),"corrupt fence accepted");
        std::ifstream in(root/"state");std::string bytes;in>>bytes;require(bytes=="broken","inspection repaired corruption");
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
