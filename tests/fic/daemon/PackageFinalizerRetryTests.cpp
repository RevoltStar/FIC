#include "daemon/PackageLifecycleState.h"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
using namespace fic::daemon;
void require(bool yes,const std::string& message) {if(!yes)throw std::runtime_error(message);}
int main() {
    if(::geteuid()!=0)return 77;
    std::string pattern="/run/fic-retry-test-XXXXXX";
    char* created=::mkdtemp(pattern.data());if(!created)return 1;
    const std::filesystem::path root=created;
    struct Cleanup {std::filesystem::path root;~Cleanup(){std::error_code e;std::filesystem::remove_all(root,e);}} cleanup{root};
    try {
        require(FINALIZER_RETRY_INTERVAL_MS==60000 && FINALIZER_ATTEMPT_TIMEOUT.count()==30000 &&
            FINALIZER_COMMAND_TIMEOUT.count()==5000 && FINALIZER_OUTPUT_LIMIT==1024*1024,"documented budgets changed");
        DaemonInstanceLock guard,empty;std::string error;
        require(guard.tryAcquire(root/"runtime",error),error);
        PackageLifecycleStore store(root/"state");
        const std::string boot="12345678-1234-1234-1234-123456789abc";
        const std::string nextBoot="87654321-1234-1234-1234-123456789abc";
        PackageLifecycleState state{PackageOperation::Install,PackagePhase::Installing,std::string(32,'a'),"version",0,std::string(32,'a')};
        require(store.create(guard,state,error),error);
        const auto refresh=[&] {
            std::optional<PackageLifecycleState> current;
            require(store.inspect(current,error)&&current.has_value(),error);state=*current;
        };
        require(store.admitFinalizerAttempt(guard,state,boot,0,error)==FinalizerAdmission::WaitingForConfiguration,"configuring proof admitted");
        require(!store.advance(guard,state,PackagePhase::InfrastructureProven,error),"install skipped pending package state");
        require(store.advance(guard,state,PackagePhase::InstalledButFenced,error),error);refresh();
        require(store.admitFinalizerAttempt(empty,state,boot,0,error)==FinalizerAdmission::Invalid,"admission without guard");
        require(store.admitFinalizerAttempt(guard,state,"invalid",0,error)==FinalizerAdmission::Invalid,"unknown boot ID accepted");
        for(std::uint64_t i=1;i<=128;++i) {
            // Many attempts exceed any old total budget. Time is deterministic,
            // injected by the internal caller, no sleep/wall-clock dependency.
            auto prior=state;
            const auto now=i*FINALIZER_RETRY_INTERVAL_MS;
            require(store.admitFinalizerAttempt(guard,state,boot,now,error)==FinalizerAdmission::Admitted,error);refresh();
            require(store.admitFinalizerAttempt(guard,prior,boot,now,error)==FinalizerAdmission::Invalid,"stale CAS replay");
            PackageLifecycleStore restarted(root/"state");
            require(restarted.admitFinalizerAttempt(guard,state,boot,now+59999,error)==FinalizerAdmission::Cooldown,"restart bypassed durable cooldown");
            require(store.recordFinalizerFailure(guard,state, i%2 ? FinalizerFailure::PackageBusy : FinalizerFailure::ProofTimeout,error),error);refresh();
        }
        require(store.admitFinalizerAttempt(guard,state,boot,state.lastAttemptMs-1,error)==FinalizerAdmission::Invalid,"clock rollback bypass");
        // New boot permits one attempt; startup helper still must obtain guard.
        require(store.admitFinalizerAttempt(guard,state,nextBoot,1,error)==FinalizerAdmission::Admitted,error);refresh();
        require(store.recordFinalizerFailure(guard,state,FinalizerFailure::InvalidJournal,error),error);refresh();
        require(store.admitFinalizerAttempt(guard,state,nextBoot,99999999,error)==FinalizerAdmission::Blocked,"structural error automatically retried");
        require(store.admitFinalizerAttempt(guard,state,boot,99999999,error)==FinalizerAdmission::Blocked,"new boot cleared structural block");
        require(!store.recordFinalizerFailure(guard,state,FinalizerFailure::PackageBusy,error),"temporary result erased structural diagnosis");
        require(!store.advance(guard,state,PackagePhase::InfrastructureProven,error),"blocked operation finalized");
        for(auto failure:{FinalizerFailure::PackageBusy,FinalizerFailure::PackageIncomplete,
            FinalizerFailure::ProofUnavailable,FinalizerFailure::ProofTimeout})
            require(!structuralFinalizerFailure(failure),"temporary fault became structural");
        for(auto failure:{FinalizerFailure::InvalidJournal,FinalizerFailure::ManifestConflict,
            FinalizerFailure::UnprovableOwnership})
            require(structuralFinalizerFailure(failure),"structural fault became temporary");
        std::cout<<"PASS: 128 durable temporary retries, cooldown, stale CAS, reboot, structural block\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
