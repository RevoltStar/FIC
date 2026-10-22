#include "daemon/PackageLifecycleState.h"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
using namespace fic::daemon;
void require(bool yes,const std::string& message) {if(!yes)throw std::runtime_error(message);}
int main() {
    if(::geteuid()!=0)return 77;
    ::alarm(25);
    std::string pattern="/run/fic-lifecycle-crash-XXXXXX";
    char* created=::mkdtemp(pattern.data());if(!created)return 1;
    const std::filesystem::path root=created;
    struct Cleanup {std::filesystem::path root;~Cleanup(){std::error_code e;std::filesystem::remove_all(root,e);}} cleanup{root};
    try {
        unsigned fixture=0;
        for(const auto& phases: {std::vector<PackagePhase>{PackagePhase::Fencing,PackagePhase::Quiescent,
                PackagePhase::DmReleased,PackagePhase::DeReleased,PackagePhase::ProviderReleased,
                PackagePhase::PasswordReleased,PackagePhase::HooksDetached,PackagePhase::ReleaseComplete,PackagePhase::RemovedTombstone},
            std::vector<PackagePhase>{PackagePhase::Installing,PackagePhase::InstalledButFenced,
                PackagePhase::InfrastructureProven,PackagePhase::Installed}}) {
            for(std::size_t stop=0;stop<phases.size();++stop) {
                auto dir=root/std::to_string(++fixture);std::filesystem::create_directory(dir);
                int pipe[2];require(::pipe(pipe)==0,"pipe");
                const auto child=::fork();require(child>=0,"fork");
                if(child==0) {
                    ::close(pipe[0]);
                    try {
                        DaemonInstanceLock guard;std::string error;
                        if(!guard.tryAcquire(dir/"runtime",error))::_exit(2);
                        PackageLifecycleStore store(dir/"state");
                        PackageLifecycleState state{phases[0]==PackagePhase::Fencing ?
                            PackageOperation::Remove : PackageOperation::Install,
                            phases[0],std::string(32,'a'),"version",0};
                        if(!store.create(guard,state,error))::_exit(3);
                        for(std::size_t i=1;i<=stop;++i) {
                            if(!store.advance(guard,state,phases[i],error))::_exit(4);
                            std::optional<PackageLifecycleState> next;
                            if(!store.inspect(next,error)||!next)::_exit(5);
                            state=*next;
                        }
                        const char ready='R';if(::write(pipe[1],&ready,1)!=1)::_exit(6);
                        while(true)::pause();
                    }catch(...) {::_exit(7);}
                }
                struct ReapChild {pid_t pid;~ReapChild(){if(pid>0){::kill(pid,SIGKILL);::waitpid(pid,nullptr,0);}}} reap{child};
                ::close(pipe[1]);char ready=0;
                require(::read(pipe[0],&ready,1)==1&&ready=='R',"durable phase barrier");::close(pipe[0]);
                DaemonInstanceLock restarted;std::string error;
                require(!restarted.tryAcquire(dir/"runtime",error),"concurrent process admitted");
                require(::kill(child,SIGKILL)==0,"kill");int status=0;
                require(::waitpid(child,&status,0)==child&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL,"crash");
                reap.pid=-1;
                require(restarted.tryAcquire(dir/"runtime",error),error);
                PackageLifecycleStore store(dir/"state");std::optional<PackageLifecycleState> recovered;
                require(store.inspect(recovered,error)&&recovered&&recovered->phase==phases[stop]&&
                    recovered->generation==stop,"crash lost or advanced durable phase");
            }
        }
        std::cout<<"PASS: SIGKILL at 13 durable phases; no concurrent admission; exact state on restart\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
