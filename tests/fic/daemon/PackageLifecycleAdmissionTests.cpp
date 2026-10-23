#include "daemon/PackageLifecycleAdmission.h"
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
void require(bool ok,const std::string& error){if(!ok)throw std::runtime_error(error);}
std::string read(const fs::path& path){std::ifstream in(path);return {std::istreambuf_iterator<char>(in),{}};}
}
int main() {
    if(::geteuid()!=0)return 77;
    char pattern[]="/run/fic-lifecycle-admission-XXXXXX";const auto* made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made;
    struct Cleanup{fs::path path;~Cleanup(){std::error_code ec;fs::remove_all(path,ec);}} cleanup{root};
    try {
        DaemonInstanceLock guard,empty;std::string error;require(guard.tryAcquire(root/"runtime",error),error);
        const auto file=root/"state.json";PackageLifecycleAdmission admission(file);PackageLifecycleStore store(file);
        require(!admission.requireInstalled(guard,error)&&!fs::exists(file),"missing state adopted/created");
        const std::string id(32,'a');
        require(store.create(guard,{PackageOperation::Install,PackagePhase::Installing,id,"1",0},error),error);
        const auto before=read(file);
        require(!admission.requireInstalled(guard,error)&&read(file)==before,"installing state admitted/changed");
        std::optional<PackageLifecycleState> state;
        const auto advance=[&](PackagePhase next){require(store.inspect(state,error)&&store.advance(guard,*state,next,error),error);};
        advance(PackagePhase::InstalledButFenced);
        require(!admission.requireInstalled(guard,error),"InstalledButFenced admitted");
        advance(PackagePhase::InfrastructureProven);advance(PackagePhase::Installed);
        AtomicFileWriter::setDirectoryFsyncHookForTests([](const std::string&){return false;});
        require(!admission.requireInstalled(guard,error),"visible Installed without durability accepted");
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(admission.requireInstalled(guard,error),error);
        require(!admission.requireInstalled(empty,error),"unguarded admission");
        const auto child=::fork();require(child>=0,"fork");
        if(child==0)::_exit(admission.requireInstalled(guard,error)?2:0);
        int status=0;require(::waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"inherited admission accepted");
        require(store.inspect(state,error)&&store.begin(guard,*state,{PackageOperation::Remove,PackagePhase::Fencing,std::string(32,'b'),"1",0},error),error);
        for(const auto phase:{PackagePhase::Quiescent,PackagePhase::DmReleased,PackagePhase::DeReleased,
            PackagePhase::ProviderReleased,PackagePhase::PasswordReleased,PackagePhase::HooksDetached,
            PackagePhase::ReleaseComplete,PackagePhase::RemovedTombstone}) {
            advance(phase);const auto pending=read(file);
            require(!admission.requireInstalled(guard,error)&&read(file)==pending,"release/tombstone admitted or changed");
        }
        {std::ofstream corrupt(file);corrupt<<"{}\n";}
        require(!admission.requireInstalled(guard,error)&&read(file)=="{}\n","corrupt state repaired/admitted");
        fs::remove(file);fs::create_symlink(root/"other",file);
        require(!admission.requireInstalled(guard,error)&&fs::is_symlink(file),"symlink state adopted");
        std::cout<<"PASS: finalized Installed only; missing/corrupt/pending/tombstone/inherited admission fail closed without mutation\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
