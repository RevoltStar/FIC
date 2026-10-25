#include "daemon/UninstallLifecycle.h"
#include "daemon/PackageLifecycleAdmission.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
namespace fs=std::filesystem;
using namespace fic::daemon;
using fic::core::PackageState;
namespace {
void require(bool ok,const std::string& message){if(!ok)throw std::runtime_error(message);}
std::string read(const fs::path& file){std::ifstream in(file);return {std::istreambuf_iterator<char>(in),{}};}
void write(const fs::path& file,const std::string& text){std::ofstream(file)<<text;::chmod(file.c_str(),0600);}
}
int main(){
    if(::geteuid()!=0)return 77;
    char pattern[]="/run/fic-uninstall-state-XXXXXX";
    const auto* made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made,file=root/"status";
    struct Cleanup{fs::path root;~Cleanup(){std::error_code ec;fs::remove_all(root,ec);}} cleanup{root};
    try {
        std::string error;DaemonInstanceLock guard,empty;
        require(guard.tryAcquire(root/"runtime",error),error);
        PackageLifecycleAdmission admission(file);UninstallLifecycle lifecycle(file);
        require(!admission.requireInstalled(guard,error)&&!fs::exists(file),"missing state adopted");
        require(!lifecycle.prepare(guard,error)&&!fs::exists(file),"missing state prepared");
        for(const auto* invalid:{"", "INSTALLED", "INSTALLED\nextra", "UNKNOWN\n", "{}\n", "INSTALLED\r\n"}) {
            write(file,invalid);require(!admission.requireInstalled(guard,error),"invalid state admitted");
            require(!lifecycle.prepare(guard,error)&&read(file)==invalid,"invalid state repaired");
        }
        for(auto state:{PackageState::Installing,PackageState::Removed}) {
            const auto text=std::string(fic::core::packageStateName(state))+"\n";write(file,text);
            require(!lifecycle.prepare(guard,error)&&read(file)==text,"illegal uninstall transition");
        }
        write(file,"INSTALLED\n");
        require(admission.requireInstalled(guard,error),error);
        require(!lifecycle.prepare(empty,error)&&read(file)=="INSTALLED\n","unguarded prepare");
        ::chmod(file.c_str(),0640);require(!lifecycle.prepare(guard,error),"unsafe permissions accepted");
        ::chmod(file.c_str(),0600);fs::create_hard_link(file,root/"alias");
        require(!lifecycle.prepare(guard,error),"hard link accepted");fs::remove(root/"alias");
        fs::rename(file,root/"real");fs::create_symlink(root/"real",file);
        require(!lifecycle.prepare(guard,error),"symlink accepted");fs::remove(file);fs::rename(root/"real",file);
        ::chown(file.c_str(),1,1);require(!lifecycle.prepare(guard,error),"foreign owner accepted");::chown(file.c_str(),0,0);
        ::chmod(root.c_str(),0755);require(!lifecycle.prepare(guard,error),"unsafe parent accepted");::chmod(root.c_str(),0700);
        AtomicFileWriter::setDirectoryFsyncHookForTests([](const std::string&){return false;});
        require(!lifecycle.prepare(guard,error),"failed durability reported success");
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(fic::core::readPackageState(file).state==PackageState::Uninstalling,"visible transition lost");
        require(lifecycle.prepare(guard,error),error);
        require(!admission.requireInstalled(guard,error),"uninstall admitted as normal");
        // Restart-equivalent: a fresh reader must retain the gate independently
        // of process memory. A fork cannot inherit singleton authority.
        auto child=::fork();require(child>=0,"fork failed");
        if(child==0)::_exit(fic::core::readPackageState(file).state==PackageState::Uninstalling &&
            !lifecycle.prepare(guard,error)?0:1);
        int status=0;require(::waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"inherited authority/restart state");
        for(const auto* blocked:{"apply_all","apply_policy","enable_policy","disable_policy","set_policy_value",
            "incident_raise","incident_clear","incident_device_missing","calc_hash","future_mutation"})
            require(!UninstallLifecycle::allowedRequest(blocked),"mutation allowlisted");
        for(const auto* allowed:{"status","module_list","policy_value","prepare_uninstall","rollback_all","shutdown"})
            require(UninstallLifecycle::allowedRequest(allowed),"uninstall/read command blocked");
        std::cout<<"PASS: strict state, durability failure/retry, restart, authority and default-deny command gate\n";
    }catch(const std::exception& e){AtomicFileWriter::setDirectoryFsyncHookForTests({});std::cerr<<e.what()<<'\n';return 1;}
}
