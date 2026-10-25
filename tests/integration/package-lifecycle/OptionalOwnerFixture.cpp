// Test-only: seed a valid unresolved journal through its production API.
// No apply, rollback, record retirement or provider installation is implemented.
#include "rollback/MutationJournal.h"
#include "daemon/DaemonInstanceLock.h"
#include "modules/dac/sudo/SudoersDisabledWrapper.h"
#include <fic/core/runtime/PackageState.h>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
int main(int argc,char** argv){
    using namespace fic::rollback;
    const char* flag=std::getenv("FIC_PACKAGE_LIFECYCLE_NATIVE");
    const char* hostNamespace=std::getenv("FIC_HOST_MNT_INODE");
    struct stat mountNamespace{};
    std::ifstream comm("/proc/1/comm");std::string init;std::getline(comm,init);
    if(!flag||std::string(flag)!="1"||!hostNamespace||::stat("/proc/self/ns/mnt",&mountNamespace)||
       std::to_string(mountNamespace.st_ino)==hostNamespace||geteuid()!=0||init!="systemd"||
       fic::core::readPackageState().state!=fic::core::PackageState::Uninstalling)return 77;
    std::string error;fic::daemon::DaemonInstanceLock lock;
    if(!lock.tryAcquire("/run/fic",error)){std::cerr<<error;return 1;}
    MutationJournal journal("/opt/fic/db/mutation-journal.json");
    if(!journal.initializeOrLoad(error)){std::cerr<<error;return 1;}
    for(const auto& r:journal.records())if(r.isActive())return 2;
    const auto seed=[&](const PolicyRef& policy,const std::string& resource,UndoAction undo,bool commit){
        MutationRecord r;r.policy=policy;r.resource=resource;r.undo=std::move(undo);MutationId id=0;
        if(!journal.prepareMutation(r,id,error)||(commit&&!journal.setStatus(id,MutationStatus::Applied,error))) {
            std::cerr<<error;return false;
        }
        std::cout<<id<<' '<<formatPolicyRef(policy)<<'\n';return true;
    };
    if(argc==2&&std::string(argv[1])=="--mixed-sysctl") {
        std::filesystem::create_directories("/etc/sysctl.d");
        std::ofstream("/etc/sysctl.d/zzzz-fic.conf")
            <<"# Managed by FIC. Manual changes may be overwritten.\nnet.ipv4.tcp_syncookies = 1\nunknown.orphan = 7\n";
        return seed({"SYSCTL","network_kernel_protection","tcp_syncookies_enable"},"net.ipv4.tcp_syncookies",
            {MutationBackend::Sysctl,UndoRemoveManagedSetting{"net.ipv4.tcp_syncookies","1"}},true)?0:1;
    }
    if(argc!=1)return 2;
    if(!seed({"NET","SshEdit","ssh_port"},"ssh:/etc/ssh/sshd_config:Port",
        {MutationBackend::Ssh,UndoRemoveSshManagedPolicy{"ssh_port","Port","2222",{}}},false))return 1;
    if(!seed({"DAC","SudoEdit","sudo_passwd_tries"},"passwd_tries",
        {MutationBackend::Sudo,UndoReleaseSudoGlobalDefault{"passwd_tries","Defaults passwd_tries=3","",
        fic::sudoers::generateSudoWrapperMutationId(0),false,""}},false))return 1;
    std::filesystem::create_directories("/etc/sysctl.d");
    std::ofstream("/etc/sysctl.d/zzzz-fic.conf")<<"# Managed by FIC. Manual changes may be overwritten.\nnet.ipv4.tcp_syncookies = 1\n";
    if(!seed({"SYSCTL","network_kernel_protection","tcp_syncookies_enable"},"net.ipv4.tcp_syncookies",
        {MutationBackend::Sysctl,UndoRemoveManagedSetting{"net.ipv4.tcp_syncookies","0"}},true))return 1;
    return 0;
}
