#include "daemon/PackagePamHooks.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
using namespace fic::daemon;
namespace fs=std::filesystem;
namespace {
void require(bool ok,const std::string& error){if(!ok)throw std::runtime_error(error);}
void write(const fs::path& path,const std::string& content,mode_t mode=0644){std::ofstream out(path);out<<content;out.close();require(::chmod(path.c_str(),mode)==0,"chmod");}
std::string read(const fs::path& path){std::ifstream in(path);return {std::istreambuf_iterator<char>(in),{}};}
}
int main(int argc,char** argv) {
    if(::geteuid()!=0)return 77;
    char pattern[]="/var/lib/fic-pam-package-test-XXXXXX";auto* made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made;
    struct Cleanup{fs::path path;~Cleanup(){std::error_code ec;fs::remove_all(path,ec);}} cleanup{root};
    try {
        const auto pam=root/"pam.d",state=root/"state";
        fs::create_directory(pam);fs::create_directory(state);
        const auto initialize=[&]{
            for(const char* facility:{"auth","account","password","session"})write(state/facility,"\n");
            write(state/"auth","Module: fic-faillock-hook-preauth\n");
            write(state/"account","Module: fic-incident-access\n");
            write(pam/"common-auth","auth include fic-faillock-preauth\n");
            write(pam/"fic-faillock-preauth","# neutral\n");
            write(pam/"common-account","account required pam_fic_access.so\n");
        };
        initialize();
        const auto command=root/"pam-auth-update";
        // Fixed native child fixture records ordering. It never calls the host
        // package manager or touches host PAM; paths are this root-private tree.
        const auto prefix="#!/bin/sh\nset -eu\ncd '"+root.string()+"'\n";
        write(command,prefix+R"(case "$*" in
*fic-incident-access*)
 echo gate >> calls
 test ! -e fail-gate
 printf '\n' > state/account
 printf 'account required pam_unix.so\n' > pam.d/common-account
 ;;
*)
 echo other >> calls
 test ! -e fail-other
 if test -e retain-other; then exit 0; fi
 if test -e drop-gate; then
   printf '\n' > state/account
   printf 'account required pam_unix.so\n' > pam.d/common-account
 fi
 printf '\n' > state/auth
 printf 'auth required pam_unix.so\n' > pam.d/common-auth
 ;;
esac
)",0755);
        auto platform=fic::platform::makeBuildPlatformProfile();platform.id="debian-12";
        platform.packageManager.kind=fic::platform::PackageManagerKind::Dpkg;
        platform.pam.incidentAccessGate.packageTopologyTarget.clear();platform.pam.configDirectories={pam};platform.pam.moduleDirectories={root/"modules"};
        fs::create_directory(root/"modules");
        require(argc==2,"expected actual built PAM module path");
        fs::copy_file(argv[1],root/"modules/pam_fic_access.so");::chmod((root/"modules/pam_fic_access.so").c_str(),0644);
        platform.pam.incidentAccessGate.controlledServices={"common-account"};
        platform.executables.entries={{fic::platform::ExecutableId::PamAuthUpdate,{command},true,{},{}}};
        PackagePamHooks hooks(platform,state);DaemonInstanceLock guard,empty;std::string error;
        require(guard.tryAcquire(root/"runtime",error),error);
        auto deadline=[] {return std::chrono::steady_clock::now()+std::chrono::seconds(10);};
        require(!hooks.detach(empty,deadline(),error)&&!fs::exists(root/"calls"),"unguarded hook mutation");
        require(!hooks.proveDetached(error),"attached hooks accepted");
        write(state/"password","Module: fic-future-unknown\n");
        require(!hooks.detach(guard,deadline(),error)&&!fs::exists(root/"calls"),"unknown profile selection authorized mutation");
        write(state/"password","\n");
        ::chmod((state/"password").c_str(),0666);
        require(!hooks.detach(guard,deadline(),error)&&!fs::exists(root/"calls"),"unprovable state executed mutation");
        ::chmod((state/"password").c_str(),0644);
        write(root/"fail-other","");
        require(!hooks.detach(guard,deadline(),error)&&read(root/"calls")=="other\n"&&
            read(pam/"common-account").find("pam_fic_access")!=std::string::npos,"first failure detached incident gate");
        fs::remove(root/"fail-other");fs::remove(root/"calls");write(root/"retain-other","");
        require(!hooks.detach(guard,deadline(),error)&&read(root/"calls")=="other\n","successful updater exit substituted hook proof");
        fs::remove(root/"retain-other");fs::remove(root/"calls");write(root/"drop-gate","");
        require(!hooks.detach(guard,deadline(),error)&&read(root/"calls")=="other\n","unexpected gate loss accepted");
        fs::remove(root/"drop-gate");fs::remove(root/"calls");initialize();write(root/"fail-gate","");
        require(!hooks.detach(guard,deadline(),error)&&read(root/"calls")=="other\ngate\n","gate failure ordering");
        require(read(pam/"common-auth")=="auth required pam_unix.so\n","failure compensated released hooks");
        fs::remove(root/"fail-gate");fs::remove(root/"calls");
        require(hooks.detach(guard,deadline(),error)&&hooks.proveDetached(error)&&read(root/"calls")=="gate\n",error);
        require(hooks.detach(guard,deadline(),error)&&read(root/"calls")=="gate\n","idempotent replay invoked updater");
        write(pam/"foreign-service","auth include fic-password-history\n");
        require(!hooks.proveDetached(error),"foreign service reference missed");fs::remove(pam/"foreign-service");
        fs::create_symlink("common-auth",pam/"alias");require(hooks.proveDetached(error),error);
        fs::remove(pam/"alias");fs::create_symlink("/etc/pam.d/login",pam/"alias");
        require(!hooks.detach(guard,deadline(),error)&&read(root/"calls")=="gate\n","escaping alias permitted mutation");fs::remove(pam/"alias");
        initialize();require(!hooks.detach(guard,std::chrono::steady_clock::now()-std::chrono::seconds(1),error)&&read(root/"calls")=="gate\n","expired deadline mutated hooks");
        std::cout<<"PASS: fixed hook order, no mutation on unproven preconditions, partial failure/retry, aliases, deadline, idempotence\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
