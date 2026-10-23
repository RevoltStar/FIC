#include "daemon/PackageManagerTransactionLock.h"
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace fic::daemon;
using namespace fic::platform;
void require(bool yes,const std::string& message) {if(!yes)throw std::runtime_error(message);}
int main(int argc,char** argv) {
    if(::geteuid()!=0)return 77;
    ::alarm(25);
    if(argc==3 && std::string(argv[1])=="--native-hold") {
        if(!std::getenv("FIC_MAINTENANCE_NATIVE") || std::string(std::getenv("FIC_MAINTENANCE_NATIVE"))!="1")return 77;
        DaemonInstanceLock daemon;std::string error;
        if(!daemon.tryAcquire("/run/fic",error)) {std::cerr<<error;return 1;}
        PackageManagerPlatformConfig config;
        const bool rpm=std::string(argv[2])=="rpm";
        config.kind=rpm?PackageManagerKind::Rpm:PackageManagerKind::Dpkg;
        config.transactionLocks=rpm?std::vector<std::filesystem::path>{"/var/lib/rpm/.rpm.lock"}:
            std::vector<std::filesystem::path>{"/var/lib/dpkg/lock-frontend","/var/lib/dpkg/lock"};
        PackageManagerTransactionLock lock;
        const auto result=lock.tryAcquire(daemon,config,error);
        if(result!=PackageManagerLockResult::Acquired){std::cerr<<error;return result==PackageManagerLockResult::Busy?75:1;}
        std::cout<<"LOCKED"<<std::endl;char ignored; (void)::read(STDIN_FILENO,&ignored,1);
        return lock.revalidate(error)?0:1;
    }
    std::string pattern="/run/fic-package-lock-XXXXXX";char* created=::mkdtemp(pattern.data());if(!created)return 1;
    std::filesystem::path root=created;
    struct Cleanup {std::filesystem::path root;~Cleanup(){std::error_code e;std::filesystem::remove_all(root,e);}} cleanup{root};
    try {
        std::string error;DaemonInstanceLock daemon,empty;require(daemon.tryAcquire(root/"runtime",error),error);
        const auto a=root/"frontend",b=root/"database";
        for(const auto& path:{a,b}) {std::ofstream(path)<<"unchanged";::chmod(path.c_str(),0640);}
        PackageManagerPlatformConfig config;config.kind=PackageManagerKind::Dpkg;config.transactionLocks={a,b};
        PackageManagerTransactionLock invalid;
        require(invalid.tryAcquire(empty,config,error)==PackageManagerLockResult::Unprovable,"missing daemon admission");
        auto unknown=config;unknown.kind=static_cast<PackageManagerKind>(99);
        require(invalid.tryAcquire(daemon,unknown,error)==PackageManagerLockResult::Unprovable,"unknown manager");
        {
            PackageManagerTransactionLock first,second;
            require(first.tryAcquire(daemon,config,error)==PackageManagerLockResult::Acquired,error);
            require(first.covers(PackageManagerKind::Dpkg)&&!first.covers(PackageManagerKind::Rpm),"manager identity not bound to lock set");
            require(second.tryAcquire(daemon,config,error)==PackageManagerLockResult::Busy,"same-process lock reentry released POSIX locks");
            const auto pid=::fork();require(pid>=0,"fork");
            if(pid==0) {
                int fd=::open(a.c_str(),O_RDWR);struct flock lock{};lock.l_type=F_WRLCK;lock.l_whence=SEEK_SET;
                ::_exit(fd>=0 && ::fcntl(fd,F_SETLK,&lock)<0 && !first.heldByCurrentProcess()?0:2);
            }
            int status=0;require(::waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"child lock conflict/authority");
            require(first.revalidate(error),error);
        }
        // Partial acquisition: real external holder owns SECOND lock. First
        // acquisition must be released on refusal; no system file is modified.
        int ready[2],release[2];require(::pipe(ready)==0&&::pipe(release)==0,"pipe");
        auto child=::fork();require(child>=0,"fork");
        if(child==0) {
            ::close(ready[0]);::close(release[1]);int fd=::open(b.c_str(),O_RDWR);
            struct flock lock{};lock.l_type=F_WRLCK;lock.l_whence=SEEK_SET;
            if(fd<0 || ::fcntl(fd,F_SETLK,&lock))::_exit(2);
            const char c='R';if(::write(ready[1],&c,1)!=1)::_exit(3);char ignored; (void)::read(release[0],&ignored,1);::_exit(0);
        }
        struct Reap {pid_t p;~Reap(){if(p>0){::kill(p,SIGKILL);::waitpid(p,nullptr,0);}}} reap{child};
        ::close(ready[1]);::close(release[0]);char c;
        require(::read(ready[0],&c,1)==1,"holder barrier");::close(ready[0]);
        PackageManagerTransactionLock contender;
        require(contender.tryAcquire(daemon,config,error)==PackageManagerLockResult::Busy,"external manager ignored");
        // A distinct process must acquire the first file: F_GETLK in the
        // owning process cannot detect its own accidentally retained POSIX lock.
        const auto probe=::fork();require(probe>=0,"fork rollback probe");
        if(probe==0) {
            int fd=::open(a.c_str(),O_RDWR);struct flock lock{};lock.l_type=F_WRLCK;lock.l_whence=SEEK_SET;
            ::_exit(fd>=0&&::fcntl(fd,F_SETLK,&lock)==0?0:2);
        }
        int probeStatus=0;require(::waitpid(probe,&probeStatus,0)==probe&&WIFEXITED(probeStatus)&&WEXITSTATUS(probeStatus)==0,"partial lock retained");
        require(::kill(child,SIGKILL)==0,"crash holder");int status=0;require(::waitpid(child,&status,0)==child,"wait holder");reap.p=-1;::close(release[1]);
        {
            PackageManagerTransactionLock restarted;
            require(restarted.tryAcquire(daemon,config,error)==PackageManagerLockResult::Acquired,error);
            std::filesystem::rename(b,root/"old");std::ofstream(b)<<"foreign replacement";
            require(!restarted.revalidate(error),"named lock replacement accepted");
        }
        std::filesystem::remove(b);std::filesystem::create_symlink(a,b);
        require(invalid.tryAcquire(daemon,config,error)==PackageManagerLockResult::Unprovable,"symlink lock accepted");
        std::filesystem::remove(b);
        require(invalid.tryAcquire(daemon,config,error)==PackageManagerLockResult::Unprovable&&!std::filesystem::exists(b),"missing lock created");
        std::ifstream in(a);std::string text;std::getline(in,text);require(text=="unchanged","lock content modified");
        std::cout<<"PASS: package POSIX lock set, process contention/crash, partial refusal, identity and no mutation\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
