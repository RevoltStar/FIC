#include "daemon/PackageWriterProcesses.h"
#include <filesystem>
#include <iostream>
#include <fstream>
#include <thread>
#include <pthread.h>
#include <stdexcept>
#include <csignal>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace fic::daemon;
namespace fs=std::filesystem;
void require(bool yes,const std::string& error){if(!yes)throw std::runtime_error(error);}
int main(int argc,char** argv) {
    if(argc==3&&(std::string(argv[1])=="--child"||std::string(argv[1])=="--thread-child")) {
        int fd=std::stoi(argv[2]);
        if(std::string(argv[1])=="--thread-child") {
            std::thread worker([fd] {
                const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
                for(;;) {
                    std::ifstream status("/proc/self/status");std::string line;bool zombie=false;
                    while(std::getline(status,line))if(line.compare(0,6,"State:")==0&&line.find('Z',6)!=std::string::npos)zombie=true;
                    if(zombie)break;
                    if(std::chrono::steady_clock::now()>=deadline)::_exit(4);
                    std::this_thread::yield();
                }
                const char ready='R';if(::write(fd,&ready,1)!=1)::_exit(5);
                while(true)::pause();
            });
            worker.detach();::pthread_exit(nullptr);
        }
        const char ready='R';if(::write(fd,&ready,1)!=1)return 2;
        while(true)::pause();
    }
    if(::geteuid()!=0)return 77;
    ::alarm(25);
    // systemd/container /run is commonly noexec; the renamed-executable probe
    // needs a root-controlled executable filesystem, not a runtime tmpfs.
    std::string pattern="/var/lib/fic-process-test-XXXXXX";char* created=::mkdtemp(pattern.data());if(!created)return 1;
    const fs::path root=created;
    struct Cleanup {fs::path root;~Cleanup(){std::error_code e;fs::remove_all(root,e);}} cleanup{root};
    try {
        fs::copy_file("/proc/self/exe",root/"reference");
        fs::copy_file("/proc/self/exe",root/"renamed-copy");
        LegacyWriterImage reference;std::string error;
        require(captureLegacyWriterImage(root/"reference",reference,error),error);
        std::vector<LegacyWriterImage> images{reference};
        fs::remove(root/"reference");
        const auto prove=[&]{return proveNoPackageWriterProcesses(images,
            std::chrono::steady_clock::now()+std::chrono::seconds(5),error);};
        require(prove(),error);
        for(const auto* mode:{"--child","--thread-child"}) {
        int pipe[2];require(::pipe(pipe)==0,"pipe");
        pid_t child=::fork();require(child>=0,"fork");
        if(child==0) {
            ::close(pipe[0]);const auto fd=std::to_string(pipe[1]);
            ::execl((root/"renamed-copy").c_str(),"renamed-copy",mode,fd.c_str(),nullptr);::_exit(3);
        }
        struct Reap {pid_t child;~Reap(){if(child>0){::kill(child,SIGKILL);::waitpid(child,nullptr,0);}}} reap{child};
        ::close(pipe[1]);char ready;require(::read(pipe[0],&ready,1)==1&&ready=='R',"executable readiness");::close(pipe[0]);
        require(!prove(),"renamed legacy copy / live zombie-leader threads not detected: "+error);
        int status=0;require(::waitpid(child,&status,WNOHANG)==0,"proof killed a manual writer");
        require(::kill(child,SIGKILL)==0&&::waitpid(child,&status,0)==child,"cleanup child");reap.child=-1;
        require(prove(),error);
        }
        // Canonical writer name with an unknown executable is not silently
        // classified as harmless, and the proof never terminates it.
        require(argc==2,"expected separate unknown-writer fixture executable");
        fs::copy_file(argv[1],root/"fic");int readyPipe[2];require(::pipe(readyPipe)==0,"unknown writer pipe");
        const auto unknown=::fork();require(unknown>=0,"fork unknown writer");
        if(unknown==0){::close(readyPipe[0]);const auto fd=std::to_string(readyPipe[1]);
            ::execl((root/"fic").c_str(),"spoofed-harmless-name",fd.c_str(),nullptr);::_exit(6);}
        struct ReapUnknown {pid_t child;~ReapUnknown(){if(child>0){::kill(child,SIGKILL);::waitpid(child,nullptr,0);}}} reapUnknown{unknown};
        ::close(readyPipe[1]);char signal;require(::read(readyPipe[0],&signal,1)==1&&signal=='R',"unknown writer readiness failed");::close(readyPipe[0]);
        require(!prove()&&error.find("writer remains")!=std::string::npos,"unknown canonical writer ignored: "+error);
        int unknownStatus=0;require(::waitpid(unknown,&unknownStatus,WNOHANG)==0,"proof killed unknown process");
        require(::kill(unknown,SIGKILL)==0&&::waitpid(unknown,&unknownStatus,0)==unknown,"unknown cleanup");reapUnknown.child=-1;
        require(prove(),error);
        for(const auto* scriptName:{"fic-notify-dispatcher","fic-udevadm-trigger"}) {
            const auto script=root/scriptName;
            {std::ofstream out(script);out<<"printf R\nread token\n";}
            int ready[2],input[2];require(::pipe(ready)==0&&::pipe(input)==0,"script pipes");
            const auto child=::fork();require(child>=0,"fork script");
            if(child==0) {
                ::dup2(input[0],STDIN_FILENO);::dup2(ready[1],STDOUT_FILENO);
                for(const auto fd:{ready[0],ready[1],input[0],input[1]})::close(fd);
                ::execl("/bin/sh","sh",script.c_str(),nullptr);::_exit(3);
            }
            struct ScriptCleanup {pid_t pid;~ScriptCleanup(){if(pid>0){::kill(pid,SIGKILL);::waitpid(pid,nullptr,0);}}} cleanup{child};
            ::close(input[0]);::close(ready[1]);char signal;
            require(::read(ready[0],&signal,1)==1&&signal=='R',"manual script readiness");::close(ready[0]);
            require(!prove()&&error.find("writer remains")!=std::string::npos,"interpreter-based manual writer missed: "+error);
            int status=0;require(::waitpid(child,&status,WNOHANG)==0,"proof terminated manual script");
            ::close(input[1]);require(::waitpid(child,&status,0)==child,"manual script cleanup");cleanup.pid=-1;
            fs::remove(script);require(prove(),error);
        }
        require(!proveNoPackageWriterProcesses({reference},std::chrono::steady_clock::now(),error),"expired budget accepted");
        auto invalid=reference;invalid.digest.clear();
        require(!proveNoPackageWriterProcesses({invalid},std::chrono::steady_clock::now()+std::chrono::seconds(5),error),"invalid reference accepted");
        fs::create_symlink(root/"reference",root/"alias");
        require(!captureLegacyWriterImage(root/"alias",invalid,error),"symlink reference accepted");
        std::cout<<"PASS: captured identity after original removed, real procfs, renamed manual copy/live-thread refusal, no kill and bounded proof\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
