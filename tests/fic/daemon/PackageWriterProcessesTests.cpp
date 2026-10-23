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
        DaemonInstanceLock guard,empty;require(guard.tryAcquire(root/"runtime",error),error);
        const std::string id(32,'a');const auto inventory=root/"writers.json";
        std::vector<LegacyWriterImage> images;
        require(!readLegacyWriterInventory(inventory,id,images,error),"missing inventory treated as empty");
        require(!writeLegacyWriterInventory(empty,inventory,id,{reference},error)&&!fs::exists(inventory),"unguarded inventory creation");
        require(writeLegacyWriterInventory(guard,inventory,id,{reference},error),error);
        require(!writeLegacyWriterInventory(guard,inventory,id,{},error),"existing inventory overwritten");
        require(!readLegacyWriterInventory(inventory,std::string(32,'b'),images,error),"foreign operation accepted");
        require(readLegacyWriterInventory(inventory,id,images,error)&&images.size()==1&&images[0].digest==reference.digest&&
            images[0].inode==reference.inode,"inventory lost reference identity");
        // The installed path can disappear during unpack. Restart proof must
        // use persisted fingerprints, never reinterpret missing originals.
        fs::remove(root/"reference");
        const auto prove=[&]{return readLegacyWriterInventory(inventory,id,images,error)&&
            proveNoPackageWriterProcesses(images,std::chrono::steady_clock::now()+std::chrono::seconds(5),error);};
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
        fs::copy_file("/bin/sleep",root/"fic");int readyPipe[2];require(::pipe2(readyPipe,O_CLOEXEC)==0,"exec pipe");
        const auto unknown=::fork();require(unknown>=0,"fork unknown writer");
        if(unknown==0){::close(readyPipe[0]);::execl((root/"fic").c_str(),"fic","30",nullptr);const char e='E';(void)::write(readyPipe[1],&e,1);::_exit(6);}
        struct ReapUnknown {pid_t child;~ReapUnknown(){if(child>0){::kill(child,SIGKILL);::waitpid(child,nullptr,0);}}} reapUnknown{unknown};
        ::close(readyPipe[1]);char signal;require(::read(readyPipe[0],&signal,1)==0,"unknown writer exec failed");::close(readyPipe[0]);
        require(!prove()&&error.find("writer remains")!=std::string::npos,"unknown canonical writer ignored: "+error);
        int unknownStatus=0;require(::waitpid(unknown,&unknownStatus,WNOHANG)==0,"proof killed unknown process");
        require(::kill(unknown,SIGKILL)==0&&::waitpid(unknown,&unknownStatus,0)==unknown,"unknown cleanup");reapUnknown.child=-1;
        require(prove(),error);
        require(!proveNoPackageWriterProcesses({reference},std::chrono::steady_clock::now(),error),"expired budget accepted");
        auto invalid=reference;invalid.digest.clear();
        require(!proveNoPackageWriterProcesses({invalid},std::chrono::steady_clock::now()+std::chrono::seconds(5),error),"invalid reference accepted");
        fs::create_symlink(root/"reference",root/"alias");
        require(!captureLegacyWriterImage(root/"alias",invalid,error),"symlink reference accepted");
        const auto duplicate=root/"duplicates.json";
        require(!writeLegacyWriterInventory(guard,duplicate,id,{reference,reference},error)&&!fs::exists(duplicate),"duplicate inventory accepted");
        {std::ofstream corrupt(inventory);corrupt<<"{\"version\":1,\"id\":\""<<id<<"\",\"count\":0,\"count\":0}";}
        require(!readLegacyWriterInventory(inventory,id,images,error)&&images.empty(),"corrupt inventory authorized empty census");
        std::cout<<"PASS: immutable operation inventory after original removed, real procfs, renamed manual copy/live-thread refusal, no kill and bounded proof\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
