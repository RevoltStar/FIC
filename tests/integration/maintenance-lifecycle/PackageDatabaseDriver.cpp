#include "daemon/PackageDatabaseSnapshot.h"
#include <cstdlib>
#include <iostream>
#include <unistd.h>
int main(int argc,char** argv) {
    const auto* opt=std::getenv("FIC_MAINTENANCE_NATIVE");
    if(::geteuid()!=0||!opt||std::string(opt)!="1")return 77;
    if(argc!=2&&argc!=3)return 2;
    const bool rpm=std::string(argv[1])=="rpm";
    if(!rpm&&std::string(argv[1])!="dpkg")return 2;
    fic::platform::PackageManagerPlatformConfig config;
    config.kind=rpm?fic::platform::PackageManagerKind::Rpm:fic::platform::PackageManagerKind::Dpkg;
    config.transactionLocks=rpm?std::vector<std::filesystem::path>{"/var/lib/rpm/.rpm.lock"}:
        std::vector<std::filesystem::path>{"/var/lib/dpkg/lock-frontend","/var/lib/dpkg/lock"};
    fic::platform::PlatformExecutables paths;
    paths.entries.push_back({fic::platform::ExecutableId::PackageQuery,
        rpm?std::vector<std::filesystem::path>{"/usr/bin/rpm","/bin/rpm"}:
            std::vector<std::filesystem::path>{"/usr/bin/dpkg-query","/bin/dpkg-query"},true,{},{}});
    fic::platform::PlatformExecutableResolver executables(paths);
    fic::daemon::DaemonInstanceLock guard;std::string error;
    if(!guard.tryAcquire("/run/fic",error)){std::cerr<<error;return 1;}
    fic::daemon::PackageManagerTransactionLock locks;
    if(locks.tryAcquire(guard,config,error)!=fic::daemon::PackageManagerLockResult::Acquired){std::cerr<<error;return 1;}
    fic::daemon::PackageDatabaseReader reader(executables,config.kind);
    std::size_t budget=1024*1024;const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(30);
    for(unsigned i=0;i<2;++i) {
        fic::daemon::PackageDatabaseSnapshot snapshot;
        if(!reader.read(locks,deadline,budget,snapshot,error)){std::cerr<<error;return 1;}
        for(const auto& [name,entry]:snapshot.packages)
            std::cout<<name<<'\t'<<static_cast<int>(entry.state)<<'\t'<<entry.version<<'\t'<<entry.architecture<<'\n';
    }
    if(argc==3) {
        std::vector<std::filesystem::path> paths;
        if(!reader.readOwnedPaths(locks,argv[2],deadline,budget,paths,error)){std::cerr<<error;return 1;}
        for(const auto& path:paths)std::cout<<"OWNED\t"<<path.string()<<'\n';
        if(!reader.readOwnedPaths(locks,argv[2],deadline,budget,paths,error)){std::cerr<<error;return 1;}
        if(reader.readOwnedPaths(locks,"unrelated",deadline,budget,paths,error)||!paths.empty())return 3;
        std::cout<<"OWNED_REPEAT_AND_UNKNOWN_REFUSAL_PASS\n";
    }
    if(!locks.revalidate(error)){std::cerr<<error;return 1;}
    std::cout<<"BUDGET_REMAINING\t"<<budget<<'\n';return 0;
}
