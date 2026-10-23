#include "daemon/PackageLifecycleCoordinator.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
using namespace fic::daemon;
namespace fs=std::filesystem;
namespace {
bool environment=true,writersStopped=true,crashAfterPublication=false;fs::path lockDirectory;
void require(bool ok,const std::string& error){if(!ok)throw std::runtime_error(error);}
std::string read(const fs::path& path){std::ifstream in(path);return {std::istreambuf_iterator<char>(in),{}};}
}
// Only link-time systemd/census boundary doubles. Store, hash-store flock,
// immutable inventories, masks and executable fingerprints are real.
namespace fic::daemon {
bool PackageWritersQuiescence::validateEnvironment(std::string& error) const {
    if(!environment){error="unsupported manager environment";return false;}return true;
}
bool PackageWritersQuiescence::requestStopBeforeAdmission(std::chrono::steady_clock::time_point,std::string& error) const {
    return validateEnvironment(error);
}
bool PackageWritersQuiescence::stopAndProve(const DaemonInstanceLock& guard,const PackageUnitMasks& masks,
    const std::string& id,const std::vector<LegacyWriterImage>& images,std::chrono::steady_clock::time_point,std::string& error) const {
    require(guard.heldByCurrentProcess()&&!images.empty(),"preparation lost admission/inventory");
    require(masks.provePublished(id,error),error);
    if(crashAfterPublication){::kill(::getpid(),SIGKILL);::_exit(99);}
    const auto child=::fork();require(child>=0,"fork contender");
    if(child==0){DaemonInstanceLock other;::_exit(other.tryAcquire(lockDirectory,error)?2:0);}
    int status=0;require(::waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"preparation lock gap");
    if(!writersStopped){error="injected unresolved writer";return false;}return true;
}
}
int main() {
    if(::geteuid()!=0)return 77;
    ::alarm(30);char pattern[]="/var/lib/fic-coordinator-test-XXXXXX";const auto* made=::mkdtemp(pattern);if(!made)return 1;
    const fs::path root=made;
    struct Cleanup{fs::path path;~Cleanup(){std::error_code ec;fs::remove_all(path,ec);}} cleanup{root};
    try {
        auto paths=fic::core::FicProductPaths::production();paths.privateBinDir=root/"bin";
        paths.runtimeDir=root/"run";paths.commandHashFile=root/"hash/hash.conf";
        paths.lockDebugLogFile=root/"locks.log";paths.mutationJournalFile=root/"journal";lockDirectory=paths.runtimeDir;
        PackageLifecycleLocations locations{root/"state",root/"units",root/"fic-runtime"};
        fs::create_directory(paths.privateBinDir);fs::create_directory(root/"hash");fs::create_directory(locations.systemUnitDirectory);
        fs::copy_file("/proc/self/exe",locations.runtimeExecutable);fs::copy_file("/proc/self/exe",paths.privateBinDir/"fic");
        // Preserve an existing foreign mask across the complete operation.
        fs::create_symlink("/dev/null",locations.systemUnitDirectory/"fic-notify.service");
        struct stat foreign{};require(::lstat((locations.systemUnitDirectory/"fic-notify.service").c_str(),&foreign)==0,"foreign mask fixture");
        const auto platform=fic::platform::makeBuildPlatformProfile();PackageLifecycleCoordinator coordinator(platform,paths,locations);
        DaemonInstanceLock guard,empty;std::string error;PackageLifecycleState prepared;
        require(guard.tryAcquire(paths.runtimeDir,error),error);
        require(!coordinator.prepare(empty,PackageOperation::Install,"1",prepared,error)&&!fs::exists(locations.stateDirectory),"unguarded preparation changed state");
        environment=false;
        require(!coordinator.prepare(guard,PackageOperation::Install,"1",prepared,error)&&!fs::exists(locations.stateDirectory),"unsupported environment changed persistent state");environment=true;
        require(!coordinator.prepare(guard,PackageOperation::Recover,"1",prepared,error),"unproved recovery accepted");
        // Fence publication shares trust-sync's real lock domain. A hostile
        // lock object refuses before adoption; a live holder delays fencing.
        const fs::path hashLock=paths.commandHashFile.string()+".lock";
        const auto victim=root/"foreign-lock-target";
        {std::ofstream out(victim);out<<"untouched\n";}
        fs::create_symlink(victim,hashLock);
        require(!coordinator.prepare(guard,PackageOperation::Install,"1",prepared,error)&&
            !fs::exists(locations.stateDirectory/"state.json")&&read(victim)=="untouched\n","untrusted hash lock adopted");
        fs::remove(hashLock);
        int ready[2],finish[2];require(::pipe(ready)==0&&::pipe(finish)==0,"hash contention pipes");
        const auto holder=::fork();require(holder>=0,"fork hash lock holder");
        if(holder==0) {
            ::close(ready[0]);::close(finish[1]);
            const int fd=::open(hashLock.c_str(),O_CREAT|O_RDWR|O_CLOEXEC,0600);
            if(fd<0||::flock(fd,LOCK_EX))::_exit(94);
            const char byte='R';if(::write(ready[1],&byte,1)!=1)::_exit(93);
            char done;if(::read(finish[0],&done,1)!=1)::_exit(92);
            ::_exit(0);
        }
        ::close(ready[1]);::close(finish[0]);char byte;
        require(::read(ready[0],&byte,1)==1,"hash lock readiness");::close(ready[0]);
        const bool busyRefused=!coordinator.prepare(guard,PackageOperation::Install,"1",prepared,error)&&
            error.find("hash-store mutation busy")!=std::string::npos&&!fs::exists(locations.stateDirectory/"state.json");
        require(::write(finish[1],"D",1)==1,"hash lock release");::close(finish[1]);
        int holderStatus=0;require(::waitpid(holder,&holderStatus,0)==holder&&WIFEXITED(holderStatus)&&WEXITSTATUS(holderStatus)==0,"hash lock holder failed");
        require(busyRefused,"fence published while trust-sync held hash lock");
        require(coordinator.requestStopBeforeAdmission(error),error);
        writersStopped=false;
        require(!coordinator.prepare(guard,PackageOperation::Install,"1",prepared,error),"unresolved writer admitted");
        PackageLifecycleStore store(locations.stateDirectory/"state.json");std::optional<PackageLifecycleState> state;
        require(store.inspect(state,error)&&state->phase==PackagePhase::Installing,error);
        const auto id=state->operationId,before=read(locations.stateDirectory/"state.json");
        require(!fs::exists(paths.mutationJournalFile),"preparation bootstrapped operational journal");
        // Unpack may already have removed the original main binary. Retry must
        // retain its original fingerprints and operation, not capture/adopt anew.
        fs::remove(paths.privateBinDir/"fic");writersStopped=true;
        require(coordinator.prepare(guard,PackageOperation::Install,"1",prepared,error)&&prepared.operationId==id,error);
        require(read(locations.stateDirectory/"state.json")==before,"retry changed lifecycle identity/provenance");
        require(!coordinator.prepare(guard,PackageOperation::Remove,"1",prepared,error),"pending install became removal");
        PackageUnitMasks masks(locations.stateDirectory/"operations",locations.systemUnitDirectory);
        require(masks.provePublished(id,error)&&masks.validateProvenance(id,error),error);
        require(store.advance(guard,*state,PackagePhase::InstalledButFenced,error)&&store.inspect(state,error),error);
        require(store.advance(guard,*state,PackagePhase::InfrastructureProven,error)&&store.inspect(state,error),error);
        require(masks.restore(guard,id,error)&&store.advance(guard,*state,PackagePhase::Installed,error),error);
        struct stat retained{};require(::lstat((locations.systemUnitDirectory/"fic-notify.service").c_str(),&retained)==0&&
            retained.st_ino==foreign.st_ino,"foreign mask replaced during restore");
        // A new upgraded main entrypoint is the exact runtime link.
        fs::create_symlink(locations.runtimeExecutable,paths.privateBinDir/"fic");
        require(coordinator.prepare(guard,PackageOperation::Upgrade,"2",prepared,error),error);
        require(prepared.phase==PackagePhase::Recovering&&prepared.operationId!=id&&prepared.maskOperationId==prepared.operationId,"upgrade did not quiesce without release");
        require(masks.provePublished(prepared.maskOperationId,error),error);
        require(fs::exists(locations.stateDirectory/"operations"/id/"writers.json"),"new operation discarded prior provenance");
        require(!fs::exists(paths.mutationJournalFile),"upgrade preparation initialized policy journal");
        // Abrupt loss after durable fence+mask publication must release only
        // flock, never the persistent writer fence. Restart reuses the exact
        // inventory even if unpack already removed the main executable.
        for(const auto operation:{PackageOperation::Install,PackageOperation::Upgrade}) {
            const auto crashRoot=root/(operation==PackageOperation::Install?"crash-install":"crash-upgrade");
            fs::create_directory(crashRoot);fs::create_directory(crashRoot/"bin");
            fs::create_directory(crashRoot/"hash");fs::create_directory(crashRoot/"units");
            auto crashPaths=paths;crashPaths.privateBinDir=crashRoot/"bin";
            crashPaths.runtimeDir=crashRoot/"run";crashPaths.commandHashFile=crashRoot/"hash/hashes";
            crashPaths.lockDebugLogFile=crashRoot/"lock.log";crashPaths.mutationJournalFile=crashRoot/"journal";
            PackageLifecycleLocations crashLocations{crashRoot/"state",crashRoot/"units",crashRoot/"runtime"};
            fs::copy_file("/proc/self/exe",crashLocations.runtimeExecutable);
            fs::copy_file("/proc/self/exe",crashPaths.privateBinDir/"fic");
            PackageLifecycleCoordinator crashCoordinator(platform,crashPaths,crashLocations);
            lockDirectory=crashPaths.runtimeDir;
            const auto child=::fork();require(child>=0,"fork publication crash");
            if(child==0) {
                DaemonInstanceLock childGuard;
                if(!childGuard.tryAcquire(crashPaths.runtimeDir,error))::_exit(98);
                crashAfterPublication=true;
                crashCoordinator.prepare(childGuard,operation,"3",prepared,error);::_exit(97);
            }
            int status=0;require(::waitpid(child,&status,0)==child&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL,"crash boundary was not reached");
            PackageLifecycleStore crashStore(crashLocations.stateDirectory/"state.json");
            require(crashStore.inspect(state,error)&&state&&state->phase==
                (operation==PackageOperation::Install?PackagePhase::Installing:PackagePhase::Fencing),error);
            const auto crashId=state->operationId;
            PackageUnitMasks crashMasks(crashLocations.stateDirectory/"operations",crashLocations.systemUnitDirectory);
            require(crashMasks.provePublished(state->maskOperationId,error),error);
            const auto inventoryBefore=read(crashLocations.stateDirectory/"operations"/crashId/"writers.json");
            fs::remove(crashPaths.privateBinDir/"fic");
            DaemonInstanceLock restartGuard;require(restartGuard.tryAcquire(crashPaths.runtimeDir,error),error);
            require(crashCoordinator.prepare(restartGuard,operation,"3",prepared,error)&&prepared.operationId==crashId,error);
            require(read(crashLocations.stateDirectory/"operations"/crashId/"writers.json")==inventoryBefore,"crash restart rewrote writer provenance");
            require(!fs::exists(crashPaths.mutationJournalFile),"crash restart initialized journal");
            require(crashMasks.provePublished(prepared.maskOperationId,error),error);
        }
        std::cout<<"PASS: fixed preparation under one admission, durable inventory/fence/masks, retry without originals, foreign mask preservation, upgrade without release\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
