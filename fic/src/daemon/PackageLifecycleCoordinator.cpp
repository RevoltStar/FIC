#include "daemon/PackageLifecycleCoordinator.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/process/ExclusivePidLock.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <memory>
#include <set>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
bool fail(std::string& error,const std::string& why){error=why;return false;}
bool privateDirectory(const std::filesystem::path& path,std::string& error) {
    if(!path.is_absolute()||path.lexically_normal()!=path||path.filename().empty()||path.filename()=="."||path.filename()=="..")
        return fail(error,"invalid lifecycle private directory path");
    // The containing root-controlled directory must already exist. Never make
    // arbitrary ancestors or repair/adopt a foreign/writable/symlink directory.
    const int parent=fic::core::openRootControlledDirectory(path.parent_path(),error);
    if(parent<0)return false;
    const auto name=path.filename();
    bool created=false;
    if(::mkdirat(parent,name.c_str(),0700)==0)created=true;
    else if(errno!=EEXIST){::close(parent);return fail(error,"cannot create lifecycle private directory");}
    const int fd=::openat(parent,name.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat info{};
    const bool proven=fd>=0&&::fstat(fd,&info)==0&&info.st_uid==0&&info.st_gid==0&&(info.st_mode&07777)==0700;
    const bool durable=proven&&::fsync(fd)==0&&(!created||::fsync(parent)==0);
    if(fd>=0)::close(fd);
    ::close(parent);
    return durable||fail(error,"lifecycle directory metadata/durability is unproven");
}
bool newId(std::string& id,std::string& error) {
    std::array<unsigned char,16> random{};std::size_t done=0;
    while(done<random.size()) {
        const auto count=::getrandom(random.data()+done,random.size()-done,0);
        if(count<0&&errno==EINTR)continue;
        if(count<=0)return fail(error,"cannot obtain lifecycle operation identity");
        done+=static_cast<std::size_t>(count);
    }
    constexpr char hex[]="0123456789abcdef";id.clear();
    for(const auto byte:random){id+=hex[byte>>4];id+=hex[byte&15];}
    return true;
}
bool inventory(const fic::core::FicProductPaths& paths,const PackageLifecycleLocations& locations,
    bool requireMain,std::vector<LegacyWriterImage>& images,std::string& error) {
    images.clear();std::set<std::string> seen;bool mainFound=false;
    for(const auto& file:{locations.runtimeExecutable,paths.privateBinDir/"fic",paths.privateBinDir/"fic-dick",
        paths.privateBinDir/"fic-notify-dispatcher",paths.privateBinDir/"fic-udevadm-trigger"}) {
        struct stat info{};if(::lstat(file.c_str(),&info)) {
            if(errno==ENOENT&&file!=locations.runtimeExecutable)continue;
            return fail(error,"missing/unprovable lifecycle writer executable: "+file.string());
        }
        auto physical=file;
        if(S_ISLNK(info.st_mode)) {
            // The ONLY supported main entrypoint alias is the exact new
            // runtime-owned ELF. Unknown old symlinks never become adoption.
            const int parent=fic::core::openRootControlledDirectory(file.parent_path(),error);
            if(parent<0)return false;
            ::close(parent);
            if(info.st_uid||info.st_nlink!=1)return fail(error,"foreign main entrypoint alias");
            std::error_code ec;const auto target=std::filesystem::read_symlink(file,ec);
            if(ec||file!=paths.privateBinDir/"fic"||target!=locations.runtimeExecutable)
                return fail(error,"unknown lifecycle writer executable alias");
            physical=locations.runtimeExecutable;
        }
        LegacyWriterImage image;
        if(!captureLegacyWriterImage(physical,image,error))return false;
        if(file==paths.privateBinDir/"fic")mainFound=true;
        if(seen.insert(image.digest).second)images.push_back(std::move(image));
    }
    return !requireMain||mainFound||fail(error,"legacy main executable must be identified before unpack");
}
}
bool PackageLifecycleCoordinator::requestStopBeforeAdmission(std::string& error) const {
    fic::platform::PlatformExecutableResolver executables(platform_.executables);
    return PackageWritersQuiescence(executables).requestStopBeforeAdmission(
        std::chrono::steady_clock::now()+std::chrono::seconds(30),error);
}
bool PackageLifecycleCoordinator::prepare(const DaemonInstanceLock& guard,PackageOperation operation,
    const std::string& version,PackageLifecycleState& prepared,std::string& error) const {
    if(!guard.heldByCurrentProcess()||
       (operation!=PackageOperation::Install&&operation!=PackageOperation::Upgrade&&operation!=PackageOperation::Remove))
        return fail(error,"invalid package preparation admission/operation");
    if(version.empty()||version.size()>128||version.find_first_of("\r\n\0",0,3)!=std::string::npos)
        return fail(error,"invalid expected package version");
    fic::platform::PlatformExecutableResolver executables(platform_.executables);
    PackageWritersQuiescence writers(executables);
    if(!writers.validateEnvironment(error)||!privateDirectory(locations_.stateDirectory,error))return false;
    PackageLifecycleStore store(locations_.stateDirectory/"state.json");std::optional<PackageLifecycleState> state;
    if(!store.inspect(state,error))return false;
    const auto operations=locations_.stateDirectory/"operations";
    if(state) {
        // Missing operation provenance must not be recreated as an empty area.
        const int root=fic::core::openRootControlledDirectory(operations,error);
        if(root<0)return false;
        struct stat info{};const bool valid=::fstat(root,&info)==0&&info.st_gid==0&&(info.st_mode&07777)==0700;
        ::close(root);if(!valid)return fail(error,"untrusted lifecycle operation provenance directory");
    } else if(!privateDirectory(operations,error))return false;
    PackageUnitMasks masks(locations_.stateDirectory/"operations",locations_.systemUnitDirectory);
    std::vector<LegacyWriterImage> images;
    const bool retry=state&&state->operation==operation&&state->packageVersion==version&&
        ((operation==PackageOperation::Install&&state->phase==PackagePhase::Installing)||
         (operation==PackageOperation::Upgrade&&(state->phase==PackagePhase::Fencing||state->phase==PackagePhase::Quiescent||state->phase==PackagePhase::Recovering))||
         (operation==PackageOperation::Remove&&state->phase>=PackagePhase::Fencing&&state->phase<=PackagePhase::ReleaseComplete));
    if(retry) {
        if(!readLegacyWriterInventory(locations_.stateDirectory/"operations"/state->operationId/"writers.json",
            state->operationId,images,error)||!masks.publish(guard,state->maskOperationId,error))return false;
    } else {
        if(state&&state->phase!=PackagePhase::Installed)return fail(error,"pending lifecycle requires closed recovery; refusing new operation");
        if(state&&operation==PackageOperation::Install)return fail(error,"installed lifecycle requires typed upgrade/reinstall");
        if(state) {
            std::vector<LegacyWriterImage> prior;
            if(!masks.validateProvenance(state->maskOperationId,error)||!readLegacyWriterInventory(
                operations/state->operationId/"writers.json",state->operationId,prior,error))return false;
        }
        if(!inventory(paths_,locations_,operation!=PackageOperation::Install,images,error))return false;
        std::string id;if(!newId(id,error))return false;
        // Immutable masks + writer inventory are durable BEFORE the fence and
        // before publishing any mask. A crash here leaves a private orphan only.
        if(!masks.prepare(guard,id,error)||!writeLegacyWriterInventory(guard,
            locations_.stateDirectory/"operations"/id/"writers.json",id,images,error))return false;
        PackageLifecycleState next{operation,operation==PackageOperation::Install?PackagePhase::Installing:PackagePhase::Fencing,id,version,0,id,{},0,FinalizerFailure::None};
        // Trust-sync repeats admission under THIS existing lock. Keep it held
        // through fence publication; never introduce an independent lock path.
        std::unique_ptr<ExclusivePidLock> hashLock;struct stat directory{};
        if(::lstat(paths_.commandHashFile.parent_path().c_str(),&directory)==0) {
            const int parent=fic::core::openRootControlledDirectory(paths_.commandHashFile.parent_path(),error);
            if(parent<0)return false;
            ::close(parent);
            const auto lockPath=paths_.commandHashFile.string()+".lock";struct stat lockInfo{};
            if(::lstat(lockPath.c_str(),&lockInfo)==0) {
                if(!S_ISREG(lockInfo.st_mode)||lockInfo.st_uid||lockInfo.st_nlink!=1||(lockInfo.st_mode&0022))
                    return fail(error,"untrusted existing hash-store lock; refusing adoption");
            } else if(errno!=ENOENT)return fail(error,"cannot inspect hash-store lock");
            hashLock=std::make_unique<ExclusivePidLock>(paths_.commandHashFile.string()+".lock",paths_.lockDebugLogFile.string(),false);
            if(!hashLock->tryAcquire())return fail(error,"hash-store mutation busy; fence not published");
        } else if(errno!=ENOENT||operation!=PackageOperation::Install)
            return fail(error,"unprovable hash-store directory before lifecycle fence");
        if(!(state?store.begin(guard,*state,next,error):store.create(guard,next,error)))return false;
        if(!store.inspect(state,error))return false;
        hashLock.reset();
        if(!masks.publish(guard,id,error))return false;
    }
    if(!writers.stopAndProve(guard,masks,state->maskOperationId,images,
        std::chrono::steady_clock::now()+std::chrono::seconds(30),error))return false;
    if(state->phase==PackagePhase::Fencing) {
        if(!store.advance(guard,*state,PackagePhase::Quiescent,error)||!store.inspect(state,error))return false;
    }
    if(operation==PackageOperation::Upgrade&&state->phase==PackagePhase::Quiescent) {
        if(!store.advance(guard,*state,PackagePhase::Recovering,error)||!store.inspect(state,error))return false;
    }
    if(!store.confirmDurable(*state,error))return false;
    prepared=*state;return true;
}
}
