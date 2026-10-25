#include "daemon/PackageStateStore.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
using fic::core::PackageState;
bool fail(std::string& error,const std::string& text){error=text;return false;}
bool absent(const std::filesystem::path& file){struct stat info{};return ::lstat(file.c_str(),&info)<0&&errno==ENOENT;}
bool ensureStateDirectory(const std::filesystem::path& file,std::string& error) {
    // The directory itself is persistent state. Never repair its ownership or
    // traverse aliases. Creation and the directory entry both become durable.
    const auto directory=file.parent_path();
    const int parent=fic::core::openRootControlledDirectory(directory.parent_path(),error);
    if(parent<0)return false;
    const int created=::mkdirat(parent,directory.filename().c_str(),0700);
    const int saved=errno;
    const int fd=::openat(parent,directory.filename().c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(created==0&&fd>=0&&::fchown(fd,0,0)!=0) {
        ::close(fd);::close(parent);return fail(error,"new package state directory ownership failed");
    }
    struct stat info{};
    const bool proven=fd>=0&&::fstat(fd,&info)==0&&info.st_uid==0&&info.st_gid==0&&(info.st_mode&07777)==0700;
    const bool durable=proven&&::fsync(fd)==0&&::fsync(parent)==0;
    if(fd>=0)::close(fd);
    ::close(parent);
    if(created&&saved!=EEXIST)return fail(error,"cannot create package state directory: "+std::string(std::strerror(saved)));
    if(!durable)return fail(error,"package state directory is not durable");
    return true;
}
}
bool PackageStateStore::publish(const DaemonInstanceLock& guard,const fic::core::PackageStateSnapshot& before,
    PackageState next,std::string& error) const {
    if(!guard.heldByCurrentProcess())return fail(error,"state publication requires daemon.lock");
    if(before.file.status!=fic::core::SecureStateReadStatus::Proven&&before.file.status!=fic::core::SecureStateReadStatus::Missing)
        return fail(error,"package lifecycle state is unprovable: "+before.file.detail);
    AtomicWriteOptions options;options.rejectSymlink=true;options.fileMode=0600;options.fileOwner=0;options.fileGroup=0;
    if(before.file.status==fic::core::SecureStateReadStatus::Proven)
        options.expectedTargetState=before.file.targetState;
    options.createIfMissing=true;options.exclusiveCreate=before.file.status==fic::core::SecureStateReadStatus::Missing;
    AtomicWriteResult result;
    return AtomicFileWriter::writeWithResult(file_.string(),std::string(fic::core::packageStateName(next))+"\n",options,&error,&result)&&result.durabilityConfirmed;
}
bool PackageStateStore::beginInstallation(const DaemonInstanceLock& guard,const fic::core::FicProductPaths& paths,std::string& error) const {
    if(!guard.heldByCurrentProcess())return fail(error,"installation requires daemon.lock");
    if(!ensureStateDirectory(file_,error))return false;
    const auto before=fic::core::readPackageState(file_);
    if(before.file.status==fic::core::SecureStateReadStatus::Missing) {
        if(!absent(paths.configDir)||!absent(paths.lockStatusFile)||!absent(paths.mutationJournalFile)||!absent(paths.mutationJournalFile.string()+".initialized"))
            return fail(error,"missing lifecycle proof with existing configuration/journal; automatic adoption is refused");
    } else if(!before.state||*before.state==PackageState::Uninstalling)
        return fail(error,"installation cannot cancel uninstall or repair unknown lifecycle state");
    if(before.state==PackageState::Installing)
        return AtomicFileWriter::ensureTargetDurableIfCurrentState(file_.string(),before.file.targetState,&error);
    return publish(guard,before,PackageState::Installing,error);
}
bool PackageStateStore::completeInstallation(const DaemonInstanceLock& guard,std::string& error) const {
    const auto before=fic::core::readPackageState(file_);
    if(before.state!=PackageState::Installing)return fail(error,"installation completion requires INSTALLING");
    return publish(guard,before,PackageState::Installed,error);
}
bool PackageStateStore::fenceRemoval(const DaemonInstanceLock& guard,std::string& error) const {
    if(!guard.heldByCurrentProcess())return fail(error,"removal fencing requires daemon.lock");
    if(!ensureStateDirectory(file_,error))return false;
    const auto before=fic::core::readPackageState(file_);
    // Missing state already prohibits normal startup. A restrictive emergency
    // fence is not adoption of any policy ownership/configuration or proof of
    // daemon preparation. Unknown/unsafe existing state is never overwritten.
    if(before.file.status==fic::core::SecureStateReadStatus::Missing)
        return publish(guard,before,PackageState::Uninstalling,error);
    if(!before.state)return fail(error,"removal fencing requires trusted package lifecycle state");
    if(before.state==PackageState::Uninstalling||before.state==PackageState::Removed)
        return guard.heldByCurrentProcess()&&AtomicFileWriter::ensureTargetDurableIfCurrentState(file_.string(),before.file.targetState,&error);
    return publish(guard,before,PackageState::Uninstalling,error);
}
bool PackageStateStore::completeRemoval(const DaemonInstanceLock& guard,std::string& error) const {
    if(!guard.heldByCurrentProcess())return fail(error,"removal completion requires daemon.lock");
    const auto before=fic::core::readPackageState(file_);
    if(before.state!=PackageState::Uninstalling&&before.state!=PackageState::Removed)
        return fail(error,"removal completion requires trusted restrictive removal state");
    if(before.state==PackageState::Removed)
        return guard.heldByCurrentProcess()&&AtomicFileWriter::ensureTargetDurableIfCurrentState(file_.string(),before.file.targetState,&error);
    return publish(guard,before,PackageState::Removed,error);
}
}
