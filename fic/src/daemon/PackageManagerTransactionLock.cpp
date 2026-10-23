#include "daemon/PackageManagerTransactionLock.h"
#include <fic/core/fs/RootControlledDirectory.h>
#include <cerrno>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
namespace fic::daemon {
namespace {
std::mutex& processMutex() {static std::mutex mutex;return mutex;}
bool trustedFile(const struct stat& s) {
    return S_ISREG(s.st_mode) && s.st_uid==0 && s.st_gid==0 && s.st_nlink==1 &&
        (s.st_mode&0022)==0 && (s.st_mode&07000)==0;
}
int openExistingLock(const std::filesystem::path& path) {
    if(!path.is_absolute() || path.lexically_normal()!=path || path.filename().empty()) return -1;
    std::string error;
    int parent=fic::core::openRootControlledDirectory(path.parent_path(),error);
    if(parent<0) return -1;
    int fd=::openat(parent,path.filename().c_str(),O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    ::close(parent);return fd;
}
}
PackageManagerTransactionLock::~PackageManagerTransactionLock() {
    for(const auto& entry:entries_) ::close(entry.fd);
    // A fork-inherited object is not authority; do not unlock inherited mutex.
    if(owner_!=::getpid() && local_.owns_lock()) (void)local_.release();
}
bool PackageManagerTransactionLock::heldByCurrentProcess() const {
    return owner_==::getpid() && !entries_.empty() && local_.owns_lock();
}
bool PackageManagerTransactionLock::covers(fic::platform::PackageManagerKind kind) const {
    return heldByCurrentProcess()&&kind_==kind;
}
bool PackageManagerTransactionLock::revalidate(std::string& error) const {
    if(!heldByCurrentProcess()) {error="package locks not owned by this process";return false;}
    for(const auto& entry:entries_) {
        struct stat pinned{},named{};
        if(::fstat(entry.fd,&pinned) || ::lstat(entry.path.c_str(),&named) ||
            !trustedFile(pinned) || !trustedFile(named) || pinned.st_dev!=entry.device ||
            pinned.st_ino!=entry.inode || pinned.st_dev!=named.st_dev || pinned.st_ino!=named.st_ino) {
            error="package-manager lock identity/metadata changed";return false;
        }
    }
    error.clear();return true;
}
PackageManagerLockResult PackageManagerTransactionLock::tryAcquire(const DaemonInstanceLock& daemon,
    const fic::platform::PackageManagerPlatformConfig& config,std::string& error) {
    const bool knownShape=(config.kind==fic::platform::PackageManagerKind::Dpkg && config.transactionLocks.size()==2) ||
        (config.kind==fic::platform::PackageManagerKind::Rpm && config.transactionLocks.size()==1);
    if(!daemon.heldByCurrentProcess() || owner_!=-1 || !knownShape) {
        error="package-manager lock requires fresh exclusive daemon admission and known lock paths";
        return PackageManagerLockResult::Unprovable;
    }
    std::unique_lock<std::mutex> local(processMutex(),std::try_to_lock);
    if(!local.owns_lock()) {error="another finalizer in this process holds package locks";return PackageManagerLockResult::Busy;}
    std::vector<Entry> acquired;
    const auto fail=[&](PackageManagerLockResult result,const std::string& reason) {
        for(const auto& entry:acquired) ::close(entry.fd);
        error=reason;return result;
    };
    std::set<std::filesystem::path> seen;
    for(const auto& path:config.transactionLocks) {
        if(!seen.insert(path).second) return fail(PackageManagerLockResult::Unprovable,"duplicate package-manager lock path");
        int fd=openExistingLock(path);struct stat before{};
        if(fd<0) return fail(PackageManagerLockResult::Unprovable,"cannot open existing trusted package-manager lock");
        acquired.push_back({fd,path,0,0});
        if(::fstat(fd,&before) || !trustedFile(before))
            return fail(PackageManagerLockResult::Unprovable,"untrusted package-manager lock metadata");
        struct flock lock{};lock.l_type=F_WRLCK;lock.l_whence=SEEK_SET;
        if(::fcntl(fd,F_SETLK,&lock)<0) {
            const auto busy=errno==EACCES || errno==EAGAIN;
            return fail(busy ? PackageManagerLockResult::Busy : PackageManagerLockResult::Unprovable,
                        busy ? "package transaction still active" : "cannot acquire package-manager record lock");
        }
        acquired.back().device=before.st_dev;acquired.back().inode=before.st_ino;
    }
    entries_=std::move(acquired);owner_=::getpid();local_=std::move(local);kind_=config.kind;
    if(!revalidate(error)) {
        for(const auto& entry:entries_) ::close(entry.fd);
        entries_.clear();owner_=-1;local_.unlock();
        return PackageManagerLockResult::Unprovable;
    }
    return PackageManagerLockResult::Acquired;
}
}
