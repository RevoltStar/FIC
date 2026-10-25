#include <fic/core/runtime/PackageState.h>
#include <fic/core/fs/RootControlledDirectory.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::core {
const char* packageStateName(PackageState state) {
    switch(state) {
    case PackageState::Installing: return "INSTALLING";
    case PackageState::Installed: return "INSTALLED";
    case PackageState::Uninstalling: return "UNINSTALLING";
    case PackageState::Removed: return "REMOVED";
    }
    return "INVALID";
}
PackageStateSnapshot readPackageState(const std::filesystem::path& path) {
    PackageStateSnapshot result;
    std::string error;
    const int parent=openRootControlledDirectory(path.parent_path(),error);
    if(parent<0) {
        // A fresh dependency-only installation has no lifecycle directory.
        // Distinguish a proven missing leaf from an unsafe ancestor; neither
        // grants startup permission. Only the closed installer may create it.
        std::string ancestorError;
        const auto directory=path.parent_path();
        const int ancestor=openRootControlledDirectory(directory.parent_path(),ancestorError);
        if(ancestor>=0) {
            struct stat info{};
            if(directory.is_absolute()&&directory==directory.lexically_normal()&&
               ::fstatat(ancestor,directory.filename().c_str(),&info,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT)
                result.file.status=SecureStateReadStatus::Missing;
            ::close(ancestor);
        }
        result.file.detail=error;return result;
    }
    ::close(parent);
    SecureStateFileExpectation expected;
    expected.owner=0;expected.group=0;expected.exactMode=0600;
    expected.parentOwner=0;expected.parentGroup=0;expected.exactParentMode=0700;
    expected.requireSingleLink=true;expected.maxSize=32;
    result.file=readSecureStateFile(path,expected);
    if(result.file.status!=SecureStateReadStatus::Proven)return result;
    for(auto state:{PackageState::Installing,PackageState::Installed,PackageState::Uninstalling,PackageState::Removed})
        if(result.file.content==std::string(packageStateName(state))+"\n") {result.state=state;return result;}
    result.file.status=SecureStateReadStatus::Unprovable;
    result.file.detail="unknown or damaged package lifecycle state";
    return result;
}
bool requireInstalledPackage(std::string& error,const std::filesystem::path& path) {
    const auto current=readPackageState(path);
    if(current.state!=PackageState::Installed) {
        error=current.state ? std::string("package lifecycle: ")+packageStateName(*current.state) :
            "package lifecycle is unproven: "+current.file.detail;
        return false;
    }
    return AtomicFileWriter::ensureTargetDurableIfCurrentState(path.string(),current.file.targetState,&error);
}
}
