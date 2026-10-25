#include "daemon/PackageLifecycleAdmission.h"
#include <fic/core/runtime/PackageState.h>
namespace fic::daemon {
bool PackageLifecycleAdmission::requireInstalled(const DaemonInstanceLock& guard,std::string& error) const {
    if(!guard.heldByCurrentProcess()){error="lifecycle admission requires daemon.lock";return false;}
    return inspectInstalled(error);
}
bool PackageLifecycleAdmission::inspectInstalled(std::string& error) const {
    return fic::core::requireInstalledPackage(error,file_);
}
}
