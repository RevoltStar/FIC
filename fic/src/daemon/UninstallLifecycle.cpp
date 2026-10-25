#include "daemon/UninstallLifecycle.h"
#include <set>
namespace fic::daemon {
bool UninstallLifecycle::prepare(const DaemonInstanceLock& guard,std::string& error) const {
    if(!guard.heldByCurrentProcess()) {error="prepare-uninstall requires daemon.lock";return false;}
    const auto before=fic::core::readPackageState(file_);
    if(before.state==fic::core::PackageState::Uninstalling)
        return AtomicFileWriter::ensureTargetDurableIfCurrentState(file_.string(),before.file.targetState,&error);
    if(before.state!=fic::core::PackageState::Installed) {error="prepare-uninstall requires proven Installed state: "+before.file.detail;return false;}
    AtomicWriteOptions options;options.rejectSymlink=true;
    options.expectedTargetState=before.file.targetState;
    AtomicWriteResult result;
    return AtomicFileWriter::writeWithResult(file_.string(),"UNINSTALLING\n",options,&error,&result)&&result.durabilityConfirmed;
}
bool UninstallLifecycle::allowedRequest(const std::string& command) {
    static const std::set<std::string> allowed{"prepare_uninstall","rollback_all","shutdown",
        "status","boot_id","module_list","policy_list","policy_is_enabled",
        "policy_is_disabled","policy_value","localization_bundle","log_records"};
    return allowed.count(command)!=0;
}
}
