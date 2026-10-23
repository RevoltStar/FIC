#include "daemon/PackageLifecycleAdmission.h"
namespace fic::daemon {
bool PackageLifecycleAdmission::requireInstalled(const DaemonInstanceLock& guard,std::string& error) const {
    if(!guard.heldByCurrentProcess()){error="lifecycle admission requires daemon.lock";return false;}
    return inspectInstalled(error);
}
bool PackageLifecycleAdmission::inspectInstalled(std::string& error) const {
    std::optional<PackageLifecycleState> state;
    if(!PackageLifecycleStore(file_).inspect(state,error)) {
        error="lifecycle fence is unprovable: "+error;return false;
    }
    if(!state){error="lifecycle completion proof is absent; closed package installation/recovery required";return false;}
    if(state->phase!=PackagePhase::Installed) {
        error="lifecycle fence active (phase="+std::to_string(static_cast<unsigned>(state->phase))+
            "); daemon and standalone policy mutations are refused";return false;
    }
    return PackageLifecycleStore(file_).confirmDurable(*state,error);
}
}
