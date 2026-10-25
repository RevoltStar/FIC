#ifndef FIC_PACKAGE_WRITERS_QUIESCENCE_H
#define FIC_PACKAGE_WRITERS_QUIESCENCE_H
#include "daemon/DaemonInstanceLock.h"
#include "daemon/PackageWriterProcesses.h"
#include "platform/PlatformExecutableResolver.h"
namespace fic::daemon {
// Fixed maintenance operations, not an arbitrary command executor. Bootstrap
// uses the existing trusted platform resolver + ProcessExecutor, independently
// of policy command-hash bootstrap (as package trust sync already does).
class PackageWritersQuiescence {
public:
    explicit PackageWritersQuiescence(const fic::platform::PlatformExecutableResolver& executables)
        : executables_(executables) {}
    bool provePreloginStopped(std::chrono::steady_clock::time_point deadline,std::string& error) const;
    bool validateEnvironment(std::string& error) const;
    // Fixed stop request before admission: the running cooperative daemon
    // holds daemon.lock itself. This method NEVER opens journal/fence/resources.
    // Caller must still acquire admission and repeat all proofs before release.
    bool requestStopBeforeAdmission(std::chrono::steady_clock::time_point deadline,std::string& error) const;
    // Called by the live daemon after durable UNINSTALLING publication. Never
    // stops fic.service itself; waits for auxiliary writers and their cgroups.
    bool stopAuxiliaryWriters(std::chrono::steady_clock::time_point deadline,std::string& error) const;
    bool proveStopped(const DaemonInstanceLock&,const std::vector<LegacyWriterImage>&,
        std::chrono::steady_clock::time_point deadline,std::string& error) const;
private:
    const fic::platform::PlatformExecutableResolver& executables_;
};
}
#endif
