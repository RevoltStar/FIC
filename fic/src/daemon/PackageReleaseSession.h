#ifndef FIC_PACKAGE_RELEASE_SESSION_H
#define FIC_PACKAGE_RELEASE_SESSION_H
#include "daemon/PackageLifecycleState.h"
#include "daemon/PackageReleaseResources.h"
#include "daemon/PackageWritersQuiescence.h"
namespace fic::daemon {
struct PackageReleaseSessionPaths {
    std::filesystem::path fenceFile,maskDirectory,systemUnitDirectory;
};
// Closed fixed removal stages, still independent of package finalization.
// Resource stage leaves PasswordReleased; completeRelease leaves ReleaseComplete.
// The durable fence remains active until a separate post-transaction proof.
class PackageReleaseSession {
public:
    PackageReleaseSession(const fic::platform::PlatformProfile& platform,
        const fic::core::FicProductPaths& paths,PackageReleaseSessionPaths lifecycle)
        : platform_(platform),paths_(paths),lifecycle_(std::move(lifecycle)) {}
    bool preflight(std::string& error) const;
    // Entire admitted removal stage. ReleaseComplete still awaits actual
    // post-transaction package removal proof and never authorizes startup.
    bool completeRelease(const DaemonInstanceLock&,const std::string& operationId,std::string& error) const;
    bool releaseManagedResources(const DaemonInstanceLock&,const std::string& operationId,std::string& error) const;
    // Fresh independent read-only proof for deferred finalization. No journal
    // bootstrap, policy release, hook detach, compensation or fence transition.
    bool proveReleased(const DaemonInstanceLock&,std::string& error) const;
private:
    bool proveReleasedResources(std::string& error) const;
    const fic::platform::PlatformProfile& platform_;
    const fic::core::FicProductPaths& paths_;
    PackageReleaseSessionPaths lifecycle_;
};
}
#endif
