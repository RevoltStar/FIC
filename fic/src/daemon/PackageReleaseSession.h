#ifndef FIC_PACKAGE_RELEASE_SESSION_H
#define FIC_PACKAGE_RELEASE_SESSION_H
#include "daemon/PackageLifecycleState.h"
#include "daemon/PackageReleaseResources.h"
#include "daemon/PackageWritersQuiescence.h"
namespace fic::daemon {
struct PackageReleaseSessionPaths {
    std::filesystem::path fenceFile,maskDirectory,systemUnitDirectory;
};
// Fixed resource stage of the closed package-session. This is NOT finalization:
// success leaves PasswordReleased with the durable fence active. Hook detach,
// final domain proofs and post-transaction removal proof are separate stages.
class PackageReleaseSession {
public:
    PackageReleaseSession(const fic::platform::PlatformProfile& platform,
        const fic::core::FicProductPaths& paths,PackageReleaseSessionPaths lifecycle)
        : platform_(platform),paths_(paths),lifecycle_(std::move(lifecycle)) {}
    bool preflight(std::string& error) const;
    bool releaseManagedResources(const DaemonInstanceLock&,const std::string& operationId,std::string& error) const;
private:
    const fic::platform::PlatformProfile& platform_;
    const fic::core::FicProductPaths& paths_;
    PackageReleaseSessionPaths lifecycle_;
};
}
#endif
