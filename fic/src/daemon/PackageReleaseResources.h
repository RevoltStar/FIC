#ifndef FIC_PACKAGE_RELEASE_RESOURCES_H
#define FIC_PACKAGE_RELEASE_RESOURCES_H
#include "daemon/DaemonInstanceLock.h"
#include "modules/identity_access/pam/PamPasswordPackageRelease.h"
#include "modules/identity_access/pam/PamProviderPackageRelease.h"
#include "platform/PlatformExecutableResolver.h"
#include <fic/core/runtime/FicRuntimePaths.h>
namespace fic::daemon {
enum class PackageReleaseDomain { DisplayManager, Desktop, PamProvider, PamPassword, AltHistoryTopology, AltFaillockTopology };
struct PackageResourceReleaseReport {
    fic::identity::pam::PamProviderPackageRelease::Report provider;
    fic::identity::pam::PamPasswordPackageRelease::Report password;
};
// Shared fixed domain operations for legacy maintenance routes and the closed
// package-session. Existing domain backends remain the sole ownership engines.
// Never loads/initializes the journal: the caller supplies the correctly admitted
// journal, or a separately validated read-only preflight journal.
class PackageReleaseResources {
public:
    PackageReleaseResources(const fic::platform::PlatformProfile& platform,
        const fic::core::FicProductPaths& paths)
        : platform_(platform),paths_(paths),executables_(platform.executables) {}
    bool supports(PackageReleaseDomain,std::string& error) const;
    bool preflight(PackageReleaseDomain,fic::rollback::MutationJournal&,
        PackageResourceReleaseReport&,std::string& error) const;
    bool proveReleased(PackageReleaseDomain,fic::rollback::MutationJournal&,std::string& error) const;
    bool release(const DaemonInstanceLock&,PackageReleaseDomain,fic::rollback::MutationJournal&,
        PackageResourceReleaseReport&,std::string& error) const;
private:
    enum class Action { Preflight, Release, Proof };
    bool run(PackageReleaseDomain,fic::rollback::MutationJournal&,Action,
        PackageResourceReleaseReport&,std::string& error) const;
    const fic::platform::PlatformProfile& platform_;
    const fic::core::FicProductPaths& paths_;
    fic::platform::PlatformExecutableResolver executables_;
};
}
#endif
