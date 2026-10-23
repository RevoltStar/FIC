#ifndef FIC_PACKAGE_LIFECYCLE_COORDINATOR_H
#define FIC_PACKAGE_LIFECYCLE_COORDINATOR_H
#include "daemon/PackageLifecycleAdmission.h"
#include "daemon/PackageWritersQuiescence.h"
#include <fic/core/runtime/FicRuntimePaths.h>
namespace fic::daemon {
struct PackageLifecycleLocations {
    std::filesystem::path stateDirectory=PackageLifecycleDirectory;
    std::filesystem::path systemUnitDirectory="/etc/systemd/system";
    std::filesystem::path runtimeExecutable="/usr/libexec/fic/fic-runtime";
};
// Closed orchestration over existing domain engines. Preparation never applies
// or reconstructs policy ownership. Runtime prerequisite/manifest validation
// belongs to the fixed package entrypoint before this admitted stage.
class PackageLifecycleCoordinator {
public:
    PackageLifecycleCoordinator(const fic::platform::PlatformProfile& platform,
        const fic::core::FicProductPaths& paths,PackageLifecycleLocations locations={})
        :platform_(platform),paths_(paths),locations_(std::move(locations)) {}
    bool requestStopBeforeAdmission(std::string& error) const;
    bool prepare(const DaemonInstanceLock&,PackageOperation,const std::string& expectedPackageVersion,
        PackageLifecycleState& prepared,std::string& error) const;
private:
    const fic::platform::PlatformProfile& platform_;
    const fic::core::FicProductPaths& paths_;
    PackageLifecycleLocations locations_;
};
}
#endif
