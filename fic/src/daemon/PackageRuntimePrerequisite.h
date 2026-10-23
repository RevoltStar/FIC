#ifndef FIC_PACKAGE_RUNTIME_PREREQUISITE_H
#define FIC_PACKAGE_RUNTIME_PREREQUISITE_H
#include "daemon/PackageDatabaseSnapshot.h"
namespace fic::daemon {
// Fixed production prerequisite. No argument can choose an alternate engine or
// override the compiled package identity. Does not prove lifecycle completion.
// Read-only pre-stop check; repeat after daemon admission before preparation.
bool proveExecutingPackageRuntime(const fic::platform::PlatformProfile&,const std::string& requestedPackageVersion,
    unsigned requestedAbi,std::string& error);
}
#endif
