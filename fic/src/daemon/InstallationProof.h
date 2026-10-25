#pragma once
#include "daemon/DaemonInstanceLock.h"
#include "platform/PlatformExecutableResolver.h"
namespace fic::daemon {
// Read-only checks of preserved state, usable before stopping an installed daemon.
bool checkPackagePersistentState(std::string& error);
// Existing C2 read-only structural/ownership/semantic preflight; no undo.
bool checkPackagePasswordTopology(const fic::platform::PlatformProfile&,
    const fic::platform::PlatformExecutableResolver&,std::string& error);
// Closed completion under daemon.lock; no apply/release and no package DB wait.
bool completePackageInstallation(const DaemonInstanceLock&,
    const fic::platform::PlatformProfile&,std::string& error);
}
