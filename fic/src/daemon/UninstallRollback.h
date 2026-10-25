#pragma once
#include "daemon/DaemonInstanceLock.h"
#include "policy/registry/PolicyRegistry.h"
#include "rollback/RollbackExecutor.h"
#include <nlohmann/json.hpp>
namespace fic::daemon {
// Daemon-only orchestration over existing release backends. Never changes
// desired policy configuration; never callable by a package helper.
nlohmann::json rollbackAllForUninstall(PolicyRegistry&,const DaemonInstanceLock&,
    const fic::platform::PlatformProfile&,const fic::platform::PlatformExecutableResolver&);
}
