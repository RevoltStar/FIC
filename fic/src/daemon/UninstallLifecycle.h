#pragma once
#include "daemon/DaemonInstanceLock.h"
#include <fic/core/runtime/PackageState.h>

namespace fic::daemon {
// State publication only, never policy rollback. The single-threaded daemon
// event loop drains each request before accepting the next one.
class UninstallLifecycle {
public:
    explicit UninstallLifecycle(std::filesystem::path file=fic::core::PACKAGE_STATE_FILE):file_(std::move(file)) {}
    bool prepare(const DaemonInstanceLock&,std::string& error) const;
    static bool allowedRequest(const std::string& command);
private:
    std::filesystem::path file_;
};
}
