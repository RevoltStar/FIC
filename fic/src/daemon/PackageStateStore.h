#pragma once
#include "daemon/DaemonInstanceLock.h"
#include <fic/core/runtime/PackageState.h>
#include <fic/core/runtime/FicRuntimePaths.h>
namespace fic::daemon {
// Minimal state publisher. Callers must hold daemon.lock and perform the
// corresponding infrastructure proofs before completing install/removal.
// This class never applies or releases a policy.
class PackageStateStore {
public:
    explicit PackageStateStore(std::filesystem::path file=fic::core::PACKAGE_STATE_FILE):file_(std::move(file)){}
    bool beginInstallation(const DaemonInstanceLock&,const fic::core::FicProductPaths&,std::string& error) const;
    bool completeInstallation(const DaemonInstanceLock&,std::string& error) const;
    // Infrastructure exclusion after emergency daemon-stage skips. This is
    // restrictive admission only, never proof of daemon prepare or rollback.
    bool fenceRemoval(const DaemonInstanceLock&,std::string& error) const;
    bool completeRemoval(const DaemonInstanceLock&,std::string& error) const;
private:
    bool publish(const DaemonInstanceLock&,const fic::core::PackageStateSnapshot&,fic::core::PackageState,std::string&) const;
    std::filesystem::path file_;
};
}
