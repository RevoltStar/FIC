#ifndef FIC_PACKAGE_PAM_HOOKS_H
#define FIC_PACKAGE_PAM_HOOKS_H
#include "daemon/DaemonInstanceLock.h"
#include "platform/PlatformExecutableResolver.h"
#include <chrono>
namespace fic::daemon {
// Fixed package infrastructure actions; policy state remains owned by the
// existing provider/password backends and must be released BEFORE this stage.
class PackagePamHooks {
public:
    explicit PackagePamHooks(const fic::platform::PlatformProfile& platform,
        std::filesystem::path selectionDirectory="/var/lib/pam")
        : platform_(platform),executables_(platform.executables),selection_(std::move(selectionDirectory)) {}
    bool detach(const DaemonInstanceLock&,std::chrono::steady_clock::time_point deadline,
        std::string& error) const;
    bool proveDetached(std::string& error) const;
private:
    bool inspectOtherHooks(bool& detached,std::string& error) const;
    bool removeProfiles(bool incident,std::chrono::steady_clock::time_point,std::string& error) const;
    const fic::platform::PlatformProfile& platform_;
    fic::platform::PlatformExecutableResolver executables_;
    std::filesystem::path selection_;
};
}
#endif
