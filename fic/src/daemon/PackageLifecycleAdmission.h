#ifndef FIC_PACKAGE_LIFECYCLE_ADMISSION_H
#define FIC_PACKAGE_LIFECYCLE_ADMISSION_H
#include "daemon/PackageLifecycleState.h"
namespace fic::daemon {
// Deliberately outside the product installation tree, package payload and volatile runtime. Package
// purge must not own/remove this directory or its tombstone/provenance.
inline constexpr const char* PackageLifecycleDirectory="/var/lib/fic-lifecycle";
inline constexpr const char* PackageLifecycleStateFile="/var/lib/fic-lifecycle/state.json";
// Admission proves a previously finalized lifecycle, including a snapshot-bound
// durability barrier. It never creates/adopts/removes state or runs package proofs.
class PackageLifecycleAdmission {
public:
    explicit PackageLifecycleAdmission(std::filesystem::path file=PackageLifecycleStateFile):file_(std::move(file)) {}
    // Content-preserving proof, not an exclusive admission. Trust-sync must repeat
    // this observation inside its existing hash-store mutation lock.
    bool inspectInstalled(std::string& error) const;
    bool requireInstalled(const DaemonInstanceLock&,std::string& error) const;
private:
    std::filesystem::path file_;
};
}
#endif
