#ifndef FIC_PACKAGE_MANAGER_TRANSACTION_LOCK_H
#define FIC_PACKAGE_MANAGER_TRANSACTION_LOCK_H
#include "daemon/DaemonInstanceLock.h"
#include "platform/PlatformProfile.h"
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>
namespace fic::daemon {
enum class PackageManagerLockResult { Acquired, Busy, Unprovable };
// Actual package-manager POSIX record locks, not a FIC PID-file surrogate.
// Acquire only after daemon.lock; no blocking wait, no create/repair/unlink.
// Closing ANY descriptor for the same file releases process-scoped POSIX locks:
// callers must not independently open these files while this guard is held.
class PackageManagerTransactionLock {
public:
    PackageManagerTransactionLock() = default;
    ~PackageManagerTransactionLock();
    PackageManagerTransactionLock(const PackageManagerTransactionLock&) = delete;
    PackageManagerTransactionLock& operator=(const PackageManagerTransactionLock&) = delete;
    PackageManagerLockResult tryAcquire(const DaemonInstanceLock&,
        const fic::platform::PackageManagerPlatformConfig&, std::string& error);
    bool heldByCurrentProcess() const;
    bool covers(fic::platform::PackageManagerKind) const;
    bool revalidate(std::string& error) const;
private:
    struct Entry {int fd; std::filesystem::path path; dev_t device; ino_t inode;};
    std::vector<Entry> entries_;
    std::unique_lock<std::mutex> local_;
    pid_t owner_ = -1;
    fic::platform::PackageManagerKind kind_=fic::platform::PackageManagerKind::Dpkg;
};
}
#endif
