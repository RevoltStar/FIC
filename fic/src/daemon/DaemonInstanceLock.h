#ifndef FIC_DAEMON_INSTANCE_LOCK_H
#define FIC_DAEMON_INSTANCE_LOCK_H

#include <filesystem>
#include <string>
#include <sys/types.h>

namespace fic::daemon {

// Lifetime lock, independent of administrative socket placement. No PID-file
// ownership inference, metadata repair, unlink-on-exit or recursive acquisition.
class DaemonInstanceLock {
public:
    DaemonInstanceLock() = default;
    ~DaemonInstanceLock();
    DaemonInstanceLock(const DaemonInstanceLock&) = delete;
    DaemonInstanceLock& operator=(const DaemonInstanceLock&) = delete;
    bool heldByCurrentProcess() const;
    bool tryAcquire(const std::filesystem::path& runtimeDirectory, std::string& error);

private:
    int descriptor_ = -1;
    pid_t ownerProcess_ = -1;
};

} // namespace fic::daemon
#endif
