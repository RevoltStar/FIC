#ifndef EXCLUSIVEPIDLOCK_H
#define EXCLUSIVEPIDLOCK_H

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string>
#include <sys/file.h>
#include <sys/types.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>
#include <mutex>
#include <iostream>
#include <fstream>
#include <map>
#include <fic/core/FileStats.h>

struct ExclusivePidSharedLockState {
    int fd;
    int refCount;
};

class ExclusivePidLock {
public:
    ExclusivePidLock(const std::string& lockFilePath,
                     const std::string& debugLogFilePath,
                     bool enableDebug = true)
        : lockFilePath_(lockFilePath), lockFileDescriptor_(-1),
          isLocked_(false), enableDebug_(enableDebug), logFile_(debugLogFilePath) {
        if (enableDebug_) {
            debugLog("ExclusivePidLock created for: " + lockFilePath);
        }
    }

    ~ExclusivePidLock() {
        if (enableDebug_) {
            debugLog("ExclusivePidLock destroyed, PID: " + std::to_string(getpid()));
        }
        release();
    }

    bool tryAcquire() {
        return acquireInternal(true);
    }

    bool acquire() {
        return acquireInternal(false);
    }

    void release() {
        if (isLocked_ && lockFileDescriptor_ != -1) {
            if (enableDebug_) {
                debugLog("Releasing lock, PID: " + std::to_string(getpid()));
            }

            bool shouldCloseFd = true;
            {
                std::lock_guard<std::mutex> lock(globalLockMapMutex_);
                auto it = globalLockMap_.find(lockFilePath_);
                if (it != globalLockMap_.end() && it->second.fd == lockFileDescriptor_) {
                    if (it->second.refCount > 1) {
                        --it->second.refCount;
                        shouldCloseFd = false;
                        if (enableDebug_) {
                            debugLog("Shared lock is still used in this process, refCount=" +
                                     std::to_string(it->second.refCount));
                        }
                    } else {
                        globalLockMap_.erase(it);
                    }
                }
            }

            if (shouldCloseFd) {
                if (lseek(lockFileDescriptor_, 0, SEEK_SET) != -1) {
                    if (ftruncate(lockFileDescriptor_, 0) != 0) {
                        debugLog("Failed to truncate lock file on release: " + std::string(strerror(errno)));
                    }
                    fsync(lockFileDescriptor_);
                }

                flock(lockFileDescriptor_, LOCK_UN);
                close(lockFileDescriptor_);
            }

            lockFileDescriptor_ = -1;
            isLocked_ = false;

            if (enableDebug_) {
                debugLog("Lock released successfully");
            }
        } else if (lockFileDescriptor_ != -1) {
            debugLog("Closing file descriptor without lock");
            close(lockFileDescriptor_);
            lockFileDescriptor_ = -1;
        }
    }

    bool isLocked() const {
        return isLocked_;
    }

    const std::string& getLockFilePath() const {
        return lockFilePath_;
    }

private:
    std::string lockFilePath_;
    int lockFileDescriptor_;
    bool isLocked_;
    bool enableDebug_;
    std::string logFile_;

    static std::map<std::string, ExclusivePidSharedLockState> globalLockMap_;
    static std::mutex globalLockMapMutex_;

    void debugLog(const std::string& message) const {
        if (!enableDebug_) return;

        std::ofstream log(logFile_, std::ios_base::app);
        if (!log.is_open()) {
            std::cerr << "[LOCK_DEBUG][" << getTimestamp() << "] PID " << getpid()
                      << ": " << message << std::endl;
            return;
        }

        log << "[" << getTimestamp() << "] PID " << getpid()
            << " FD " << lockFileDescriptor_
            << " LOCKED " << (isLocked_ ? "Y" : "N")
            << ": " << message << std::endl;
        log.close();
    }

    std::string getTimestamp() const {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%H:%M:%S");
        return oss.str();
    }

    bool acquireInternal(bool nonBlocking) {
        if (isLocked_) {
            debugLog("Already locked (instance level), returning true");
            return true;
        }

        debugLog("Attempting to acquire lock (nonBlocking=" + std::to_string(nonBlocking) + ")");

        {
            std::lock_guard<std::mutex> lock(globalLockMapMutex_);
            auto it = globalLockMap_.find(lockFilePath_);
            if (it != globalLockMap_.end()) {
                if (fcntl(it->second.fd, F_GETFD) != -1) {
                    ++it->second.refCount;
                    debugLog("Already holding lock on this file in this process (FD: " +
                             std::to_string(it->second.fd) + "), reusing, refCount=" +
                             std::to_string(it->second.refCount));
                    lockFileDescriptor_ = it->second.fd;
                    isLocked_ = true;
                    return true;
                } else {
                    debugLog("Stale file descriptor found, removing from shared map");
                    globalLockMap_.erase(it);
                }
            }
        }

        lockFileDescriptor_ = open(lockFilePath_.c_str(), O_RDWR | O_CREAT, 0644);
        if (lockFileDescriptor_ == -1) {
            debugLog("Failed to open lock file: " + std::string(strerror(errno)));
            return false;
        }

        FileStats fs(lockFilePath_);

        bool ficExists = FileStats::group_exists("fic");
        std::string targetGroup = ficExists ? "fic" : "root";

        if (fs._group != targetGroup) {
            if (!fs.change_owner_group(lockFilePath_, "root", targetGroup)) {
                debugLog("Failed to update owner/group for lock file");
            }
        }

        mode_t permissions = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
        if (!fs.change_permissions(lockFilePath_, permissions)) {
            debugLog("Failed to update permissions for lock file");
        }

        debugLog("Lock file opened, FD: " + std::to_string(lockFileDescriptor_));

        int flockOperation = LOCK_EX;
        if (nonBlocking) {
            flockOperation |= LOCK_NB;
        }

        debugLog("Calling flock with operation: " + std::to_string(flockOperation));

        if (flock(lockFileDescriptor_, flockOperation) == -1) {
            if (errno == EWOULDBLOCK && nonBlocking) {
                debugLog("Lock is already held by another process");
            } else {
                debugLog("flock failed: " + std::string(strerror(errno)) +
                         " (errno=" + std::to_string(errno) + ")");
            }

            close(lockFileDescriptor_);
            lockFileDescriptor_ = -1;
            return false;
        }

        debugLog("flock acquired successfully");

        pid_t storedPid = readStoredPid();
        pid_t currentPid = getpid();

        debugLog("Stored PID: " + std::to_string(storedPid) +
                 ", current PID: " + std::to_string(currentPid));

        if (storedPid == currentPid) {
            debugLog("PID matches current process, lock acquired");
            isLocked_ = true;

            {
                std::lock_guard<std::mutex> lock(globalLockMapMutex_);
                globalLockMap_[lockFilePath_] = {lockFileDescriptor_, 1};
            }

            return true;
        }

        if (storedPid != 0) {
            bool alive = isProcessAlive(storedPid);
            debugLog("Process " + std::to_string(storedPid) +
                     (alive ? " is alive" : " is dead"));

            if (alive) {
                debugLog("Another process is still alive, cannot acquire lock");
                flock(lockFileDescriptor_, LOCK_UN);
                close(lockFileDescriptor_);
                lockFileDescriptor_ = -1;
                return false;
            } else {
                debugLog("Stale PID found, clearing lock file");
                lseek(lockFileDescriptor_, 0, SEEK_SET);
                if (ftruncate(lockFileDescriptor_, 0) != 0) {
                    debugLog("Failed to truncate stale PID lock file: " + std::string(strerror(errno)));
                }
            }
        } else {
            debugLog("No PID stored in lock file");
        }

        if (writePid(currentPid)) {
            debugLog("Current PID written successfully");
            isLocked_ = true;

            {
                std::lock_guard<std::mutex> lock(globalLockMapMutex_);
                globalLockMap_[lockFilePath_] = {lockFileDescriptor_, 1};
            }

            debugLog("Lock acquired successfully");
            return true;
        } else {
            debugLog("Failed to write PID into lock file");

            flock(lockFileDescriptor_, LOCK_UN);
            close(lockFileDescriptor_);
            lockFileDescriptor_ = -1;
            return false;
        }
    }

    pid_t readStoredPid() const {
        if (lockFileDescriptor_ == -1) {
            return 0;
        }

        off_t originalPos = lseek(lockFileDescriptor_, 0, SEEK_CUR);
        if (lseek(lockFileDescriptor_, 0, SEEK_SET) == -1) {
            return 0;
        }

        char buffer[32];
        ssize_t bytesRead = read(lockFileDescriptor_, buffer, sizeof(buffer) - 1);
        if (bytesRead <= 0) {
            if (originalPos != -1) {
                lseek(lockFileDescriptor_, originalPos, SEEK_SET);
            }
            return 0;
        }

        buffer[bytesRead] = '\0';

        if (originalPos != -1) {
            lseek(lockFileDescriptor_, originalPos, SEEK_SET);
        }

        pid_t pid = 0;
        sscanf(buffer, "%d", &pid);
        return pid;
    }

    bool writePid(pid_t pid) {
        if (lockFileDescriptor_ == -1) {
            return false;
        }

        if (lseek(lockFileDescriptor_, 0, SEEK_SET) == -1) {
            return false;
        }

        char buffer[32];
        int len = snprintf(buffer, sizeof(buffer), "%d\n", pid);
        if (len <= 0 || len >= (int)sizeof(buffer)) {
            return false;
        }

        ssize_t written = write(lockFileDescriptor_, buffer, len);
        if (written != len) {
            return false;
        }

        if (ftruncate(lockFileDescriptor_, len) == -1) {
            return false;
        }

        fsync(lockFileDescriptor_);
        return true;
    }

    bool isProcessAlive(pid_t pid) const {
        if (pid <= 0) return false;
        int result = kill(pid, 0);
        if (result == 0) return true;
        if (errno == ESRCH) return false;
        if (errno == EPERM) return true;
        return false;
    }
};

#endif // EXCLUSIVEPIDLOCK_H
