#include "ExclusivePidLock.h"

std::map<std::string, ExclusivePidSharedLockState> ExclusivePidLock::globalLockMap_;
std::mutex ExclusivePidLock::globalLockMapMutex_;
