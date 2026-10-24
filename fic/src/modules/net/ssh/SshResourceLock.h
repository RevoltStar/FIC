#pragma once
#include <mutex>
// Shared main sshd_config resource: apply and the entire disable/undo decision.
// This is process-local; daemon admission supplies the separate singleton contract.
inline std::mutex& sshResourceMutex() {
    static std::mutex mutex;
    return mutex;
}
