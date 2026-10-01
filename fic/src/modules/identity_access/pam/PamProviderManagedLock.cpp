#include "modules/identity_access/pam/PamProviderManagedLock.h"

#include <fic/core/process/ExclusivePidLock.h>
#include <fic/core/runtime/FicRuntimePaths.h>

namespace fic::identity::pam {

namespace {

std::mutex& overrideMutex() {
    static std::mutex mutex;
    return mutex;
}

std::filesystem::path& overridePath() {
    static std::filesystem::path path;
    return path;
}

std::string lockDebugLogPath() {
    if (!fic::core::FicRuntimePaths::isInitialized()) {
        return {};
    }
    return fic::core::FicRuntimePaths::get().lockDebugLogFile.string();
}

} // namespace

void PamProviderManagedLock::setLockFilePathForTests(
    const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(overrideMutex());
    overridePath() = path;
}

void PamProviderManagedLock::resetLockFilePathForTests() {
    std::lock_guard<std::mutex> lock(overrideMutex());
    overridePath().clear();
}

std::filesystem::path PamProviderManagedLock::lockFilePath() {
    {
        std::lock_guard<std::mutex> lock(overrideMutex());
        if (!overridePath().empty()) {
            return overridePath();
        }
    }
    if (!fic::core::FicRuntimePaths::isInitialized()) {
        return {};
    }
    return fic::core::FicRuntimePaths::get().runtimeDir /
        "pam-provider-managed.lock";
}

PamProviderManagedLock::Handle::Handle(
    std::unique_ptr<class ExclusivePidLock> lock)
    : lock_(std::move(lock)) {}

PamProviderManagedLock::Handle::~Handle() {
    release();
}

PamProviderManagedLock::Handle::Handle(Handle&& other) noexcept
    : lock_(std::move(other.lock_)) {}

PamProviderManagedLock::Handle& PamProviderManagedLock::Handle::operator=(
    Handle&& other) noexcept {
    if (this != &other) {
        release();
        lock_ = std::move(other.lock_);
    }
    return *this;
}

void PamProviderManagedLock::Handle::release() {
    if (lock_ != nullptr) {
        lock_->release();
        lock_.reset();
    }
}

bool PamProviderManagedLock::tryAcquire(Handle& handle, std::string& error) {
    handle = Handle();
    const std::filesystem::path path = lockFilePath();
    if (path.empty()) {
        // No runtime paths (hermetic unit-test environment): the lock is a
        // documented no-op here. Production always has runtime paths.
        return true;
    }
    std::unique_ptr<ExclusivePidLock> lock =
        std::make_unique<ExclusivePidLock>(
            path.string(), lockDebugLogPath(), /*enableDebug=*/true);
    if (!lock->tryAcquire()) {
        error = "managed provider mutation lock is held by another process: " +
            path.string();
        return false;
    }
    handle = Handle(std::move(lock));
    return true;
}

bool PamProviderManagedLock::acquire(Handle& handle, std::string& error) {
    handle = Handle();
    const std::filesystem::path path = lockFilePath();
    if (path.empty()) {
        return true;
    }
    std::unique_ptr<ExclusivePidLock> lock =
        std::make_unique<ExclusivePidLock>(
            path.string(), lockDebugLogPath(), /*enableDebug=*/true);
    if (!lock->acquire()) {
        error = "could not acquire the managed provider mutation lock: " +
            path.string();
        return false;
    }
    handle = Handle(std::move(lock));
    return true;
}

} // namespace fic::identity::pam