#ifndef FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_LOCK_H
#define FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_LOCK_H

#include <fic/core/process/ExclusivePidLock.h>

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

namespace fic::identity::pam {

// Step 7F shared interprocess mutation lock domain for the managed provider
// configuration. The managed-entry apply (PamProviderManagedEntryExecutor),
// the managed-flag apply (PamProviderManagedFlagExecutor), the runtime
// provider rollback (PamProviderRollback) and the package provider release
// Stage B (PamProviderPackageRelease) all serialize on ONE lock file
// (<runtimeDir>/pam-provider-managed.lock), so a shared journal/file
// transition can never interleave between the daemon and a maintenance
// process. A single global PAM provider domain (not per-provider files):
// the executors mutate the same journal and the same physical files, and
// one domain keeps the concurrency contract simple and provable.
//
// Implementation is the project ExclusivePidLock primitive — no custom
// flock code. The debug log goes to the existing lock debug path. An
// in-process std::mutex does NOT protect the daemon against a maintenance
// process; this interprocess lock does (the in-process rollback mutex
// stays for the non-PAM backends that still rely on it).
//
// Lock path resolution: FicRuntimePaths when initialized (production),
// otherwise (unit-test environment without runtime paths) the lock is
// DISABLED (a no-op guard) so hermetic unit tests are unaffected. Lock
// domain tests set an explicit override path (setLockFilePathForTests).
class PamProviderManagedLock {
public:
    // Test-only override of the lock file path (production never calls).
    static void setLockFilePathForTests(const std::filesystem::path& path);
    static void resetLockFilePathForTests();

    // The production lock file path; empty when runtime paths are not
    // initialized (lock disabled).
    static std::filesystem::path lockFilePath();

    // RAII exclusive lock handle. A default (empty) handle is a no-op.
    class Handle {
    public:
        Handle() = default;
        ~Handle();
        Handle(Handle&& other) noexcept;
        Handle& operator=(Handle&& other) noexcept;
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

    private:
        friend class PamProviderManagedLock;
        explicit Handle(std::unique_ptr<ExclusivePidLock> lock);
        void release();
        std::unique_ptr<ExclusivePidLock> lock_;
    };

    // Fails immediately when another process holds the lock.
    static bool tryAcquire(Handle& handle, std::string& error);
    // Blocks until the lock becomes available.
    static bool acquire(Handle& handle, std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PROVIDER_MANAGED_LOCK_H