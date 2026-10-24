#include "service/VerifiedConfigActivationProof.h"
#include "service/VerifiedConfigServiceActivator.h"
#include "service/VerifiedConfigMountSupport.h"
#include "service/VerifiedConfigSystemd.h"
#include "service/VerifiedConfigLaunchContract.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <unistd.h>

namespace fic::service {
namespace {
using namespace detail;
struct Hooks {
#ifdef FIC_ACTIVATOR_TESTING
    const TestHooks* tests = nullptr;
    int fault(const std::string& action, std::size_t index) const {
        return tests && tests->fault ? tests->fault(action, index) : 0;
    }
    void checkpoint(TestPhase phase, const std::string& path) const {
        if (tests && tests->checkpoint) tests->checkpoint(phase, path);
    }
#else
    int fault(const std::string&, std::size_t) const { return 0; }
#endif
};
[[noreturn]] void osFailure(ActivationStatus status, const std::string& message) {
    throw Failure(status, message + ": " + std::strerror(errno));
}
Fd ensureDirectory(const std::filesystem::path& path, mode_t mode) {
    if (path == path.root_path()) return openAbsolute(path, O_RDONLY|O_DIRECTORY);
    auto parent = ensureDirectory(path.parent_path(), 0750);
    if (::mkdirat(parent.get(), path.filename().c_str(), mode) != 0 && errno != EEXIST)
        osFailure(ActivationStatus::SnapshotFailed, "create private runtime directory");
    Fd fd(::openat(parent.get(), path.filename().c_str(), O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    if (!fd) osFailure(ActivationStatus::UnsupportedConfiguration, "open runtime directory");
    const auto st = identity(fd.get());
    if (st.uid != 0 || (st.mode & 0022))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "runtime directory is not root-controlled");
    return fd;
}
bool capable() {
    if (::geteuid() != 0) return false;
    std::ifstream input("/proc/self/status"); std::string line;
    while (std::getline(input, line)) if (line.rfind("CapEff:\t", 0) == 0) {
        try { return (std::stoull(line.substr(8), nullptr, 16) & (1ULL << 21)) != 0; } catch (...) { return false; }
    }
    return false;
}
void requireWritableDenied(const std::string& path, ControlledPathKind kind, const Identity& expected) {
    auto pinned = openAbsolute(path, kind == ControlledPathKind::Directory ? O_RDONLY|O_DIRECTORY : O_PATH);
    const auto observed = identity(pinned.get());
    if (observed.mount != expected.mount || !sameObject(observed, expected))
        throw Failure(ActivationStatus::InterferenceDetected, "write proof refuses replaced snapshot");
    if (kind == ControlledPathKind::File) {
        const int fd = ::open(fdPath(pinned.get()).c_str(), O_WRONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd >= 0) { ::close(fd); throw Failure(ActivationStatus::InterferenceDetected, "snapshot allowed writable open"); }
        if (errno != EROFS) osFailure(ActivationStatus::InterferenceDetected, "read-only write-denial proof failed");
    } else {
        const int root = pinned.get();
        const auto prefix = ".fic-ro-proof-" + std::to_string(::getpid()) + "-";
        std::string name = prefix + "0";
        struct stat exists{};
        for (unsigned i = 0; ::fstatat(root, name.c_str(), &exists, AT_SYMLINK_NOFOLLOW) == 0; ++i) {
            if (i > 8192) throw Failure(ActivationStatus::InterferenceDetected, "write-proof name limit");
            name = prefix + std::to_string(i + 1);
        }
        if (errno != ENOENT) osFailure(ActivationStatus::InterferenceDetected, "write-proof lookup");
        const int fd = ::openat(root, name.c_str(), O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0600);
        if (fd >= 0) { ::close(fd); ::unlinkat(root, name.c_str(), 0); throw Failure(ActivationStatus::InterferenceDetected, "snapshot allowed directory write"); }
        if (errno != EROFS) osFailure(ActivationStatus::InterferenceDetected, "read-only directory proof failed");
    }
}
void requireSameSnapshot(const std::map<std::string, struct stat>& expected,
                         const std::map<std::string, struct stat>& actual) {
    if (expected.size() != actual.size()) throw Failure(ActivationStatus::InterferenceDetected, "snapshot structure changed");
    for (const auto& [name, a] : expected) {
        const auto it = actual.find(name);
        if (it == actual.end()) throw Failure(ActivationStatus::InterferenceDetected, "snapshot entry disappeared");
        const auto& b = it->second;
        if (a.st_dev != b.st_dev || a.st_ino != b.st_ino || a.st_mode != b.st_mode || a.st_uid != b.st_uid ||
            a.st_gid != b.st_gid || a.st_nlink != b.st_nlink || a.st_size != b.st_size ||
            a.st_mtim.tv_sec != b.st_mtim.tv_sec || a.st_mtim.tv_nsec != b.st_mtim.tv_nsec ||
            a.st_ctim.tv_sec != b.st_ctim.tv_sec || a.st_ctim.tv_nsec != b.st_ctim.tv_nsec)
            throw Failure(ActivationStatus::InterferenceDetected, "snapshot identity/attributes changed: " + name);
    }
}
struct OwnedMount { std::string path; Identity expected; bool mounted = false; };
struct Operation {
    const Hooks& hooks;
    Fd base, lock;
    std::string name, directory, source, ns;
    std::vector<OwnedMount> mounts;
    bool cleaned = false;
    explicit Operation(const Hooks& h) : hooks(h) {}
    ~Operation() {
        if (!cleaned) { ActivationResult ignored; try { cleanup(ignored); } catch (...) {} }
    }
    void cleanup(ActivationResult& result) {
        if (cleaned) return;
        cleaned = true;
        for (auto it = mounts.rbegin(); it != mounts.rend(); ++it) if (it->mounted) {
            try {
                if (namespaceIdentity(::getpid()) != ns) throw std::runtime_error("cleanup namespace changed");
                auto parent = openAbsolute(std::filesystem::path(it->path).parent_path(), O_PATH|O_DIRECTORY);
                const auto leaf = std::filesystem::path(it->path).filename().string();
                const auto pinned = fdPath(parent.get()) + "/" + leaf;
                {
                    Fd target(::openat(parent.get(), leaf.c_str(), O_PATH|O_NOFOLLOW|O_CLOEXEC));
                    if (!target) throw std::runtime_error("cleanup target disappeared");
                    const auto now = identity(target.get());
                    bool listed = false;
                    for (const auto& m : readMountInfo()) if (m.id == now.mount && m.target == it->path && m.source == source && m.type == "tmpfs") listed = true;
                    if (!it->expected.mount || now.mount != it->expected.mount || !sameObject(now, it->expected) || !listed)
                        throw std::runtime_error("cleanup refuses foreign/replaced mount");
                } // Close mount reference BEFORE ordinary umount; no lazy detach.
                const int injected = hooks.fault("umount", std::distance(mounts.rbegin(), it));
                if (injected) errno = injected;
                if (injected || ::umount2(pinned.c_str(), 0)) osFailure(ActivationStatus::CleanupFailed, "ordinary umount");
                it->mounted = false;
                for (const auto& m : readMountInfo()) if (m.id == it->expected.mount)
                    throw std::runtime_error("owned mount still listed after umount");
            } catch (const std::exception& e) {
                result.cleanupErrors.push_back(it->path + ": " + e.what());
                result.residualPaths.push_back(it->path);
            }
        }
        if (!name.empty() && result.cleanupErrors.empty() && ::unlinkat(base.get(), name.c_str(), AT_REMOVEDIR)) {
            result.cleanupErrors.push_back(directory + ": cannot remove operation directory: " + std::strerror(errno));
            result.residualPaths.push_back(directory);
        }
        if (!result.cleanupErrors.empty()) result.status = ActivationStatus::CleanupFailed;
    }
    void create(const std::filesystem::path& workspace) {
        base = ensureDirectory(workspace, 0700);
        const auto st = identity(base.get());
        if ((st.mode & 0777) != 0700) throw Failure(ActivationStatus::UnsupportedConfiguration, "activator workspace must have mode 0700");
        lock = Fd(::openat(base.get(), "lock", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600));
        if (!lock) osFailure(ActivationStatus::SnapshotFailed, "open activation lock");
        const auto ls = identity(lock.get());
        if (!S_ISREG(ls.mode) || ls.uid != 0 || (ls.mode & 0077) || ::flock(lock.get(), LOCK_EX|LOCK_NB))
            throw Failure(ActivationStatus::UnsupportedConfiguration, "activation lock is unsafe or busy");
        for (unsigned attempt = 0; attempt < 16; ++attempt) {
            unsigned char random[8];
            if (::getrandom(random, sizeof random, 0) != sizeof random) osFailure(ActivationStatus::SnapshotFailed, "operation entropy");
            std::string candidate = "vcsa.";
            const char* hex = "0123456789abcdef";
            for (auto byte : random) { candidate += hex[byte >> 4]; candidate += hex[byte & 15]; }
            if (::mkdirat(base.get(), candidate.c_str(), 0700) == 0) {
                name = candidate;
                directory = (workspace / name).string(); source = "fic-" + name; return;
            }
            if (errno != EEXIST) osFailure(ActivationStatus::SnapshotFailed, "create private operation directory");
        }
        name.clear(); throw Failure(ActivationStatus::SnapshotFailed, "operation name collisions");
    }
    void mountTmpfs(std::uint64_t size) {
        requireSafePublicationParent(directory, false, ActivationStatus::InterferenceDetected);
        auto target = openAbsolute(directory, O_RDONLY|O_DIRECTORY);
        const std::string options = "mode=0700,size=" + std::to_string(size) + ",nr_inodes=8192";
        const int injected = hooks.fault("tmpfs", 0); if (injected) errno = injected;
        if (injected || ::mount(source.c_str(), fdPath(target.get()).c_str(), "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, options.c_str()))
            osFailure(ActivationStatus::SnapshotFailed, "mount bounded tmpfs");
        mounts.push_back({directory, {}, true});
        auto root = openAbsolute(directory, O_RDONLY|O_DIRECTORY); mounts.back().expected = identity(root.get());
        bool own = false;
        for (const auto& m : readMountInfo()) if (m.id == mounts.back().expected.mount && m.source == source && m.type == "tmpfs" && m.target == directory) own = true;
        if (!own) throw Failure(ActivationStatus::InterferenceDetected, "new tmpfs identity unproven");
    }
    void publish(const ControlledPath& path, const std::string& snapshot, const Identity& original, std::size_t i) {
        requireSafePublicationParent(path.path, false, ActivationStatus::InterferenceDetected);
        auto target = openAbsolute(path.path, O_RDONLY);
        if (!sameObject(identity(target.get()), original) || identity(target.get()).mount != original.mount)
            throw Failure(ActivationStatus::InterferenceDetected, "controlled target changed before bind");
        auto sourceFd = openAbsolute(snapshot, O_RDONLY);
        const auto sourceIdentity = identity(sourceFd.get());
        const int injected = hooks.fault("bind", i); if (injected) errno = injected;
        if (injected || ::mount(fdPath(sourceFd.get()).c_str(), fdPath(target.get()).c_str(), nullptr, MS_BIND, nullptr))
            osFailure(ActivationStatus::MountFailed, "publish snapshot bind");
        mounts.push_back({path.path.string(), {}, true});
        auto installed = openAbsolute(path.path, O_RDONLY);
        const auto now = identity(installed.get());
        if (!sameObject(now, sourceIdentity)) throw Failure(ActivationStatus::InterferenceDetected, "bind source identity changed");
        mounts.back().expected = now;
    }
};
ActivationResult perform(const ActivationRequest& request, const Hooks& hooks, const detail::ActivationProof* proof = nullptr) {
    ActivationResult result;
    try { validateRequest(request); } catch (const Failure& e) {
        result.status = result.primaryStatus = e.status; result.diagnostic = e.what(); return result;
    }
    Operation operation(hooks);
    std::unique_ptr<SystemdActivation> service;
    try {
        operation.ns = namespaceIdentity(::getpid());
        detail::validatePublicationEnvironment(request, &result.residualPaths);
        const auto deadline = std::chrono::steady_clock::now() + request.timeout;
        const auto workspace = fic::core::FicRuntimePaths::get().runtimeDir / "verified-config-activator";
        service = std::make_unique<SystemdActivation>(request.unit, deadline, request.paths);
        const auto launch = service->preflight();
        if (proof) {
            if (proof->expectedConfiguration.empty() || !proof->published || !proof->ready ||
                proof->sourceRoots.size() != request.paths.size() || proof->sourceAttributes.size() != request.paths.size())
                throw Failure(ActivationStatus::UnsupportedConfiguration, "incomplete activation proof");
            for (const auto& [key, expected] : proof->expectedConfiguration)
                if (launch.at(key) != expected) throw Failure(ActivationStatus::InterferenceDetected, "preflight proof launch contract changed");
        }
        const auto environmentFiles = validateEnvironmentFiles(launch.properties, &request.paths);
        std::vector<Fd> sources; std::vector<Identity> original; std::vector<Tree> trees;
        auto budget = request.maxSnapshotBytes;
        for (const auto& p : request.paths) {
            requireSafePublicationParent(p.path, false, ActivationStatus::UnsupportedConfiguration);
            try {
                auto source = openAbsolute(p.path, O_RDONLY);
                verifyTree(source.get(), p, request.maxSnapshotBytes);
                trees.push_back(readTree(source.get(), p.kind, budget)); original.push_back(identity(source.get()));
                if (proof) {
                    const auto root = proof->sourceRoots.find(p.path.string());
                    const auto attrs = proof->sourceAttributes.find(p.path.string());
                    if (root == proof->sourceRoots.end() || attrs == proof->sourceAttributes.end() ||
                        !sameObject(root->second, original.back()) || root->second.mount != original.back().mount)
                        throw Failure(ActivationStatus::InterferenceDetected, "proof source identity changed");
                    requireSameSnapshot(attrs->second, trees.back().attributes);
                }
                sources.push_back(std::move(source));
            } catch (const Failure&) {
                // Initial unsupported launch inputs must fail before any mount.
                // Do not expose their bytes or digest in diagnostics.
                if (environmentFiles.count(p.path.string()))
                    throw Failure(ActivationStatus::UnsupportedConfiguration, "EnvironmentFile source verification failed");
                throw;
            }
        }
        operation.create(workspace); operation.mountTmpfs(request.maxSnapshotBytes);
        {
            auto root = openAbsolute(operation.directory, O_RDONLY|O_DIRECTORY);
            const auto opened = identity(root.get());
            if (opened.mount != operation.mounts.front().expected.mount || !sameObject(opened, operation.mounts.front().expected))
                throw Failure(ActivationStatus::InterferenceDetected, "snapshot root replaced before copy");
            for (std::size_t i = 0; i < request.paths.size(); ++i) {
                service->remaining();
                const auto name = std::to_string(i);
                const bool directory = request.paths[i].kind == ControlledPathKind::Directory;
                if (directory && ::mkdirat(root.get(), name.c_str(), 0700)) osFailure(ActivationStatus::SnapshotFailed, "create snapshot directory");
                Fd dest(::openat(root.get(), name.c_str(), (directory ? O_RDONLY|O_DIRECTORY : O_RDWR|O_CREAT|O_EXCL)|O_NOFOLLOW|O_CLOEXEC, 0600));
                if (!dest) osFailure(ActivationStatus::SnapshotFailed, "create snapshot object");
                copyTree(sources[i].get(), dest.get(), trees[i], request.paths[i].kind);
                verifyTree(dest.get(), request.paths[i], request.maxSnapshotBytes);
            }
            const int injected = hooks.fault("readonly", 0); if (injected) errno = injected;
            if (injected || ::mount(nullptr, fdPath(root.get()).c_str(), nullptr, MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC, nullptr))
                osFailure(ActivationStatus::SnapshotFailed, "remount tmpfs superblock read-only");
        }
        requireReadOnly(operation.directory, operation.mounts.front().expected, "tmpfs", operation.source);
        auto snapshotFd = openAbsolute(operation.directory, O_RDONLY|O_DIRECTORY);
        // Whole snapshot also includes empty controlled roots (not inferable
        // from an empty file manifest), so pin its exact attributes directly.
        auto snapshotBudget = request.maxSnapshotBytes;
        const auto pinnedAttributes = readTree(snapshotFd.get(), ControlledPathKind::Directory, snapshotBudget).attributes;
        snapshotFd = Fd();
        for (std::size_t i = 0; i < request.paths.size(); ++i) {
            const auto snapshot = operation.directory + "/" + std::to_string(i);
            auto fd = openAbsolute(snapshot, O_RDONLY);
            verifyTree(fd.get(), request.paths[i], request.maxSnapshotBytes);
            requireWritableDenied(snapshot, request.paths[i].kind, identity(fd.get()));
        }
#ifdef FIC_ACTIVATOR_TESTING
        hooks.checkpoint(detail::TestPhase::SnapshotReadOnly, operation.directory);
#endif
        for (std::size_t i = 0; i < request.paths.size(); ++i) {
            if (environmentFiles.count(request.paths[i].path.string())) {
                auto current = openAbsolute(request.paths[i].path, O_RDONLY);
                verifyTree(current.get(), request.paths[i], request.maxSnapshotBytes);
            }
            operation.publish(request.paths[i], operation.directory + "/" + std::to_string(i), original[i], i);
        }
        // Observer opens AFTER our mounts; no baseline-acknowledging poll.
        MountObserver observer;
        const auto verifyPublished = [&] {
            service->remaining();
            if (namespaceIdentity(::getpid()) != operation.ns) throw Failure(ActivationStatus::InterferenceDetected, "activator namespace changed");
            requireReadOnly(operation.directory, operation.mounts.front().expected, "tmpfs", operation.source);
            auto root = openAbsolute(operation.directory, O_RDONLY|O_DIRECTORY);
            auto remainingBytes = request.maxSnapshotBytes;
            requireSameSnapshot(pinnedAttributes, readTree(root.get(), ControlledPathKind::Directory, remainingBytes).attributes);
            for (std::size_t i = 0; i < request.paths.size(); ++i) {
                const auto& p = request.paths[i];
                requireReadOnly(p.path, operation.mounts[i+1].expected, "tmpfs", operation.source);
                auto fd = openAbsolute(p.path, O_RDONLY); verifyTree(fd.get(), p, request.maxSnapshotBytes);
                requireWritableDenied(p.path, p.kind, operation.mounts[i+1].expected);
            }
        };
        verifyPublished();
#ifdef FIC_ACTIVATOR_TESTING
        hooks.checkpoint(detail::TestPhase::Watching, operation.directory);
#endif
        if (proof) { proof->published(deadline); verifyPublished(); }
        if (observer.changed()) throw Failure(ActivationStatus::InterferenceDetected, "mount namespace changed after publication");
        service->restart();
#ifdef FIC_ACTIVATOR_TESTING
        hooks.checkpoint(detail::TestPhase::RestartQueued, operation.directory);
#endif
        ServiceState ready;
        while (true) {
            if (observer.changed()) throw Failure(ActivationStatus::InterferenceDetected, "mount namespace event during activation");
            auto state = service->current();
            if (service->ready(state)) { service->confirm(state); ready = std::move(state); break; }
            observer.changed(std::min<std::int64_t>(20, service->remaining().count()));
        }
        verifyPublished(); service->confirm(ready);
        if (proof) { proof->ready(ready, deadline); verifyPublished(); service->confirm(ready); }
        if (observer.changed()) throw Failure(ActivationStatus::InterferenceDetected, "mount namespace event before commit");
        result.readinessConfirmed = true;
        result.status = result.primaryStatus = ActivationStatus::Success;
        result.diagnostic = "notify readiness and pinned configuration confirmed within documented observation model";
    } catch (const Failure& e) {
        result.status = result.primaryStatus = e.status; result.diagnostic = e.what();
    } catch (const std::exception& e) {
        result.status = result.primaryStatus = ActivationStatus::UnsupportedConfiguration; result.diagnostic = e.what();
    }
    // Primary outcome is fixed BEFORE our own namespace changes.
    if (!result.success() && service) {
        const auto canceled = service->cancelPendingJob(); if (!canceled.empty()) result.diagnostic += "; " + canceled;
    }
#ifdef FIC_ACTIVATOR_TESTING
    try { hooks.checkpoint(detail::TestPhase::BeforeCleanup, operation.directory); }
    catch (const std::exception& e) { result.cleanupErrors.push_back(std::string("cleanup checkpoint: ") + e.what()); }
#endif
    operation.cleanup(result);
    return result;
}
}
void detail::validatePublicationEnvironment(const ActivationRequest& request, std::vector<std::string>* residualPaths) {
    validateRequest(request);
    if (!capable()) throw Failure(ActivationStatus::UnsupportedConfiguration, "root and effective CAP_SYS_ADMIN required");
    std::ifstream selinux("/sys/fs/selinux/enforce"); char enforcing = '0'; selinux >> enforcing;
    if (enforcing == '1') throw Failure(ActivationStatus::UnsupportedConfiguration, "SELinux enforcing snapshot labels unsupported");
    const auto workspace = fic::core::FicRuntimePaths::get().runtimeDir / "verified-config-activator";
    if (!workspace.is_absolute() || workspace != workspace.lexically_normal()) throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid workspace");
    const auto mounts = readMountInfo();
    std::vector<std::string> residual;
    for (const auto& m : mounts) if (m.source.rfind("fic-vcsa.", 0) == 0) residual.push_back(m.target);
    if (residualPaths) *residualPaths = residual;
    if (!residual.empty()) throw Failure(ActivationStatus::ResidualMounts, "previous activation mounts require manual inspection; not adopted or unmounted");
    requireSafePublicationParent(workspace / "prospective-operation", true, ActivationStatus::UnsupportedConfiguration);
    for (const auto& p : request.paths) {
        requireSafePublicationParent(p.path, false, ActivationStatus::UnsupportedConfiguration);
        if (p.path == workspace || below(p.path, workspace) || below(workspace, p.path))
            throw Failure(ActivationStatus::UnsupportedConfiguration, "controlled path overlaps workspace");
        for (const auto& m : mounts) if (m.target == p.path || (p.kind == ControlledPathKind::Directory && below(m.target, p.path)))
            throw Failure(ActivationStatus::UnsupportedConfiguration, "controlled target has an existing/nested mount");
    }
}
ActivationResult VerifiedConfigServiceActivator::activate(const ActivationRequest& request) { return perform(request, {}); }
ActivationResult detail::activateWithProof(const ActivationRequest& request, const detail::ActivationProof& proof) {
    return perform(request, {}, &proof);
}
#ifdef FIC_ACTIVATOR_TESTING
namespace detail {
ActivationResult activateForTests(const ActivationRequest& r, const TestHooks& hooks) { return perform(r, Hooks{&hooks}); }
ActivationResult activateWithProofForTests(const ActivationRequest& r, const ActivationProof& proof, const TestHooks& hooks) {
    return perform(r, Hooks{&hooks}, &proof);
}
}
#endif
const char* activationStatusName(ActivationStatus s) {
    switch (s) {
#define FIC_STATUS(x) case ActivationStatus::x: return #x
    FIC_STATUS(Success); FIC_STATUS(ChecksumMismatch); FIC_STATUS(UnsupportedConfiguration);
    FIC_STATUS(SnapshotFailed); FIC_STATUS(MountFailed); FIC_STATUS(InterferenceDetected);
    FIC_STATUS(RestartFailed); FIC_STATUS(ReadinessUnconfirmed); FIC_STATUS(TimedOut);
    FIC_STATUS(CleanupFailed); FIC_STATUS(ResidualMounts);
#undef FIC_STATUS
    }
    return "Unknown";
}
} // namespace fic::service
