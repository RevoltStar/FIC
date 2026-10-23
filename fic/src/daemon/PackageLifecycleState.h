#ifndef FIC_PACKAGE_LIFECYCLE_STATE_H
#define FIC_PACKAGE_LIFECYCLE_STATE_H
#include "daemon/DaemonInstanceLock.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <filesystem>
#include <cstdint>
#include <chrono>
#include <optional>
#include <string>
namespace fic::daemon {
enum class PackagePhase { Installing, Installed, Fencing, Quiescent, DmReleased, DeReleased,
    ProviderReleased, PasswordReleased, HooksDetached, ReleaseComplete, Recovering, InfrastructureProven, InstalledButFenced, RemovedTombstone };
enum class PackageOperation { Install, Upgrade, Remove, Recover };
enum class FinalizerFailure { None, PackageBusy, PackageIncomplete, ProofUnavailable, ProofTimeout,
    InvalidJournal, ManifestConflict, UnprovableOwnership };
enum class FinalizerAdmission { Admitted, Cooldown, WaitingForConfiguration, Blocked, Terminal, Invalid };
inline constexpr std::uint64_t FINALIZER_RETRY_INTERVAL_MS = 60000;
inline constexpr std::chrono::milliseconds FINALIZER_ATTEMPT_TIMEOUT{30000};
inline constexpr std::chrono::milliseconds FINALIZER_COMMAND_TIMEOUT{5000};
inline constexpr std::size_t FINALIZER_OUTPUT_LIMIT = 1024 * 1024;
bool structuralFinalizerFailure(FinalizerFailure failure);
struct PackageLifecycleState {
    PackageOperation operation;
    PackagePhase phase;
    std::string operationId;
    std::string packageVersion;
    unsigned long generation = 0;
    std::string lastAttemptBoot;
    std::uint64_t lastAttemptMs = 0;
    FinalizerFailure lastFailure = FinalizerFailure::None;
};
// Persistent storage is deliberately independent of the package installation and volatile runtime directories. The
// coordinator must prepare and prove its root-controlled directory before use.
class PackageLifecycleStore {
public:
    explicit PackageLifecycleStore(std::filesystem::path path) : path_(std::move(path)) {}
    bool inspect(std::optional<PackageLifecycleState>& state, std::string& error) const;
    // Snapshot-bound recovery barrier for an already published phase. Reading
    // a visible phase alone cannot acknowledge a failed rename-directory fsync.
    bool confirmDurable(const PackageLifecycleState& expected,std::string& error) const;
    bool create(const DaemonInstanceLock&, const PackageLifecycleState&, std::string& error);
    // Starts a new typed operation from an exact current snapshot; recovery
    // proofs belong to the closed coordinator, never to a caller-provided flag.
    bool begin(const DaemonInstanceLock&, const PackageLifecycleState& expected,
               const PackageLifecycleState& nextOperation, std::string& error);
    // Must be called before expensive proofs while the same guard remains held.
    // Admission is durable; failure/crash never consumes a total retry budget.
    FinalizerAdmission admitFinalizerAttempt(const DaemonInstanceLock&,
        const PackageLifecycleState& expected, const std::string& bootId,
        std::uint64_t bootTimeMs, std::string& error);
    bool recordFinalizerFailure(const DaemonInstanceLock&,
        const PackageLifecycleState& expected, FinalizerFailure, std::string& error);
    bool advance(const DaemonInstanceLock&, const PackageLifecycleState& expected,
                 PackagePhase next, std::string& error);
private:
    bool replace(const DaemonInstanceLock&, const PackageLifecycleState& expected,
                 PackageLifecycleState next, std::string& error);
    std::filesystem::path path_;
};
}
#endif
