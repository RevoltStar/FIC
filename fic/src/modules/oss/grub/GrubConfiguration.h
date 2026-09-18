#ifndef FIC_OSS_GRUB_CONFIGURATION_H
#define FIC_OSS_GRUB_CONFIGURATION_H

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/ProcessExecutor.h>

#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

// Typed outcome of a GRUB source mutation for the journal lifecycle matrix
// (never derived from error message matching):
//   Unchanged     — FIC did not modify the managed source;
//   Installed     — FIC installed new source state (rename published);
//   Compensated   — FIC-installed state was conditionally rolled back and
//                   the pre-apply state is proven restored;
//   Indeterminate — the source may still contain the FIC mutation
//                   (installed but not durable, or concurrent drift after
//                   install): the Prepared journal record must stay active.
enum class GrubSourceMutationState {
    Unchanged,
    Installed,
    Compensated,
    Indeterminate
};

struct GrubValueObservation {
    bool found = false;
    bool valid = true;
    std::string value;
    std::filesystem::path source;
    size_t line = 0;
    std::string error;
};

struct GrubOperationResult {
    bool ok = false;
    bool changed = false;
    GrubSourceMutationState sourceState = GrubSourceMutationState::Unchanged;
    std::string message;
    std::vector<std::string> diagnostics;
};

struct GrubConfigurationOptions {
    std::filesystem::path defaultsPath;
    std::filesystem::path rebuildExecutable;
    std::vector<std::string> rebuildArguments;
    bool enforceOwnership = true;
};

struct GrubManagedConfigurationOptions {
    std::filesystem::path managedPath;
    std::filesystem::path rebuildExecutable;
    std::vector<std::string> rebuildArguments;
    bool enforceOwnership = true;
    // Validate-only base defaults (Debian/Ubuntu: /etc/default/grub).
    // FIC never edits this file, but update-grub still sources it as root
    // shell code, so it must be proven safe before the managed drop-in is
    // mutated or the rebuild runs. Empty when the platform has no base
    // defaults (ALT shared-file topology).
    std::filesystem::path baseDefaultsPath;
    // ALT shared defaults hosting the FIC EOF managed block.
    std::filesystem::path sharedDefaultsPath;
};

using GrubCommandRunner = std::function<ProcessResult(
    const std::string&,
    const std::vector<std::string>&,
    const ProcessOptions&
)>;

// Intra-process serialization of ALL GRUB backend operations (apply AND
// rollback share this one mutex). Cross-process correctness is NOT claimed:
// it rests on atomic snapshots, CAS/expectedTargetState writes, state
// re-proof and the durable mutation journal.
std::mutex& grubBackendMutex();

GrubCommandRunner defaultGrubCommandRunner();

// Verified GRUB rebuild through the runner seam (production default:
// VerifiedProcessExecutor with an empty environment and a bounded timeout).
bool runGrubRebuild(const std::filesystem::path& executable,
                    const std::vector<std::string>& arguments,
                    const GrubCommandRunner& runner,
                    std::string& error);

// Read-only inspection of the FIC-owned managed GRUB value under the
// platform topology (Debian/Ubuntu managed drop-in or ALT EOF managed
// block). Never mutates anything. A missing managed artifact is
// valid == true, found == false. A malformed FIC artifact is
// valid == false (fail closed).
GrubValueObservation inspectGrubManagedValue(
    const GrubManagedConfigurationOptions& options,
    const std::string& key);

// Typed observation of a GRUB-managed target file. Replaces the old boolean
// "regular file exists" probe: a missing artifact (ENOENT) is a legitimate
// Missing state; anything that occupies the path but is not a regular
// non-symlink file (directory, symlink, FIFO, socket, device) is Unsafe and
// must fail closed; any other lstat failure is Error. Both are distinct from
// Missing — an unsafe artifact must NEVER be reported as "already released".
enum class GrubTargetKind {
    Missing,
    Regular,
    Unsafe,
    Error
};

struct GrubTargetProbe {
    GrubTargetKind kind = GrubTargetKind::Error;
    std::string error;
};

GrubTargetProbe probeGrubTargetFile(const std::filesystem::path& path);

// Single classifier of an active GRUB journal record against the CURRENT
// managed source state (both topologies). Used before AND after the
// mandatory rebuild:
//   Before  — the managed value is absent: the mutation never installed or
//             was fully compensated;
//   After   — the managed value is present and equals the recorded
//             appliedValue;
//   Drift   — the managed value is present with another value: never
//             rewritten, never overwritten, the journal record is not
//             resolved;
//   Invalid — the managed source could not be classified (unreadable,
//             unsafe or malformed FIC artifact): fail closed.
// The underlying inspection is returned through the optional out-parameter
// so callers can reuse it for diagnostics.
enum class GrubManagedJournalState {
    Before,
    After,
    Drift,
    Invalid
};

GrubManagedJournalState classifyGrubManagedJournalState(
    const GrubManagedConfigurationOptions& options,
    const std::string& key,
    const std::string& appliedValue,
    GrubValueObservation* observation = nullptr);

// Typed outcome of a FRESH managed-source proof of the expected policy
// value. Always derived from a new inspection of the CURRENT on-disk
// source — never from a pre-write or pre-rebuild snapshot:
//   Matches — the managed source is valid/safe, the key exists and equals
//             the expected value;
//   Missing — the managed source is valid, but the key is absent;
//   Drift   — the managed source is valid, but the key holds another value
//             (external mutation);
//   Invalid — the managed source is unreadable, unsafe or a malformed FIC
//             artifact (fail closed).
enum class GrubManagedValueProof {
    Matches,
    Missing,
    Drift,
    Invalid
};

// Proves that the FIC-owned managed GRUB source under the platform topology
// still contains key == expectedValue in a valid/safe source. Used as the
// post-rebuild proof after EVERY GRUB rebuild that follows a source
// mutation (changed apply) and before EVERY idempotent apply success: a
// successful rebuild alone never proves managed-state compliance, because
// an external writer may mutate the source while the rebuild runs.
GrubManagedValueProof proveExpectedGrubManagedValue(
    const GrubManagedConfigurationOptions& options,
    const std::string& key,
    const std::string& expectedValue,
    std::string& error);

// Validate-only safety proof of EVERY input update-grub sources or reads,
// under the platform topology. Must be called immediately before EVERY GRUB
// rebuild (normal apply, journal reconciliation, prepared recovery,
// NothingToDo rollback, post-rollback, compensating rebuild, value-change
// release) because the rebuild executes the rebuild command as root with the
// current on-disk inputs:
//   * Debian/Ubuntu (baseDefaultsPath set): validateBaseGrubDefaults —
//     a missing base file is acceptable, an existing one must be safe;
//   * ALT (sharedDefaultsPath set): validateGrubSourceFile — a missing
//     shared file is acceptable for a rebuild, an existing one must be a
//     regular non-symlink file of a bounded size without group/world write
//     bits, owned by root when enforceOwnership is set, inside a safe
//     directory chain.
bool validateGrubRebuildInputs(const GrubManagedConfigurationOptions& options,
                               std::string& error);

// Validate-only safety proof of the ALT shared GRUB defaults file. Missing is
// acceptable (nothing unsafe is sourced); an existing file must be safe.
bool validateGrubSourceFile(const std::filesystem::path& path,
                            bool enforceOwnership,
                            std::string& error);

// Conditional compensation shared by ALT apply and ALT rollback: replaces
// the file content ONLY while the target still IS exactly the expected
// FIC-installed state (identity, metadata, content). Refuses symlinks,
// preserves existing metadata. Never adopts a fresh snapshot as its own
// expected state: concurrent external mutation is preserved.
enum class GrubCompensationOutcome {
    Proven,
    ConcurrentDrift,
    Failed
};

GrubCompensationOutcome restoreGrubFileIfCurrentState(
    const std::filesystem::path& path,
    const std::string& content,
    const AtomicTargetState& expectedInstalledState,
    std::string& error);

// Safe editor for the FIC-owned EOF managed block of the ALT shared GRUB
// defaults file (/etc/sysconfig/grub2). Foreign bytes are preserved
// byte-exact; the FIC managed block is always (re)placed at EOF.
//
// SINGLE-SNAPSHOT model: load() captures ONE authoritative snapshot of the
// target (safe open, bounded read, identity re-proof — see readSnapshot()).
// Parsing, mutation rendering, the CAS precondition
// (AtomicWriteOptions::expectedTargetState) and the compensation
// pre-apply state are all derived from that same snapshot, so an external
// writer racing between the load and the write can only fail the CAS —
// its bytes are never adopted as FIC's own expected state and never
// overwritten. Uses an atomic CAS write with post-write proof and a
// conditional compensation of the exact pre-apply state after a failed
// rebuild.
class GrubConfiguration {
public:
    explicit GrubConfiguration(GrubConfigurationOptions options = {},
                               GrubCommandRunner runner = {});

    bool load(std::string& error);
    const std::string& content() const { return loadedState_.content; }
    // The authoritative snapshot captured by load(): identity, metadata and
    // exact content. It is the CAS precondition and the compensation source.
    const AtomicTargetState& loadedState() const { return loadedState_; }
    bool loaded() const { return loaded_; }
    const std::filesystem::path& path() const { return options_.defaultsPath; }

    GrubOperationResult ensureManagedValue(const std::string& key,
                                           const std::string& value);

private:
    GrubConfigurationOptions options_;
    GrubCommandRunner runner_;
    AtomicTargetState loadedState_;
    bool loaded_ = false;

    bool checkFileSafety(std::string& error) const;
    bool readSnapshot(std::string& error);
    bool rebuild(std::string& error);
};

// Test-only deterministic seam for stale-read race coverage: when set, the
// hook is invoked exactly once immediately before the CAS write of the ALT
// shared-defaults mutation paths (apply and rollback), after the snapshot
// was captured and the mutation was rendered. It simulates an external
// writer racing between the FIC snapshot and the atomic replacement.
// Production code must never set or invoke it.
void setGrubSharedPreWriteHookForTests(std::function<void()> hook);
void fireGrubSharedPreWriteHookForTests();

// Test-only deterministic seam for post-load external mutation coverage: when
// set, the hook receives the currently loaded shared-defaults path and runs
// immediately before the idempotent-apply ownership re-proof, simulating an
// external writer racing between load() and the re-proof. Fired at most once
// per set value (self-clearing). Production code must never set or invoke it.
void setGrubPostLoadMutationHookForTests(
    std::function<void(const std::string&)> hook);
void fireGrubPostLoadMutationHookForTests(const std::string& path);

// Validate-only safety proof for the platform base defaults file (Debian/
// Ubuntu: /etc/default/grub). Never mutates anything. A missing file is
// acceptable; an existing file must be a regular non-symlink file of a
// bounded size without group/world write bits, owned by root when
// enforceOwnership is set, inside a safe directory chain. Runs before any
// managed drop-in mutation or GRUB rebuild because update-grub still sources
// this file as root shell code.
bool validateBaseGrubDefaults(const std::filesystem::path& path,
                              bool enforceOwnership,
                              std::string& error);

GrubOperationResult ensureManagedGrubDropInValue(
    const GrubManagedConfigurationOptions& options,
    const std::string& key,
    const std::string& value,
    GrubCommandRunner runner = {});

#endif // FIC_OSS_GRUB_CONFIGURATION_H
