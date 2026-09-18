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
// byte-exact; the FIC managed block is always (re)placed at EOF. Uses an
// atomic CAS write (captured expected target state) with post-write proof
// and a conditional compensation of the exact pre-apply state after a
// failed rebuild.
class GrubConfiguration {
public:
    explicit GrubConfiguration(GrubConfigurationOptions options = {},
                               GrubCommandRunner runner = {});

    bool load(std::string& error);
    const std::string& content() const { return document_; }
    const std::filesystem::path& path() const { return options_.defaultsPath; }

    GrubOperationResult ensureManagedValue(const std::string& key,
                                           const std::string& value);

private:
    GrubConfigurationOptions options_;
    GrubCommandRunner runner_;
    std::string document_;

    bool checkFileSafety(std::string& error) const;
    bool readDocument(std::string& error);
    bool rebuild(std::string& error) const;
};

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
