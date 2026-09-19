#ifndef ATOMICFILEWRITER_H
#define ATOMICFILEWRITER_H

#include <functional>
#include <optional>
#include <string>

#include <sys/types.h>

enum class FileMetadataPolicy {
    // Existing uid/gid/mode win over the optional values below.
    PreserveExisting,
    // Provided values replace existing metadata; omitted values are preserved.
    EnforceProvided
};

struct AtomicTargetIdentity {
    dev_t device = 0;
    ino_t inode = 0;
};

struct AtomicTargetState {
    AtomicTargetIdentity identity;
    std::string content;
    mode_t mode = 0;
    uid_t owner = 0;
    gid_t group = 0;
};

struct AtomicWriteOptions {
    // Applies both to a direct write and to a file disappearing before write.
    bool createIfMissing = false;
    bool rejectSymlink = false;
    // Atomically fail if any object occupies the target at commit time.
    bool exclusiveCreate = false;
    FileMetadataPolicy metadataPolicy = FileMetadataPolicy::PreserveExisting;
    // For a new file these values are used regardless of metadataPolicy.
    std::optional<mode_t> fileMode;
    std::optional<uid_t> fileOwner;
    std::optional<gid_t> fileGroup;
    // When set, refuse replacement unless the target still names this inode.
    std::optional<AtomicTargetIdentity> expectedTargetIdentity;
    // Optimistic snapshot precondition, checked again immediately before
    // replacement. This is not an atomic compare-and-swap against arbitrary
    // non-cooperating writers: they can still race between this check and
    // rename(2).
    std::optional<AtomicTargetState> expectedTargetState;
};

struct AtomicWriteResult {
    bool installed = false;
    // True only when the replacement was published by rename(2) AND its
    // durability was confirmed by a successful fsync of the parent
    // directory. installed alone means the target already carries the new
    // content in the running system, but the rename can still be lost to a
    // crash/power loss until the parent directory fsync succeeds —
    // installed != durable.
    bool durabilityConfirmed = false;
    // Set when the write was refused because the target no longer matches the
    // expected identity/state precondition. Nothing was replaced in that case.
    bool preconditionFailed = false;
    // Present only when installed == true: the exact target state FIC
    // installed through rename (temp file identity, final metadata applied to
    // the temp file, exact written content). It is built from the temp file
    // descriptor, NOT from a post-rename capture of the target: an external
    // writer could replace the target between rename and a fresh capture.
    // Note: installed == true stays set even when a later durability step
    // (directory fsync) fails and the write reports failure — the system may
    // already have been mutated, so callers must treat it as installed.
    std::optional<AtomicTargetState> installedTargetState;
};

class AtomicFileWriter {
public:
    static bool write(const std::string& path,
                      const std::string& content,
                      const AtomicWriteOptions& options = {},
                      std::string* errorMessage = nullptr);

    static bool writeWithResult(const std::string& path,
                                const std::string& content,
                                const AtomicWriteOptions& options,
                                std::string* errorMessage,
                                AtomicWriteResult* result);

    // Test-only deterministic seam: when set, it replaces the real directory
    // fsync performed after a successful rename of the given target AND the
    // directory fsync performed by ensureTargetDurable() for the same path.
    // Returning false simulates a durability failure AFTER the target was
    // installed (installed=true semantics), without relying on real
    // filesystem faults. Production code must never set the hook.
    static void setDirectoryFsyncHookForTests(
        std::function<bool(const std::string& targetPath)> hook);

    // Confirms a directory-entry change (including removal) for path.
    // Unlike ensureTargetDurable(), the target need not exist.
    static bool fsyncParentDirectoryForPath(
        const std::string& path, std::string* errorMessage = nullptr);

    // Confirms the durability of a target that was already observed on disk:
    // fsyncs the parent directory WITHOUT touching the file itself. This is
    // the recovery barrier for a state (for example a config AFTER/BEFORE
    // projection or a journal document) that may have been published by a
    // rename(2) whose parent directory fsync never completed (crash between
    // rename and fsync): the observed content proves nothing about power-loss
    // durability until the directory entry is fsynced. The temp file is
    // always fsynced before rename by writeWithResult(), so the parent
    // directory is the only missing barrier here.
    static bool ensureTargetDurable(const std::string& path,
                                    std::string* errorMessage = nullptr);

    // State-bound recovery barrier: first re-proves that the target still IS
    // exactly the given captured state (identity, metadata, exact content)
    // and only then fsyncs the parent directory. A durability confirmation
    // must never legitimize an externally replaced target, so every caller
    // that captured its state earlier (config snapshot, journal document,
    // FIC-installed state) should prefer this combined helper over a bare
    // ensureTargetDurable(). Failure reasons are differentiated: a mismatched
    // target reports "state changed before durability confirmation", a failed
    // directory fsync reports the fsync error itself. Both cases fail closed.
    static bool ensureTargetDurableIfCurrentState(
        const std::string& path,
        const AtomicTargetState& expected,
        std::string* errorMessage = nullptr);

    // True when the target currently IS exactly the given captured state
    // (identity, metadata, exact content; symlinks refused). Used to re-prove
    // FIC ownership before finishing durability: a mere directory fsync must
    // never legitimize an externally replaced target.
    static bool targetStateMatches(const std::string& path,
                                   const AtomicTargetState& expected,
                                   std::string* errorMessage = nullptr);

    // Captures an optimistic snapshot of a regular file: identity, metadata
    // and exact content read through the same descriptor. Refuses symlinks
    // and non-regular files. The snapshot can be passed as
    // AtomicWriteOptions::expectedTargetState to refuse replacement when the
    // file changed between the snapshot and the write (TOCTOU protection for
    // shared configuration files).
    static bool captureTargetState(const std::string& path,
                                   AtomicTargetState& state,
                                   std::string* errorMessage = nullptr);
};

#endif // ATOMICFILEWRITER_H
