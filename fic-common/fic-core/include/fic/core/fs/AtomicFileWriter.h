#ifndef ATOMICFILEWRITER_H
#define ATOMICFILEWRITER_H

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
