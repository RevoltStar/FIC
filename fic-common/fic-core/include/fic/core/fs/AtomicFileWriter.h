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
    // Stronger CAS precondition, checked again immediately before replacement.
    std::optional<AtomicTargetState> expectedTargetState;
};

struct AtomicWriteResult {
    bool installed = false;
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
};

#endif // ATOMICFILEWRITER_H
