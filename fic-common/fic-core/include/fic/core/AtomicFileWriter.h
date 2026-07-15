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

struct AtomicWriteOptions {
    // Applies both to a direct write and to a file disappearing before write.
    bool createIfMissing = false;
    bool rejectSymlink = false;
    FileMetadataPolicy metadataPolicy = FileMetadataPolicy::PreserveExisting;
    // For a new file these values are used regardless of metadataPolicy.
    std::optional<mode_t> fileMode;
    std::optional<uid_t> fileOwner;
    std::optional<gid_t> fileGroup;
};

class AtomicFileWriter {
public:
    static bool write(const std::string& path,
                      const std::string& content,
                      const AtomicWriteOptions& options = {},
                      std::string* errorMessage = nullptr);
};

#endif // ATOMICFILEWRITER_H
