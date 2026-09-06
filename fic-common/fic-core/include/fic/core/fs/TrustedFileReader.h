#ifndef FIC_CORE_FS_TRUSTED_FILE_READER_H
#define FIC_CORE_FS_TRUSTED_FILE_READER_H

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

#include <sys/stat.h>
#include <sys/types.h>

namespace fic::core {

struct TrustedFileReadOptions {
    std::optional<uid_t> expectedOwner;
    std::optional<gid_t> expectedGroup;
    mode_t forbiddenMode = 0;
    mode_t requiredAnyMode = 0;
    bool requireRegularFile = true;
    bool requireSingleLink = false;
};

struct TrustedFileMetadata {
    dev_t device = 0;
    ino_t inode = 0;
    mode_t mode = 0;
    uid_t owner = 0;
    gid_t group = 0;
    nlink_t linkCount = 0;
};

using TrustedFilePostValidationHook =
    std::function<void(const std::filesystem::path&)>;

bool inspectTrustedFile(const std::filesystem::path& path,
                        const TrustedFileReadOptions& options,
                        TrustedFileMetadata* metadata,
                        std::string& error,
                        int* systemError = nullptr);

bool readTrustedFile(const std::filesystem::path& path,
                     const TrustedFileReadOptions& options,
                     std::string& content,
                     std::string& error,
                     TrustedFileMetadata* metadata = nullptr,
                     const TrustedFilePostValidationHook&
                         postValidationHook = {},
                     int* systemError = nullptr);

} // namespace fic::core

#endif
