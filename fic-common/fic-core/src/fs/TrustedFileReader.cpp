#include <fic/core/fs/TrustedFileReader.h>

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace fic::core {
namespace {

class UniqueFd {
public:
    explicit UniqueFd(int descriptor = -1) : descriptor_(descriptor) {}
    ~UniqueFd() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            if (descriptor_ >= 0)
                ::close(descriptor_);
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    int get() const { return descriptor_; }

    bool close(std::string& detail) {
        if (descriptor_ < 0)
            return true;
        const int descriptor = std::exchange(descriptor_, -1);
        if (::close(descriptor) == 0)
            return true;
        detail = std::strerror(errno);
        return false;
    }

private:
    int descriptor_;
};

bool openAndValidate(const std::filesystem::path& path,
                     const TrustedFileReadOptions& options,
                     UniqueFd& descriptor,
                     TrustedFileMetadata& metadata,
                     std::string& error,
                     int& systemError) {
    systemError = 0;
    descriptor = UniqueFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC |
        O_NOFOLLOW | O_NONBLOCK));
    if (descriptor.get() < 0) {
        systemError = errno;
        error = systemError == ELOOP
            ? "trusted file is a symbolic link: " + path.string()
            : "could not securely open trusted file " + path.string() +
                ": " + std::strerror(systemError);
        return false;
    }
    struct stat info {};
    if (::fstat(descriptor.get(), &info) != 0) {
        systemError = errno;
        error = "could not inspect opened trusted file " + path.string() +
            ": " + std::strerror(systemError);
        return false;
    }
    if (options.requireRegularFile && !S_ISREG(info.st_mode)) {
        error = "trusted file is not regular: " + path.string();
        return false;
    }
    if ((options.expectedOwner.has_value() &&
         info.st_uid != *options.expectedOwner) ||
        (options.expectedGroup.has_value() &&
         info.st_gid != *options.expectedGroup)) {
        error = "trusted file has unsafe ownership: " + path.string();
        return false;
    }
    if ((info.st_mode & options.forbiddenMode) != 0) {
        error = "trusted file has unsafe mode: " + path.string();
        return false;
    }
    if (options.requiredAnyMode != 0 &&
        (info.st_mode & options.requiredAnyMode) == 0) {
        error = "trusted file has unsafe mode: " + path.string();
        return false;
    }
    if (options.requireSingleLink && info.st_nlink != 1) {
        error = "trusted file has multiple hard links: " + path.string();
        return false;
    }
    metadata = {info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_gid, info.st_nlink};
    return true;
}

} // namespace

bool inspectTrustedFile(const std::filesystem::path& path,
                        const TrustedFileReadOptions& options,
                        TrustedFileMetadata* metadata,
                        std::string& error,
                        int* systemError) {
    UniqueFd descriptor;
    TrustedFileMetadata opened;
    int failure = 0;
    if (!openAndValidate(path, options, descriptor, opened, error, failure)) {
        if (systemError != nullptr)
            *systemError = failure;
        return false;
    }
    std::string detail;
    if (!descriptor.close(detail)) {
        error = "could not close trusted file " + path.string() + ": " +
            detail;
        return false;
    }
    if (metadata != nullptr)
        *metadata = opened;
    if (systemError != nullptr)
        *systemError = 0;
    error.clear();
    return true;
}

bool readTrustedFile(const std::filesystem::path& path,
                     const TrustedFileReadOptions& options,
                     std::string& content,
                     std::string& error,
                     TrustedFileMetadata* metadata,
                     const TrustedFilePostValidationHook& postValidationHook,
                     int* systemError) {
    UniqueFd descriptor;
    TrustedFileMetadata opened;
    int ignoredSystemError = 0;
    if (!openAndValidate(path, options, descriptor, opened, error,
                         ignoredSystemError)) {
        if (systemError != nullptr)
            *systemError = ignoredSystemError;
        return false;
    }
    if (postValidationHook)
        postValidationHook(path);
    content.clear();
    char buffer[8192];
    for (;;) {
        const ssize_t count = ::read(descriptor.get(), buffer, sizeof(buffer));
        if (count > 0) {
            content.append(buffer, static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;
        content.clear();
        error = "could not completely read trusted file " + path.string() +
            ": " + std::strerror(errno);
        return false;
    }
    std::string detail;
    if (!descriptor.close(detail)) {
        content.clear();
        error = "could not close trusted file " + path.string() + ": " +
            detail;
        return false;
    }
    if (metadata != nullptr)
        *metadata = opened;
    if (systemError != nullptr)
        *systemError = 0;
    error.clear();
    return true;
}

} // namespace fic::core
