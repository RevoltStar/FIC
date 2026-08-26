#include "modules/identity_access/shared/configuration/PreparedFileChange.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity {
namespace {

std::string errnoMessage() {
    return std::strerror(errno);
}

bool closeDescriptor(int& descriptor) {
    if (descriptor < 0) {
        return true;
    }
    const int current = descriptor;
    descriptor = -1;
    return ::close(current) == 0;
}

bool metadataMatches(const struct stat& status,
                     const SecureConfigurationFileOptions& options,
                     const std::filesystem::path& path,
                     std::string& error) {
    if (!S_ISREG(status.st_mode)) {
        error = "refusing to use non-regular configuration file: " +
            path.string();
        return false;
    }
    if (options.expectedOwner.has_value() &&
        status.st_uid != *options.expectedOwner) {
        error = "unexpected owner for configuration file: " + path.string();
        return false;
    }
    if (options.expectedGroup.has_value() &&
        status.st_gid != *options.expectedGroup) {
        error = "unexpected group for configuration file: " + path.string();
        return false;
    }
    const mode_t mode = status.st_mode & 07777;
    if (options.exactMode.has_value() && mode != *options.exactMode) {
        error = "unexpected mode for configuration file: " + path.string();
        return false;
    }
    if ((mode & options.forbiddenMode) != 0) {
        error = "unsafe writable configuration file: " + path.string();
        return false;
    }
    if (status.st_size < 0 ||
        static_cast<std::uintmax_t>(status.st_size) > options.maximumBytes) {
        error = "configuration file exceeds size limit: " + path.string();
        return false;
    }
    return true;
}

bool snapshotsEqual(const ConfigurationFileSnapshot& left,
                    const ConfigurationFileSnapshot& right) {
    return left.content == right.content &&
        left.owner == right.owner &&
        left.group == right.group &&
        left.mode == right.mode;
}

bool hasSafeDirectoryChain(const std::filesystem::path& path,
                           std::string& error) {
    const auto normalized = path.lexically_normal();
    std::filesystem::path current = normalized.root_path();
    for (const auto& component : normalized.relative_path()) {
        current /= component;
        struct stat status {};
        if (::lstat(current.c_str(), &status) != 0) {
            error = "could not inspect configuration path " +
                current.string() + ": " + errnoMessage();
            return false;
        }
        if (S_ISLNK(status.st_mode) || !S_ISDIR(status.st_mode)) {
            error = "refusing to traverse unsafe configuration path: " +
                current.string();
            return false;
        }
    }
    return true;
}

AtomicWriteOptions writeOptions(
    const SecureConfigurationFileOptions& options,
    const ConfigurationFileSnapshot& metadata) {
    AtomicWriteOptions result;
    result.createIfMissing = false;
    result.rejectSymlink = true;
    result.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    result.fileOwner = options.expectedOwner.value_or(metadata.owner);
    result.fileGroup = options.expectedGroup.value_or(metadata.group);
    result.fileMode = options.exactMode.value_or(metadata.mode);
    return result;
}

class PreparedFileChange final : public PreparedConfigurationChange {
public:
    PreparedFileChange(std::string identifier,
                       SecureConfigurationFileOptions options,
                       ConfigurationFileSnapshot original,
                       std::string candidate,
                       ConfigurationContentVerifier verifier)
        : identifier_(std::move(identifier)),
          options_(std::move(options)),
          original_(std::move(original)),
          candidate_(std::move(candidate)),
          verifier_(std::move(verifier)) {
    }

    std::string id() const override {
        return identifier_;
    }

    bool needsCommit() const noexcept override {
        return original_.content != candidate_;
    }

    bool needsActivation() const noexcept override {
        return false;
    }

    ConfigurationStepResult commitPersistent() override {
        ConfigurationFileSnapshot current;
        std::string error;
        if (!readSecureConfigurationFile(options_, current, error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        if (!snapshotsEqual(current, original_)) {
            return ConfigurationStepResult::failure(
                "configuration changed after preflight: " +
                options_.path.string());
        }
        if (candidate_ == original_.content) {
            return ConfigurationStepResult::success(false);
        }
        if (!AtomicFileWriter::write(
                options_.path.string(),
                candidate_,
                writeOptions(options_, original_),
                &error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        return ConfigurationStepResult::success(true);
    }

    ConfigurationStepResult verifyPersistent() override {
        ConfigurationFileSnapshot current;
        std::string error;
        if (!readSecureConfigurationFile(options_, current, error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        ConfigurationFileSnapshot expected = original_;
        expected.content = candidate_;
        if (!snapshotsEqual(current, expected)) {
            return ConfigurationStepResult::failure(
                "configuration does not match prepared candidate: " +
                options_.path.string());
        }
        if (verifier_ && !verifier_(current.content, error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        return ConfigurationStepResult::success(false);
    }

    ConfigurationStepResult activate() override {
        return ConfigurationStepResult::success(false);
    }

    ConfigurationStepResult verifyEffective() override {
        return verifyPersistent();
    }

    ConfigurationStepResult rollbackPersistent() override {
        ConfigurationFileSnapshot current;
        std::string error;
        if (!readSecureConfigurationFile(options_, current, error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        if (snapshotsEqual(current, original_)) {
            return ConfigurationStepResult::success(false);
        }
        ConfigurationFileSnapshot expected = original_;
        expected.content = candidate_;
        if (!snapshotsEqual(current, expected)) {
            return ConfigurationStepResult::failure(
                "refusing to overwrite an external configuration change: " +
                options_.path.string());
        }
        if (!AtomicFileWriter::write(
                options_.path.string(),
                original_.content,
                writeOptions(options_, original_),
                &error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        return ConfigurationStepResult::success(true);
    }

    ConfigurationStepResult restoreRuntimeAfterRollback() override {
        return ConfigurationStepResult::success(false);
    }

    ConfigurationStepResult verifyRollback() override {
        ConfigurationFileSnapshot current;
        std::string error;
        if (!readSecureConfigurationFile(options_, current, error)) {
            return ConfigurationStepResult::failure(std::move(error));
        }
        if (!snapshotsEqual(current, original_)) {
            return ConfigurationStepResult::failure(
                "configuration rollback was not exact: " +
                options_.path.string());
        }
        return ConfigurationStepResult::success(false);
    }

private:
    std::string identifier_;
    SecureConfigurationFileOptions options_;
    ConfigurationFileSnapshot original_;
    std::string candidate_;
    ConfigurationContentVerifier verifier_;
};

} // namespace

bool readSecureConfigurationFile(
    const SecureConfigurationFileOptions& options,
    ConfigurationFileSnapshot& snapshot,
    std::string& error) {
    if (options.path.empty() || !options.path.is_absolute()) {
        error = "configuration path must be absolute";
        return false;
    }
    if (!verifySecureConfigurationDirectory(
            options.path.parent_path(), options, error)) {
        return false;
    }

    struct stat linkStatus {};
    if (::lstat(options.path.c_str(), &linkStatus) != 0) {
        error = "could not inspect configuration file " +
            options.path.string() + ": " + errnoMessage();
        return false;
    }
    if (S_ISLNK(linkStatus.st_mode)) {
        error = "refusing to use symbolic link: " + options.path.string();
        return false;
    }
    if (!metadataMatches(linkStatus, options, options.path, error)) {
        return false;
    }

    int descriptor = ::open(
        options.path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        error = "could not open configuration file " + options.path.string() +
            ": " + errnoMessage();
        return false;
    }

    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        error = "could not inspect opened configuration file " +
            options.path.string() + ": " + errnoMessage();
        closeDescriptor(descriptor);
        return false;
    }
    if (status.st_dev != linkStatus.st_dev || status.st_ino != linkStatus.st_ino) {
        error = "configuration file changed while opening: " +
            options.path.string();
        closeDescriptor(descriptor);
        return false;
    }
    if (!metadataMatches(status, options, options.path, error)) {
        closeDescriptor(descriptor);
        return false;
    }

    std::string content;
    content.reserve(static_cast<std::size_t>(status.st_size));
    std::vector<char> buffer(16384);
    while (true) {
        const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = "could not read configuration file " +
                options.path.string() + ": " + errnoMessage();
            closeDescriptor(descriptor);
            return false;
        }
        if (count == 0) {
            break;
        }
        if (content.size() + static_cast<std::size_t>(count) >
            options.maximumBytes) {
            error = "configuration file exceeds size limit: " +
                options.path.string();
            closeDescriptor(descriptor);
            return false;
        }
        content.append(buffer.data(), static_cast<std::size_t>(count));
    }
    if (!closeDescriptor(descriptor)) {
        error = "could not close configuration file " +
            options.path.string() + ": " + errnoMessage();
        return false;
    }

    snapshot.content = std::move(content);
    snapshot.owner = status.st_uid;
    snapshot.group = status.st_gid;
    snapshot.mode = status.st_mode & 07777;
    return true;
}

bool verifySecureConfigurationDirectory(
    const std::filesystem::path& path,
    const SecureConfigurationFileOptions& fileOptions,
    std::string& error) {
    if (path.empty() || !path.is_absolute()) {
        error = "configuration directory path must be absolute";
        return false;
    }
    if (!hasSafeDirectoryChain(path, error)) {
        return false;
    }
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        error = "could not inspect configuration directory " + path.string() +
            ": " + errnoMessage();
        return false;
    }
    if (S_ISLNK(status.st_mode) || !S_ISDIR(status.st_mode)) {
        error = "refusing to use unsafe configuration directory: " +
            path.string();
        return false;
    }
    if (fileOptions.expectedOwner.has_value() &&
        status.st_uid != *fileOptions.expectedOwner) {
        error = "unexpected owner for configuration directory: " +
            path.string();
        return false;
    }
    if (fileOptions.expectedGroup.has_value() &&
        status.st_gid != *fileOptions.expectedGroup) {
        error = "unexpected group for configuration directory: " +
            path.string();
        return false;
    }
    if ((status.st_mode & fileOptions.forbiddenMode) != 0) {
        error = "unsafe writable configuration directory: " + path.string();
        return false;
    }
    return true;
}

std::unique_ptr<PreparedConfigurationChange> makePreparedFileChange(
    std::string identifier,
    SecureConfigurationFileOptions options,
    ConfigurationFileSnapshot original,
    std::string candidate,
    ConfigurationContentVerifier verifier) {
    return std::make_unique<PreparedFileChange>(
        std::move(identifier),
        std::move(options),
        std::move(original),
        std::move(candidate),
        std::move(verifier));
}

bool executePreparedFileChange(
    std::unique_ptr<PreparedConfigurationChange> change,
    std::string& error) {
    std::vector<std::unique_ptr<PreparedConfigurationChange>> changes;
    changes.push_back(std::move(change));
    const auto result = ConfigurationTransaction::execute(std::move(changes));
    if (result.ok) {
        return true;
    }
    error = result.error;
    for (const auto& recoveryError : result.recoveryErrors) {
        error += "; recovery error: " + recoveryError;
    }
    return false;
}

} // namespace fic::identity
