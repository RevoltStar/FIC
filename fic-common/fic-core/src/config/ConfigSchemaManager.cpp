#include <fic/core/config/ConfigSchemaManager.h>

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/version/ProductVersion.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::core {
namespace {
constexpr std::array<const char*, 9> CONFIG_FILES = {
    "AUDIT.conf", "DAC.conf", "DC.conf", "GLOBAL.conf", "IDENTITY_ACCESS.conf",
    "FIREWALL.conf", "NET.conf", "OSS.conf", "SYSCTL.conf"
};

bool validAbsoluteNormalized(const std::filesystem::path& path) {
    return !path.empty() && path.is_absolute() && path.lexically_normal() == path;
}

bool ensureRealDirectory(const std::filesystem::path& path,
                         bool allowRecoveryBootstrap,
                         bool& created,
                         std::string& error) {
    if (!validAbsoluteNormalized(path)) {
        error = "configuration path must be absolute and normalized: " +
            path.string();
        return false;
    }
    created = false;
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (errno != ENOENT || !allowRecoveryBootstrap) {
            error = "configuration directory is missing or cannot be inspected: " +
                path.string() + ": " + std::strerror(errno);
            return false;
        }
        if (::mkdir(path.c_str(), 02750) != 0) {
            error = "could not create directory " + path.string() + ": " +
                std::strerror(errno);
            return false;
        }
        created = true;
        if (::lstat(path.c_str(), &info) != 0) {
            error = "could not inspect new configuration directory: " + path.string();
            return false;
        }
    }
    if (!S_ISDIR(info.st_mode)) {
        error = "configuration path is not a real directory: " + path.string();
        return false;
    }
    if (created && ::chmod(path.c_str(), 02750) != 0) {
        error = "could not set directory permissions for " + path.string() +
            ": " + std::strerror(errno);
        return false;
    }
    return true;
}

bool readRegularFile(const std::filesystem::path& path,
                     std::string& content,
                     std::string& error,
                     const std::optional<ConfigAuthorityIdentity>& identity =
                         std::nullopt) {
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        error = "configuration is missing or cannot be opened safely: " +
            path.string() + ": " + std::strerror(errno);
        return false;
    }
    struct stat info {};
    if (::fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
        error = "configuration is not a regular file: " + path.string();
        ::close(descriptor);
        return false;
    }
    if (identity.has_value() &&
        !canonicalConfigFileMetadata(info, *identity, path, error)) {
        ::close(descriptor);
        return false;
    }
    if (static_cast<std::uintmax_t>(info.st_size) > MAX_WORKING_CONFIG_BYTES) {
        error = "configuration exceeds the 1 MiB limit: " + path.string();
        ::close(descriptor);
        return false;
    }

    content.clear();
    std::array<char, 8192> buffer {};
    for (;;) {
        const ssize_t bytesRead = ::read(descriptor, buffer.data(), buffer.size());
        if (bytesRead > 0) {
            content.append(buffer.data(), static_cast<std::size_t>(bytesRead));
            if (content.size() > MAX_WORKING_CONFIG_BYTES) {
                error = "configuration exceeds the 1 MiB limit: " + path.string();
                ::close(descriptor);
                return false;
            }
            continue;
        }
        if (bytesRead == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        error = "could not read configuration " + path.string() + ": " +
            std::strerror(errno);
        ::close(descriptor);
        return false;
    }
    struct stat after {};
    if (::fstat(descriptor, &after) != 0 ||
        after.st_dev != info.st_dev || after.st_ino != info.st_ino ||
        after.st_size != info.st_size || after.st_uid != info.st_uid ||
        after.st_gid != info.st_gid || after.st_mode != info.st_mode ||
        after.st_nlink != info.st_nlink ||
        after.st_mtim.tv_sec != info.st_mtim.tv_sec ||
        after.st_mtim.tv_nsec != info.st_mtim.tv_nsec ||
        after.st_ctim.tv_sec != info.st_ctim.tv_sec ||
        after.st_ctim.tv_nsec != info.st_ctim.tv_nsec) {
        error = "configuration changed during secure read: " + path.string();
        ::close(descriptor);
        return false;
    }
    if (identity.has_value()) {
        struct stat named {};
        if (::lstat(path.c_str(), &named) != 0 ||
            named.st_dev != info.st_dev || named.st_ino != info.st_ino ||
            named.st_uid != info.st_uid || named.st_gid != info.st_gid ||
            named.st_mode != info.st_mode || named.st_nlink != info.st_nlink) {
            error = "working configuration path changed during proof: " +
                path.string();
            ::close(descriptor);
            return false;
        }
    }
    if (::close(descriptor) != 0) {
        error = "could not close configuration " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    return true;
}

bool parseSchemaVersion(const std::string& content,
                        int& version,
                        std::string& error) {
    constexpr const char* prefix = "_schema_version=";
    std::istringstream input(content);
    std::string line;
    bool found = false;
    while (std::getline(input, line)) {
        if (line.rfind(prefix, 0) != 0) {
            continue;
        }
        if (found) {
            error = "configuration contains duplicate _schema_version";
            return false;
        }
        found = true;
        try {
            std::size_t consumed = 0;
            const std::string encoded = line.substr(std::strlen(prefix));
            version = std::stoi(encoded, &consumed);
            if (consumed != encoded.size() || version < 0 ||
                encoded != std::to_string(version)) {
                error = "configuration has an invalid _schema_version";
                return false;
            }
        } catch (const std::exception&) {
            error = "configuration has an invalid _schema_version";
            return false;
        }
    }
    if (!found) {
        error = "configuration does not declare _schema_version";
        return false;
    }
    return true;
}

bool verifyConfigContent(const std::string& fileName,
                         const std::string& content,
                         std::string& error) {
    int version = -1;
    if (!parseSchemaVersion(content, version, error)) {
        error = fileName + ": " + error;
        return false;
    }
    if (version != fic::version::CONFIG_SCHEMA_VERSION) {
        error = fileName + " has unsupported configuration schema " +
            std::to_string(version) + "; expected " +
            std::to_string(fic::version::CONFIG_SCHEMA_VERSION);
        return false;
    }
    return true;
}

bool setManagedFileMetadata(const std::filesystem::path& directory,
                            AtomicWriteOptions& options,
                            std::string& error) {
    struct stat info {};
    if (::lstat(directory.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        error = "could not determine managed file directory metadata: " +
            directory.string();
        return false;
    }
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0640;
    options.fileOwner = ::geteuid();
    options.fileGroup = info.st_gid;
    return true;
}
} // namespace

bool ConfigSchemaManager::ensureConfigs(
    const std::filesystem::path& defaultConfigDirectory,
    const std::filesystem::path& configDirectory,
    std::string& error,
    bool allowRecoveryBootstrap,
    std::optional<ConfigAuthorityIdentity> testIdentity) {
    error.clear();
    if (!validAbsoluteNormalized(defaultConfigDirectory) ||
        !validAbsoluteNormalized(configDirectory)) {
        error = "default and working config directories must be absolute and normalized";
        return false;
    }
    struct stat defaultDirectoryInfo {};
    if (::lstat(defaultConfigDirectory.c_str(), &defaultDirectoryInfo) != 0 ||
        !S_ISDIR(defaultDirectoryInfo.st_mode)) {
        error = "default config path is not a real directory: " +
            defaultConfigDirectory.string();
        return false;
    }
    ConfigAuthorityIdentity identity;
    if (testIdentity.has_value()) {
        identity = *testIdentity;
    } else if (!productionConfigAuthority(identity, error)) {
        return false;
    }
    bool created = false;
    if (!ensureRealDirectory(configDirectory, allowRecoveryBootstrap,
                             created, error)) {
        return false;
    }
    if (!proveConfigDirectory(configDirectory, identity, error)) {
        return false;
    }
    if (!created) {
        // Reject unsafe existing authority before creating any ordinary
        // missing configuration in the same directory.
        for (const char* fileName : CONFIG_FILES) {
            const auto workingPath = configDirectory / fileName;
            struct stat existing {};
            if (::lstat(workingPath.c_str(), &existing) == 0) {
                std::string content;
                if (!readRegularFile(workingPath, content, error, identity)) {
                    return false;
                }
            } else if (errno == ENOENT) {
                if (std::strcmp(fileName, "GLOBAL.conf") == 0) {
                    error = "recovery configuration is missing and cannot be bootstrapped: " +
                        workingPath.string();
                    return false;
                }
            } else {
                error = "could not inspect working configuration " +
                    workingPath.string() + ": " + std::strerror(errno);
                return false;
            }
        }
    }

    for (const char* fileName : CONFIG_FILES) {
        std::string defaultContent;
        if (!readRegularFile(
                defaultConfigDirectory / fileName, defaultContent, error) ||
            !verifyConfigContent(fileName, defaultContent, error)) {
            return false;
        }
        const std::filesystem::path workingPath = configDirectory / fileName;
        struct stat workingInfo {};
        if (::lstat(workingPath.c_str(), &workingInfo) == 0) {
            std::string existingContent;
            if (!readRegularFile(workingPath, existingContent, error, identity)) {
                return false;
            }
            continue;
        }
        if (errno != ENOENT) {
            error = "could not inspect working configuration " +
                workingPath.string() + ": " + std::strerror(errno);
            return false;
        }
        if (std::strcmp(fileName, "GLOBAL.conf") == 0 && !created) {
            error = "recovery configuration is missing and cannot be bootstrapped: " +
                workingPath.string();
            return false;
        }

        AtomicWriteOptions options;
        options.createIfMissing = true;
        options.rejectSymlink = true;
        options.exclusiveCreate = true;
        if (!setManagedFileMetadata(configDirectory, options, error) ||
            !AtomicFileWriter::write(
                workingPath.string(), defaultContent, options, &error)) {
            return false;
        }
        std::string createdContent;
        if (!readRegularFile(workingPath, createdContent, error, identity)) {
            return false;
        }
    }
    return proveConfigDirectory(configDirectory, identity, error);
}

bool ConfigSchemaManager::verifyConfigs(
    const std::filesystem::path& configDirectory,
    std::string& error,
    std::optional<ConfigAuthorityIdentity> testIdentity) {
    error.clear();
    if (!validAbsoluteNormalized(configDirectory)) {
        error = "config directory must be absolute and normalized";
        return false;
    }
    ConfigAuthorityIdentity identity;
    if (testIdentity.has_value()) {
        identity = *testIdentity;
    } else if (!productionConfigAuthority(identity, error)) {
        return false;
    }
    if (!proveConfigDirectory(configDirectory, identity, error)) {
        return false;
    }
    for (const char* fileName : CONFIG_FILES) {
        std::string content;
        if (!readRegularFile(configDirectory / fileName, content, error, identity) ||
            !verifyConfigContent(fileName, content, error)) {
            return false;
        }
    }
    return proveConfigDirectory(configDirectory, identity, error);
}

} // namespace fic::core
