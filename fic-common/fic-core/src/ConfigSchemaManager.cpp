#include <fic/core/ConfigSchemaManager.h>

#include <fic/core/AtomicFileWriter.h>
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
constexpr std::size_t MAX_CONFIG_BYTES = 1024U * 1024U;
constexpr std::array<const char*, 9> CONFIG_FILES = {
    "AUDIT.conf", "DAC.conf", "DC.conf", "GLOBAL.conf", "IDENTITY_ACCESS.conf",
    "FIREWALL.conf", "NET.conf", "OSS.conf", "SYSCTL.conf"
};

bool validAbsoluteNormalized(const std::filesystem::path& path) {
    return !path.empty() && path.is_absolute() && path.lexically_normal() == path;
}

bool ensureRealDirectory(const std::filesystem::path& path, std::string& error) {
    if (!validAbsoluteNormalized(path)) {
        error = "configuration path must be absolute and normalized: " +
            path.string();
        return false;
    }
    std::error_code filesystemError;
    std::filesystem::create_directories(path, filesystemError);
    if (filesystemError) {
        error = "could not create directory " + path.string() + ": " +
            filesystemError.message();
        return false;
    }
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
        error = "configuration path is not a real directory: " + path.string();
        return false;
    }
    if (::chmod(path.c_str(), 02750) != 0) {
        error = "could not set directory permissions for " + path.string() +
            ": " + std::strerror(errno);
        return false;
    }
    return true;
}

bool readRegularFile(const std::filesystem::path& path,
                     std::string& content,
                     std::string& error) {
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
    if (static_cast<std::uintmax_t>(info.st_size) > MAX_CONFIG_BYTES) {
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
    std::string& error) {
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
    if (!ensureRealDirectory(configDirectory, error)) {
        return false;
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
            if (!S_ISREG(workingInfo.st_mode)) {
                error = "working configuration is not a regular file: " +
                    workingPath.string();
                return false;
            }
            continue;
        }
        if (errno != ENOENT) {
            error = "could not inspect working configuration " +
                workingPath.string() + ": " + std::strerror(errno);
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
    }
    return true;
}

bool ConfigSchemaManager::verifyConfigs(
    const std::filesystem::path& configDirectory,
    std::string& error) {
    error.clear();
    if (!validAbsoluteNormalized(configDirectory)) {
        error = "config directory must be absolute and normalized";
        return false;
    }
    for (const char* fileName : CONFIG_FILES) {
        std::string content;
        if (!readRegularFile(configDirectory / fileName, content, error) ||
            !verifyConfigContent(fileName, content, error)) {
            return false;
        }
    }
    return true;
}

} // namespace fic::core
