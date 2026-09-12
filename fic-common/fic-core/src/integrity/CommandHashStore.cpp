#include <fic/core/integrity/CommandHashStore.h>

#include "CommandHashStoreInternal.h"

#include <fic/core/config/ConfigFileHandler.h>
#include <fic/core/process/ExclusivePidLock.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <memory>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
const std::filesystem::path& command_hash_file_path() {
    return fic::core::FicRuntimePaths::get().commandHashFile;
}

using command_hash_store_detail::UniqueFd;

bool open_validated_executable(const std::string& executable,
                               UniqueFd& descriptor,
                               std::string& error) {
    if (!command_hash_store_detail::validateExecutablePathSyntax(
            executable, error)) {
        return false;
    }
    if (!command_hash_store_detail::validateCommandHashStoreKey(
            executable, error)) {
        return false;
    }

    const int rawDescriptor = ::open(
        executable.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (rawDescriptor < 0) {
        if (errno == ELOOP) {
            error = "executable path is a symbolic link: " + executable;
        } else {
            error = "failed to open executable for hashing: " + executable +
                ": " + std::strerror(errno);
        }
        return false;
    }

    UniqueFd opened(rawDescriptor);
    // Keep the executable out of the stdio slots overwritten in the child.
    if (opened.get() <= STDERR_FILENO) {
        const int movedDescriptor = ::fcntl(opened.get(), F_DUPFD_CLOEXEC, 3);
        if (movedDescriptor < 0) {
            error = "failed to relocate executable descriptor: " + executable +
                ": " + std::strerror(errno);
            return false;
        }
        opened = UniqueFd(movedDescriptor);
    }
    struct stat metadata {};
    if (::fstat(opened.get(), &metadata) != 0) {
        error = "failed to inspect opened executable: " + executable + ": " +
            std::strerror(errno);
        return false;
    }
    if (!S_ISREG(metadata.st_mode)) {
        error = "executable path is not a regular file: " + executable;
        return false;
    }
    if ((metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        error = "executable file has no execute permission bits: " + executable;
        return false;
    }

    descriptor = std::move(opened);
    error.clear();
    return true;
}

bool calculate_sha256_from_fd_impl(int descriptor, std::string& hash,
                                   std::string& error) {
    using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    DigestContext context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context) {
        error = "OpenSSL: failed to allocate digest context";
        return false;
    }
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        error = "OpenSSL: failed to initialize SHA-256 context";
        return false;
    }

    char buffer[16 * 1024];
    off_t offset = 0;
    while (true) {
        const ssize_t count = ::pread(descriptor, buffer, sizeof(buffer), offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            error = "failed to read executable for hashing: " +
                std::string(std::strerror(errno));
            return false;
        }
        if (count == 0) break;
        offset += count;
        if (EVP_DigestUpdate(
                context.get(), buffer, static_cast<std::size_t>(count)) != 1) {
            error = "OpenSSL: failed to update SHA-256 digest";
            return false;
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context.get(), digest, &digestLength) != 1) {
        error = "OpenSSL: failed to finalize SHA-256 digest";
        return false;
    }

    constexpr char HexChars[] = "0123456789abcdef";
    hash.clear();
    hash.reserve(digestLength * 2);
    for (unsigned int index = 0; index < digestLength; ++index) {
        const unsigned char value = digest[index];
        hash.push_back(HexChars[value >> 4]);
        hash.push_back(HexChars[value & 0x0F]);
    }
    error.clear();
    return true;
}

bool command_hash_directory_exists(std::string& error) {
    const std::filesystem::path& hashFile = command_hash_file_path();
    const std::filesystem::path hashDirectory = hashFile.parent_path();
    if (!std::filesystem::exists(hashDirectory)) {
        error = "command hash directory does not exist: " + hashDirectory.string();
        return false;
    }
    if (!std::filesystem::is_directory(hashDirectory)) {
        error = "command hash path parent is not a directory: " + hashDirectory.string();
        return false;
    }
    return true;
}

bool command_hash_file_options(FileHandlerOptions& options, std::string& error) {
    const std::filesystem::path directory =
        command_hash_file_path().parent_path();
    struct stat directoryInfo {};
    if (::stat(directory.c_str(), &directoryInfo) != 0) {
        error = "could not stat command hash directory: " + directory.string();
        return false;
    }
    options.writeOptions.createIfMissing = true;
    options.writeOptions.rejectSymlink = true;
    options.writeOptions.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.writeOptions.fileMode = 0640;
    options.writeOptions.fileOwner = 0;
    options.writeOptions.fileGroup = directoryInfo.st_gid;
    return true;
}
} // namespace

namespace command_hash_store_detail {

bool validateCommandHashStoreKey(const std::string& executable,
                                 std::string& error) {
    constexpr char HexDigits[] = "0123456789ABCDEF";
    for (const unsigned char byte : executable) {
        if (byte > 0x1f && byte != 0x7f && byte != '=' && byte != '#') {
            continue;
        }

        std::string byteDescription = "0x";
        byteDescription.push_back(HexDigits[byte >> 4]);
        byteDescription.push_back(HexDigits[byte & 0x0f]);
        if (byte == 0x00) {
            byteDescription += " (NUL)";
        } else if (byte == 0x09) {
            byteDescription += " (TAB)";
        } else if (byte == 0x0a) {
            byteDescription += " (LF)";
        } else if (byte == 0x0d) {
            byteDescription += " (CR)";
        } else if (byte == 0x7f) {
            byteDescription += " (DEL)";
        } else if (byte == '=') {
            byteDescription += " (equals sign)";
        } else if (byte == '#') {
            byteDescription += " (number sign)";
        }
        error = "executable path contains a byte unsupported by the command "
                "hash store format: " + byteDescription;
        return false;
    }
    error.clear();
    return true;
}

bool validateExecutablePathSyntax(const std::string& executable,
                                  std::string& error) {
    if (executable.empty()) {
        error = "executable path is empty";
        return false;
    }
    const std::filesystem::path path(executable);
    if (!path.is_absolute()) {
        error = "executable path must be absolute";
        return false;
    }
    if (executable.back() == '/') {
        error = "executable path must not end with slash";
        return false;
    }
    for (const std::filesystem::path& component : path) {
        if (component == "..") {
            error = "executable path must not contain directory traversal";
            return false;
        }
    }
    error.clear();
    return true;
}

bool calculateSha256FromFd(int descriptor, std::string& hash,
                           std::string& error) {
    return calculate_sha256_from_fd_impl(descriptor, hash, error);
}

bool calculateValidatedExecutableSha256(const std::string& executable,
                                        std::string& hash,
                                        std::string& error) {
    UniqueFd descriptor;
    if (!open_validated_executable(executable, descriptor, error)) {
        return false;
    }
    return calculateSha256FromFd(descriptor.get(), hash, error);
}

} // namespace command_hash_store_detail

bool CommandHashStore::saveHash(const std::string& executable, std::string& error) {
    return saveHashes({executable}, error);
}

bool CommandHashStore::saveHashes(
    const std::vector<std::string>& executables,
    std::string& error) {
    return updateHashes(executables, {}, error);
}

bool CommandHashStore::updateHashes(
    const std::vector<std::string>& executables,
    const std::vector<std::string>& removedExecutables,
    std::string& error) {
    if (!command_hash_directory_exists(error)) {
        return false;
    }

    const std::string hashFile = command_hash_file_path().string();
    ExclusivePidLock writeLock(
        hashFile + ".lock",
        fic::core::FicRuntimePaths::get().lockDebugLogFile.string(),
        false);
    if (!writeLock.acquire()) {
        error = "failed to acquire command hash write lock: " + hashFile + ".lock";
        return false;
    }

    std::vector<std::pair<std::string, std::string>> hashes;
    hashes.reserve(executables.size());
    for (const std::string& executable : executables) {
        std::string hash;
        if (!command_hash_store_detail::calculateValidatedExecutableSha256(
                executable, hash, error)) {
            return false;
        }
        hashes.emplace_back(executable, hash);
    }
    for (const std::string& executable : removedExecutables) {
        if (!command_hash_store_detail::validateExecutablePathSyntax(
                executable, error) ||
            !command_hash_store_detail::validateCommandHashStoreKey(
                executable, error)) {
            return false;
        }
    }

    FileHandlerOptions fileOptions;
    if (!command_hash_file_options(fileOptions, error)) {
        return false;
    }
    ConfigFileHandler commandHashes(
        hashFile, "=", fileOptions, ConfigKeyWhitespacePolicy::Preserve);
    if (!commandHashes.loadConfig()) {
        error = "failed to load command hash file: " + hashFile;
        return false;
    }
    for (const std::string& executable : removedExecutables) {
        if (!commandHashes.removeValue(executable)) {
            error = "failed to remove command hash value: " + executable;
            return false;
        }
    }
    for (const auto& [executable, hash] : hashes) {
        if (!commandHashes.setValue(executable, hash)) {
            error = "failed to update command hash value: " + executable;
            return false;
        }
    }
    if (!commandHashes.FileHandler::saveFile()) {
        error = "failed to save command hash file: " + hashFile;
        return false;
    }

    return true;
}

bool CommandHashStore::verifyHash(const std::string& executable, std::string& error) {
    UniqueFd descriptor;
    return command_hash_store_detail::openVerifiedExecutable(
        executable, descriptor, error);
}

bool command_hash_store_detail::openVerifiedExecutable(
    const std::string& executable, UniqueFd& descriptor, std::string& error) {
    descriptor = UniqueFd();
    if (!command_hash_store_detail::validateExecutablePathSyntax(
            executable, error) ||
        !command_hash_store_detail::validateCommandHashStoreKey(
            executable, error)) {
        return false;
    }

    const std::string hashFile = command_hash_file_path().string();
    ConfigFileHandler commandHashes(
        hashFile, "=", {}, ConfigKeyWhitespacePolicy::Preserve);
    if (!commandHashes.loadConfig()) {
        error = "failed to load command hash file: " + hashFile;
        return false;
    }

    const std::string expectedHash = commandHashes.getValue(executable);
    if (expectedHash.empty()) {
        error = "no stored reference hash was found for executable: " + executable;
        return false;
    }

    UniqueFd opened;
    std::string actualHash;
    if (!open_validated_executable(executable, opened, error) ||
        !calculateSha256FromFd(opened.get(), actualHash, error)) {
        return false;
    }

    if (expectedHash != actualHash) {
        error = "executable hash does not match stored reference value: " + executable;
        return false;
    }

    descriptor = std::move(opened);
    return true;
}
