#include <fic/core/CommandHashStore.h>

#include <fic/core/ConfigFileHandler.h>
#include <fic/core/ExclusivePidLock.h>
#include <fic/core/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <openssl/evp.h>
#include <sys/stat.h>

namespace {
const std::filesystem::path& command_hash_file_path() {
    return fic::core::FicRuntimePaths::get().commandHashFile;
}

bool is_symlink(const std::string& path) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        return false;
    }
    return S_ISLNK(info.st_mode);
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
    options.writeOptions.fileMode = 0660;
    options.writeOptions.fileOwner = 0;
    options.writeOptions.fileGroup = directoryInfo.st_gid;
    return true;
}
} // namespace

bool CommandHashStore::saveHash(const std::string& executable, std::string& error) {
    return saveHashes({executable}, error);
}

bool CommandHashStore::saveHashes(
    const std::vector<std::string>& executables,
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
        if (!isValidExecutablePath(executable, error)) {
            return false;
        }
        const std::string hash = calculateSha256(executable, error);
        if (hash.empty()) {
            return false;
        }
        hashes.emplace_back(executable, hash);
    }

    FileHandlerOptions fileOptions;
    if (!command_hash_file_options(fileOptions, error)) {
        return false;
    }
    ConfigFileHandler commandHashes(hashFile, "=", fileOptions);
    if (!commandHashes.loadConfig()) {
        error = "failed to load command hash file: " + hashFile;
        return false;
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
    if (!isValidExecutablePath(executable, error)) {
        return false;
    }

    const std::string hashFile = command_hash_file_path().string();
    ConfigFileHandler commandHashes(hashFile);
    if (!commandHashes.loadConfig()) {
        error = "failed to load command hash file: " + hashFile;
        return false;
    }

    const std::string expectedHash = commandHashes.getValue(executable);
    if (expectedHash.empty()) {
        error = "no stored reference hash was found for executable: " + executable;
        return false;
    }

    const std::string actualHash = calculateSha256(executable, error);
    if (actualHash.empty()) {
        return false;
    }

    if (expectedHash != actualHash) {
        error = "executable hash does not match stored reference value: " + executable;
        return false;
    }

    return true;
}

bool CommandHashStore::isValidExecutablePath(const std::string& executable, std::string& error) {
    if (executable.empty()) {
        error = "executable path is empty";
        return false;
    }
    if (executable.front() != '/') {
        error = "executable path must be absolute";
        return false;
    }
    if (executable.back() == '/') {
        error = "executable path must not end with slash";
        return false;
    }
    if (executable.find("..") != std::string::npos) {
        error = "executable path must not contain directory traversal";
        return false;
    }
    if (is_symlink(executable)) {
        error = "executable path is a symbolic link: " + executable;
        return false;
    }
    return true;
}

std::string CommandHashStore::calculateSha256(const std::string& executable, std::string& error) {
    std::ifstream file(executable, std::ios::binary);
    if (!file.is_open()) {
        error = "failed to open executable for hashing: " + executable;
        return "";
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        error = "OpenSSL: failed to allocate digest context";
        return "";
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        error = "OpenSSL: failed to initialize SHA-256 context";
        EVP_MD_CTX_free(context);
        return "";
    }

    char buffer[1024 * 16];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(context, buffer, static_cast<size_t>(file.gcount())) != 1) {
            error = "OpenSSL: failed to update SHA-256 digest";
            EVP_MD_CTX_free(context);
            return "";
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context, digest, &digestLength) != 1) {
        error = "OpenSSL: failed to finalize SHA-256 digest";
        EVP_MD_CTX_free(context);
        return "";
    }

    EVP_MD_CTX_free(context);

    const char* hexChars = "0123456789abcdef";
    std::string hash;
    hash.reserve(digestLength * 2);
    for (unsigned int i = 0; i < digestLength; ++i) {
        const unsigned char value = digest[i];
        hash.push_back(hexChars[value >> 4]);
        hash.push_back(hexChars[value & 0x0F]);
    }
    return hash;
}
