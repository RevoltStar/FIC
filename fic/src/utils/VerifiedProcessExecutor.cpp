#include "utils/VerifiedProcessExecutor.h"

#include "utils/ConfigFileHandler.h"

#include <fstream>
#include <openssl/evp.h>
#include <string>
#include <sys/stat.h>

namespace {
constexpr const char* COMMAND_HASH_FILE_PATH = "/opt/fic/db/commandhash.txt";

bool is_symlink(const std::string& path) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        return false;
    }
    return S_ISLNK(info.st_mode);
}

bool is_valid_executable_path(const std::string& executable, std::string& error) {
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

std::string calculate_sha256(const std::string& executable, std::string& error) {
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

bool verify_executable_hash(const std::string& executable, std::string& error) {
    if (!is_valid_executable_path(executable, error)) {
        return false;
    }

    ConfigFileHandler commandHashes(COMMAND_HASH_FILE_PATH);
    if (!commandHashes.loadConfig()) {
        error = "failed to load command hash file: " + std::string(COMMAND_HASH_FILE_PATH);
        return false;
    }

    const std::string expectedHash = commandHashes.getValue(executable);
    if (expectedHash.empty()) {
        error = "no stored reference hash was found for executable: " + executable;
        return false;
    }

    const std::string actualHash = calculate_sha256(executable, error);
    if (actualHash.empty()) {
        return false;
    }

    if (expectedHash != actualHash) {
        error = "executable hash does not match stored reference value: " + executable;
        return false;
    }

    return true;
}
} // namespace

ProcessResult VerifiedProcessExecutor::execute(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const ProcessOptions& options
) {
    ProcessResult result;
    std::string error;
    if (!verify_executable_hash(executable, error)) {
        result.error = error;
        return result;
    }

    return ProcessExecutor::execute(executable, arguments, options);
}
