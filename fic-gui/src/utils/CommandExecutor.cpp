/*#include "utils/CommandExecutor.h"

std::string CommandExecutor::commandHashFilePath = "/opt/fic/config/commandhash.conf";
std::unique_ptr<ConfigFileHandler> CommandExecutor::cfh = std::make_unique<ConfigFileHandler>(commandHashFilePath);

// Check whether the path points to a symbolic link.
bool CommandExecutor::isSymlink(const std::string& path) {
    struct stat info;
    if (lstat(path.c_str(), &info) != 0) {
        return false;
    }
    return S_ISLNK(info.st_mode);
}

// Calculate a SHA-256 hash for the command file.
std::string CommandExecutor::calcHashbyCommand(const std::string& command){
    std::ifstream file(command, std::ios::binary);
    if (!file) {
        std::cerr << "Command file does not exist: " << command << std::endl;
        return "";
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        std::cerr << "OpenSSL: failed to allocate digest context." << std::endl;
        return "";
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "OpenSSL: failed to initialize SHA-256 context." << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    char buffer[1024 * 16]; // 16 KB buffer
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(md_ctx, buffer, static_cast<size_t>(file.gcount())) != 1) {
            std::cerr << "OpenSSL: failed to update SHA-256 digest." << std::endl;
            EVP_MD_CTX_free(md_ctx);
            return "";
        }
    }

    if (file.gcount() > 0) {
        if (EVP_DigestUpdate(md_ctx, buffer, static_cast<size_t>(file.gcount())) != 1) {
            std::cerr << "OpenSSL: failed to finalize SHA-256 input." << std::endl;
            EVP_MD_CTX_free(md_ctx);
            return "";
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_length) != 1) {
        std::cerr << "OpenSSL: failed to finalize SHA-256 digest." << std::endl;
        EVP_MD_CTX_free(md_ctx);
        return "";
    }

    EVP_MD_CTX_free(md_ctx);

    // Convert the binary digest to a lowercase hexadecimal string.
    const char* hex_chars = "0123456789abcdef";
    std::string hex_hash;
    hex_hash.reserve(digest_length * 2);

    for (unsigned int i = 0; i < digest_length; ++i) {
        unsigned char c = digest[i];
        hex_hash.push_back(hex_chars[c >> 4]);
        hex_hash.push_back(hex_chars[c & 0x0F]);
    }

    return hex_hash;
}

bool CommandExecutor::checkCommandIsValid(const std::string& command){
    if(command.empty()) return false;
    if(command[0] != '/') return false; // absolute paths only
    if(command.back() == '/') return false;

    // Prevent directory traversal attempts.
    if(command.find("..") != std::string::npos) {
        return false;
    }

    if (isSymlink(command)) {
        std::cerr << "Command path is a symbolic link. Use an absolute real path." << std::endl;
        return false;
    }
    return true;
}

bool CommandExecutor::calcHash(const std::string& command){
    if(!CommandExecutor::checkCommandIsValid(command)){
        std::cout << "Input format must be /path/to/command without a trailing slash " << commandHashFilePath;
        return false;
    }
    if(!cfh->loadConfig()){
        std::cout << "Failed to open file " << CommandExecutor::commandHashFilePath;
        return false;
    }

    auto sha256hash = CommandExecutor::calcHashbyCommand(command);
    if(!cfh->setValue(command, sha256hash)){
        return false;
    }
    if(!cfh->FileHandler::saveFile()){
        return false;
    }
    return true;
}

// Get the stored reference hash.
std::string CommandExecutor::getHash(const std::string& command){
    if(!cfh->loadConfig()){
        std::cerr << "Failed to open file " << commandHashFilePath;
        return "";
    }
    return cfh->getValue(command);
}

bool CommandExecutor::checkHash(const std::string &command){
    if(!CommandExecutor::checkCommandIsValid(command)){
        std::cout << "Input format must be /path/to/command without a trailing slash " << commandHashFilePath;
        return false;
    }

    std::string expectedSHA256 = CommandExecutor::getHash(command);
    std::string realSHA256 = CommandExecutor::calcHashbyCommand(command);

    if(expectedSHA256 == ""){
        std::cerr << "No stored reference hash was found for file: " << command << std::endl;
        return false;
    }
    if(realSHA256 == ""){
        std::cerr << "Failed to calculate the current hash for the command file." << std::endl;
        return false;
    }

    if(expectedSHA256 != realSHA256){
        std::cerr << "Current hash does not match the stored reference value." << std::endl;
        return false;
    }
    return true;
}

bool CommandExecutor::execute(const std::string &command, const std::string &param){
    // Validate the command path before execution.
    if(!CommandExecutor::checkCommandIsValid(command)){
        std::cerr << "Input format must be /path/to/command without a trailing slash " << commandHashFilePath;
        return false;
    }
    if(!checkHash(command)){
        return false;
    }
    std::ostringstream oss;
    oss << command << " " << param;
    int result = std::system(oss.str().c_str());

    if (result != 0) {
        return false;
    }
    return true;
}
*/