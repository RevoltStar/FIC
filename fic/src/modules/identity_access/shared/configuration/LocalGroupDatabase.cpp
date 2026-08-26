#include "modules/identity_access/shared/configuration/LocalGroupDatabase.h"

#include <cctype>
#include <fstream>
#include <sys/stat.h>

namespace fic::identity {

bool isValidLocalGroupName(const std::string& value) {
    if (value.empty() || value.size() > 32 ||
        std::isdigit(static_cast<unsigned char>(value.front())) != 0 ||
        (std::isalpha(static_cast<unsigned char>(value.front())) == 0 &&
         value.front() != '_')) {
        return false;
    }
    for (std::size_t i = 1; i < value.size(); ++i) {
        const char character = value[i];
        if (std::isalnum(static_cast<unsigned char>(character)) != 0 ||
            character == '_' || character == '-') {
            continue;
        }
        if (character == '$' && i + 1 == value.size()) continue;
        return false;
    }
    return true;
}

bool localGroupExistsExactlyOnce(
    const std::filesystem::path& path,
    const std::string& expected) {
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0 || !S_ISREG(status.st_mode)) {
        return false;
    }
    std::ifstream stream(path);
    if (!stream.is_open()) return false;
    std::size_t matches = 0;
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        const std::size_t first = line.find(':');
        const std::size_t second = first == std::string::npos
            ? std::string::npos : line.find(':', first + 1);
        const std::size_t third = second == std::string::npos
            ? std::string::npos : line.find(':', second + 1);
        if (first == std::string::npos || second == std::string::npos ||
            third == std::string::npos ||
            line.find(':', third + 1) != std::string::npos) {
            return false;
        }
        const std::string name = line.substr(0, first);
        const std::string gid = line.substr(second + 1, third - second - 1);
        if (!isValidLocalGroupName(name) || gid.empty()) return false;
        for (char character : gid) {
            if (std::isdigit(static_cast<unsigned char>(character)) == 0) {
                return false;
            }
        }
        if (name == expected) ++matches;
    }
    return stream.eof() && matches == 1;
}

} // namespace fic::identity
