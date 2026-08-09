#ifndef SYSCTLKEY_H
#define SYSCTLKEY_H

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

namespace fic::sysctl {

inline std::string trimKey(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char c) {
        return !std::isspace(c);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char c) {
        return !std::isspace(c);
    }).base(), value.end());
    return value;
}

inline std::vector<std::string> splitKey(const std::string& value, char separator) {
    std::vector<std::string> result;
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t next = value.find(separator, start);
        result.push_back(value.substr(
            start,
            next == std::string::npos ? std::string::npos : next - start
        ));
        if (next == std::string::npos) {
            break;
        }
        start = next + 1;
    }
    return result;
}

inline std::string joinKeyParts(const std::vector<std::string>& parts,
                                std::size_t first,
                                std::size_t lastExclusive,
                                char separator) {
    std::string result;
    for (std::size_t index = first; index < lastExclusive; ++index) {
        if (!result.empty()) {
            result += separator;
        }
        result += parts[index];
    }
    return result;
}

inline std::string canonicalSysctlPath(std::string key) {
    key = trimKey(std::move(key));
    if (!key.empty() && key.front() == '-') {
        key.erase(key.begin());
        key = trimKey(std::move(key));
    }
    constexpr const char* procPrefix = "/proc/sys/";
    if (key.compare(0, std::char_traits<char>::length(procPrefix), procPrefix) == 0) {
        key.erase(0, std::char_traits<char>::length(procPrefix));
    }
    while (!key.empty() && key.front() == '/') {
        key.erase(key.begin());
    }
    if (key.empty()) {
        return {};
    }

    const std::size_t firstDot = key.find('.');
    const std::size_t firstSlash = key.find('/');
    if (firstSlash != std::string::npos &&
        (firstDot == std::string::npos || firstSlash < firstDot)) {
        return key;
    }

    if (firstSlash == std::string::npos) {
        const std::vector<std::string> parts = splitKey(key, '.');
        if (parts.size() >= 5 && parts[0] == "net" &&
            (parts[1] == "ipv4" || parts[1] == "ipv6") &&
            (parts[2] == "conf" || parts[2] == "neigh")) {
            return parts[0] + "/" + parts[1] + "/" + parts[2] + "/" +
                   joinKeyParts(parts, 3, parts.size() - 1, '.') + "/" +
                   parts.back();
        }
    }

    for (char& ch : key) {
        if (ch == '.') {
            ch = '/';
        } else if (ch == '/') {
            ch = '.';
        }
    }
    return key;
}

inline std::string configKeyFromCanonicalPath(const std::string& path) {
    const std::vector<std::string> parts = splitKey(path, '/');
    const bool hasLiteralDot = std::any_of(parts.begin(), parts.end(), [](const std::string& part) {
        return part.find('.') != std::string::npos;
    });
    if (hasLiteralDot) {
        return path;
    }
    std::string result = path;
    std::replace(result.begin(), result.end(), '/', '.');
    return result;
}

} // namespace fic::sysctl

#endif // SYSCTLKEY_H
