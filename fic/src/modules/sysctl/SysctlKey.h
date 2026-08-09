#ifndef SYSCTLKEY_H
#define SYSCTLKEY_H

#include <algorithm>
#include <cctype>
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

inline std::string stripSysctlDecorations(std::string key) {
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
    return key;
}

inline std::string systemdConfigKeyToCanonicalPath(std::string key) {
    key = stripSysctlDecorations(std::move(key));
    if (key.empty()) {
        return {};
    }

    const std::size_t firstDot = key.find('.');
    const std::size_t firstSlash = key.find('/');
    if (firstSlash != std::string::npos &&
        (firstDot == std::string::npos || firstSlash < firstDot)) {
        return key;
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

inline std::string internalKeyToCanonicalPath(std::string key) {
    key = stripSysctlDecorations(std::move(key));
    if (key.empty()) {
        return {};
    }
    if (key.find('/') != std::string::npos) {
        return key;
    }
    std::replace(key.begin(), key.end(), '.', '/');
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
