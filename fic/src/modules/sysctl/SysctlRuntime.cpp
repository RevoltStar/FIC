#include "modules/sysctl/SysctlRuntime.h"

#include "modules/sysctl/SysctlKey.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace {

constexpr std::size_t maxRuntimeValueBytes = 64 * 1024;

std::string trimCopy(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), value.end());
    return value;
}

bool validComponent(const std::string& component) {
    if (component.empty() || component == "." || component == "..") {
        return false;
    }
    return std::all_of(component.begin(), component.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.';
    });
}

bool writeAll(int fd, const std::string& value, std::string& error) {
    const char* current = value.data();
    std::size_t remaining = value.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd, current, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = std::strerror(errno);
            return false;
        }
        if (written == 0) {
            error = "write returned 0";
            return false;
        }
        current += written;
        remaining -= static_cast<std::size_t>(written);
    }
    return true;
}

} // namespace

SysctlRuntime::SysctlRuntime(SysctlRuntimeOptions options)
    : options_(std::move(options)) {
}

bool SysctlRuntime::parameterPath(const std::string& key,
                                  std::filesystem::path& path,
                                  std::string& error) const {
    if (key.empty()) {
        error = "Пустое имя runtime sysctl-параметра";
        return false;
    }
    if (!options_.root.is_absolute() ||
        options_.root.lexically_normal() != options_.root) {
        error = "Корневой каталог runtime sysctl должен быть абсолютным и нормализованным";
        return false;
    }

    const std::string relative = fic::sysctl::internalKeyToCanonicalPath(key);
    if (relative.empty()) {
        error = "Недопустимое имя runtime sysctl-параметра: " + key;
        return false;
    }

    std::filesystem::path result = options_.root;
    std::size_t start = 0;
    while (start <= relative.size()) {
        const std::size_t separator = relative.find('/', start);
        const std::string component = relative.substr(
            start,
            separator == std::string::npos ? std::string::npos : separator - start
        );
        if (!validComponent(component)) {
            error = "Недопустимое имя runtime sysctl-параметра: " + key;
            return false;
        }
        result /= component;
        if (separator == std::string::npos) {
            break;
        }
        start = separator + 1;
    }

    path = result;
    error.clear();
    return true;
}

bool SysctlRuntime::readValue(const std::string& key,
                              std::string& value,
                              std::string& error) const {
    std::filesystem::path path;
    if (!parameterPath(key, path, error)) {
        return false;
    }

    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        error = "Не удалось открыть runtime sysctl " + path.string() +
                " для чтения: " + std::strerror(errno);
        return false;
    }

    std::string content;
    char buffer[4096];
    while (true) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            content.append(buffer, static_cast<std::size_t>(count));
            if (content.size() > maxRuntimeValueBytes) {
                ::close(fd);
                error = "Runtime-значение sysctl превышает допустимый размер: " + path.string();
                return false;
            }
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            const std::string readError = std::strerror(errno);
            ::close(fd);
            error = "Не удалось прочитать runtime sysctl " + path.string() +
                    ": " + readError;
            return false;
        }
        break;
    }
    ::close(fd);

    value = trimCopy(std::move(content));
    error.clear();
    return true;
}

SysctlRuntimeResult SysctlRuntime::ensureValue(const std::string& key,
                                               const std::string& value) const {
    SysctlRuntimeResult result;
    if (value.find('\0') != std::string::npos ||
        value.find('\n') != std::string::npos ||
        value.find('\r') != std::string::npos) {
        result.message = "Runtime-значение sysctl содержит недопустимый перевод строки";
        return result;
    }

    std::string current;
    std::string error;
    if (!readValue(key, current, error)) {
        result.message = error;
        return result;
    }
    const std::string expected = trimCopy(value);
    if (current == expected) {
        result.ok = true;
        result.message = "Runtime-значение sysctl уже соответствует политике";
        return result;
    }

    std::filesystem::path path;
    if (!parameterPath(key, path, error)) {
        result.message = error;
        return result;
    }
    const int fd = ::open(path.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        result.message = "Не удалось открыть runtime sysctl " + path.string() +
                         " для записи: " + std::strerror(errno);
        return result;
    }
    if (!writeAll(fd, expected, error)) {
        ::close(fd);
        result.message = "Не удалось записать runtime sysctl " + path.string() +
                         ": " + error;
        return result;
    }
    if (::close(fd) != 0) {
        result.message = "Не удалось закрыть runtime sysctl " + path.string() +
                         " после записи: " + std::strerror(errno);
        return result;
    }

    std::string verified;
    if (!readValue(key, verified, error)) {
        result.message = "Не удалось проверить runtime sysctl после записи: " + error;
        return result;
    }
    if (verified != expected) {
        result.message = "Runtime sysctl " + key + " после записи имеет значение '" +
                         verified + "', ожидалось '" + expected + "'";
        return result;
    }

    result.ok = true;
    result.changed = true;
    result.message = "Runtime-отклонение sysctl исправлено";
    return result;
}
