#include "modules/dac/sudo/SudoSecurePathPolicyTypeValue.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <stdexcept>
#include <utility>

SudoSecurePathPolicyTypeValue::SudoSecurePathPolicyTypeValue(
    std::string defaultValue)
    : MultiLineTextPolicyTypeValue(",", ":", std::move(defaultValue)) {
    if (!validate(this->defaultValue)) {
        throw std::invalid_argument("Invalid sudo secure_path default");
    }
}

std::string SudoSecurePathPolicyTypeValue::trimCopy(std::string value) {
    value.erase(value.begin(), std::find_if(
        value.begin(), value.end(), [](unsigned char character) {
            return std::isspace(character) == 0;
        }));
    value.erase(std::find_if(
        value.rbegin(), value.rend(), [](unsigned char character) {
            return std::isspace(character) == 0;
        }).base(), value.end());
    return value;
}

bool SudoSecurePathPolicyTypeValue::isSeparator(char value) {
    return value == ',' || value == ':' || value == '\n' || value == '\r';
}

std::vector<std::string> SudoSecurePathPolicyTypeValue::splitSecurePath(
    const std::string& value) {
    std::vector<std::string> paths;
    std::string current;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const char character = value[index];
        if (!isSeparator(character)) {
            current.push_back(character);
            continue;
        }
        paths.push_back(trimCopy(current));
        current.clear();
        if (character == '\r' && index + 1 < value.size() &&
            value[index + 1] == '\n') {
            ++index;
        }
    }
    paths.push_back(trimCopy(current));
    return paths;
}

std::string SudoSecurePathPolicyTypeValue::joinSecurePath(
    const std::vector<std::string>& paths,
    const std::string& delimiter) {
    std::string result;
    for (std::size_t index = 0; index < paths.size(); ++index) {
        if (index != 0) {
            result += delimiter;
        }
        result += paths[index];
    }
    return result;
}

bool SudoSecurePathPolicyTypeValue::isValidAbsoluteDirectoryPath(
    const std::string& path) {
    if (path.empty() || path.front() != '/') {
        return false;
    }
    if ((path.size() > 1 && path.back() == '/') ||
        path.find("//") != std::string::npos) {
        return false;
    }
    const std::string forbiddenCharacters = "\"'\\|<>!@#$%^&*()[]{};:";
    for (char character : path) {
        if (std::isspace(static_cast<unsigned char>(character)) != 0 ||
            forbiddenCharacters.find(character) != std::string::npos) {
            return false;
        }
    }
    const std::filesystem::path candidate(path);
    if (!candidate.is_absolute() || candidate.lexically_normal().string() != path) {
        return false;
    }
    for (const auto& component : candidate) {
        if (component == "." || component == "..") {
            return false;
        }
    }
    return true;
}

bool SudoSecurePathPolicyTypeValue::validate(const std::string& value) {
    if (value.empty()) {
        return false;
    }
    const std::vector<std::string> paths = splitSecurePath(value);
    return !paths.empty() && std::all_of(
        paths.begin(), paths.end(), [](const std::string& path) {
            return isValidAbsoluteDirectoryPath(path);
        });
}

std::string SudoSecurePathPolicyTypeValue::postProcessingValue(
    const std::string& value) {
    if (!validate(value)) {
        return "";
    }
    return json(splitSecurePath(value)).dump();
}

std::string SudoSecurePathPolicyTypeValue::reverse_postProcessingValue(
    const std::string& value) {
    try {
        const json parsedValue = json::parse(value);
        if (!parsedValue.is_array()) {
            return value;
        }
        std::vector<std::string> paths;
        for (const auto& item : parsedValue) {
            if (!item.is_string()) {
                return value;
            }
            paths.push_back(item.get<std::string>());
        }
        return joinSecurePath(paths, ":");
    } catch (const json::parse_error&) {
        return joinSecurePath(splitSecurePath(value), ":");
    } catch (const json::type_error&) {
        return value;
    }
}

std::string SudoSecurePathPolicyTypeValue::getPolicyRestrictionInfo() {
    return "Укажите полный список абсолютных каталогов: политика полностью "
        "заменяет effective sudo secure_path. Компоненты '.' и '..', пустые "
        "компоненты и ненормализованные пути запрещены";
}
