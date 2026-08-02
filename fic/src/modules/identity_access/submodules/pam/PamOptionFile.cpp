#include "modules/identity_access/submodules/pam/PamOptionFile.h"

#include <fic/core/AtomicFileWriter.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

bool validKey(const std::string& key) {
    return !key.empty() &&
        std::all_of(key.begin(), key.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '_' || c == '-';
        });
}

std::string trimCopy(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();
    return std::string(first, last);
}

bool parseAssignment(const std::string& line,
                     std::string& key,
                     std::string& value) {
    const std::string trimmed = trimCopy(line);
    if (trimmed.empty() || trimmed.front() == '#') {
        return false;
    }
    const std::size_t equals = trimmed.find('=');
    if (equals == std::string::npos) {
        return false;
    }
    key = trimCopy(trimmed.substr(0, equals));
    value = trimCopy(trimmed.substr(equals + 1));
    const std::size_t comment = value.find('#');
    if (comment != std::string::npos) {
        value = trimCopy(value.substr(0, comment));
    }
    return validKey(key);
}

bool parseFlagLine(const std::string& line,
                   const std::string& expectedKey,
                   bool& isFlag,
                   bool& malformed) {
    isFlag = false;
    malformed = false;
    std::string code = line;
    const std::size_t comment = code.find('#');
    if (comment != std::string::npos) {
        code.erase(comment);
    }
    code = trimCopy(std::move(code));
    if (code.empty()) {
        return true;
    }
    if (code == expectedKey) {
        isFlag = true;
        return true;
    }
    if (code.compare(0, expectedKey.size(), expectedKey) == 0 &&
        code.size() > expectedKey.size()) {
        const unsigned char delimiter =
            static_cast<unsigned char>(code[expectedKey.size()]);
        malformed = delimiter == '=' || std::isspace(delimiter) != 0;
    }
    return true;
}

bool readFile(const std::filesystem::path& path,
              bool& existed,
              std::string& content,
              std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        if (errno == ENOENT) {
            existed = false;
            content.clear();
            return true;
        }
        error = "could not inspect " + path.string() + ": " +
            std::strerror(errno);
        return false;
    }
    existed = true;
    if (S_ISLNK(info.st_mode)) {
        error = "refusing to use symbolic link: " + path.string();
        return false;
    }
    if (!S_ISREG(info.st_mode)) {
        error = "refusing to use non-regular file: " + path.string();
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        error = "could not open " + path.string();
        return false;
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (!input.good() && !input.eof()) {
        error = "could not read " + path.string();
        return false;
    }
    content = buffer.str();
    return true;
}

AtomicWriteOptions writeOptions() {
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0644;
    options.fileOwner = ::geteuid();
    options.fileGroup = ::getegid();
    return options;
}

std::vector<std::string> splitLines(const std::string& content) {
    std::vector<std::string> lines;
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::string joinLines(const std::vector<std::string>& lines) {
    std::string content;
    for (const auto& line : lines) {
        content += line;
        content.push_back('\n');
    }
    return content;
}

} // namespace

bool PamOptionFile::setValue(const std::filesystem::path& path,
                             const std::string& key,
                             const std::string& value,
                             std::string& error) {
    if (!validKey(key) || value.empty() ||
        value.find_first_of("\r\n") != std::string::npos) {
        error = "invalid PAM option assignment";
        return false;
    }

    bool existed = false;
    std::string originalContent;
    if (!readFile(path, existed, originalContent, error)) {
        return false;
    }

    std::vector<std::string> lines = splitLines(originalContent);
    bool replaced = false;
    for (auto& line : lines) {
        std::string parsedKey;
        std::string parsedValue;
        if (parseAssignment(line, parsedKey, parsedValue) && parsedKey == key) {
            const std::size_t first = line.find_first_not_of(" \t");
            const std::string indentation =
                first == std::string::npos ? "" : line.substr(0, first);
            const std::size_t comment = line.find('#');
            const std::string commentSuffix =
                comment == std::string::npos ? "" : " " + line.substr(comment);
            line = indentation + key + " = " + value + commentSuffix;
            replaced = true;
        }
    }
    if (!replaced) {
        lines.push_back(key + " = " + value);
    }

    if (!AtomicFileWriter::write(
            path.string(), joinLines(lines), writeOptions(), &error)) {
        return false;
    }
    if (hasOnlyValue(path, key, value, error)) {
        return true;
    }

    std::string rollbackError;
    if (existed) {
        if (!AtomicFileWriter::write(
                path.string(), originalContent, writeOptions(), &rollbackError)) {
            error += "; rollback failed: " + rollbackError;
        }
    } else {
        std::error_code removeError;
        std::filesystem::remove(path, removeError);
        if (removeError) {
            error += "; rollback failed: " + removeError.message();
        }
    }
    return false;
}

bool PamOptionFile::hasOnlyValue(
    const std::filesystem::path& path,
    const std::string& key,
    const std::string& expectedValue,
    std::string& error) {
    bool existed = false;
    std::string content;
    if (!readFile(path, existed, content, error) || !existed) {
        if (error.empty()) {
            error = "PAM option file does not exist: " + path.string();
        }
        return false;
    }

    bool found = false;
    for (const auto& line : splitLines(content)) {
        std::string parsedKey;
        std::string parsedValue;
        if (!parseAssignment(line, parsedKey, parsedValue) || parsedKey != key) {
            continue;
        }
        found = true;
        if (parsedValue != expectedValue) {
            error = "unexpected value for " + key + " in " + path.string() +
                ": " + parsedValue;
            return false;
        }
    }
    if (!found) {
        error = "option " + key + " was not found in " + path.string();
        return false;
    }
    return true;
}

bool PamOptionFile::setFlag(const std::filesystem::path& path,
                            const std::string& key,
                            bool enabled,
                            std::string& error) {
    if (!validKey(key)) {
        error = "invalid PAM flag";
        return false;
    }

    bool existed = false;
    std::string originalContent;
    if (!readFile(path, existed, originalContent, error)) {
        return false;
    }
    if (!existed && !enabled) {
        return true;
    }

    std::vector<std::string> lines = splitLines(originalContent);
    bool found = false;
    for (auto& line : lines) {
        bool isFlag = false;
        bool malformed = false;
        parseFlagLine(line, key, isFlag, malformed);
        if (malformed) {
            error = "malformed PAM flag " + key + " in " + path.string();
            return false;
        }
        if (!isFlag) {
            continue;
        }
        found = true;
        const std::size_t first = line.find_first_not_of(" \t");
        const std::string indentation =
            first == std::string::npos ? "" : line.substr(0, first);
        const std::size_t comment = line.find('#');
        if (enabled) {
            const std::string commentSuffix = comment == std::string::npos
                ? ""
                : " " + line.substr(comment);
            line = indentation + key + commentSuffix;
        } else {
            line = comment == std::string::npos
                ? ""
                : indentation + line.substr(comment);
        }
    }
    if (enabled && !found) {
        lines.push_back(key);
    }

    if (!AtomicFileWriter::write(
            path.string(), joinLines(lines), writeOptions(), &error)) {
        return false;
    }
    if (hasFlag(path, key, enabled, error)) {
        return true;
    }

    std::string rollbackError;
    if (existed) {
        if (!AtomicFileWriter::write(
                path.string(), originalContent, writeOptions(), &rollbackError)) {
            error += "; rollback failed: " + rollbackError;
        }
    } else {
        std::error_code removeError;
        std::filesystem::remove(path, removeError);
        if (removeError) {
            error += "; rollback failed: " + removeError.message();
        }
    }
    return false;
}

bool PamOptionFile::hasFlag(const std::filesystem::path& path,
                            const std::string& key,
                            bool expectedEnabled,
                            std::string& error) {
    if (!validKey(key)) {
        error = "invalid PAM flag";
        return false;
    }

    bool existed = false;
    std::string content;
    if (!readFile(path, existed, content, error)) {
        return false;
    }
    if (!existed) {
        if (!expectedEnabled) {
            return true;
        }
        error = "PAM option file does not exist: " + path.string();
        return false;
    }

    bool found = false;
    for (const auto& line : splitLines(content)) {
        bool isFlag = false;
        bool malformed = false;
        parseFlagLine(line, key, isFlag, malformed);
        if (malformed) {
            error = "malformed PAM flag " + key + " in " + path.string();
            return false;
        }
        found = found || isFlag;
    }
    if (found != expectedEnabled) {
        error = "unexpected state for " + key + " in " + path.string();
        return false;
    }
    return true;
}

} // namespace fic::identity::pam
