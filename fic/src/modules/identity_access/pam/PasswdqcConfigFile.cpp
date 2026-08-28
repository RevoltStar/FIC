#include "modules/identity_access/pam/PasswdqcConfigFile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

struct ParsedLine {
    bool assignment = false;
    std::string key;
    std::string value;
};

bool validKey(const std::string& key)
{
    return !key.empty() &&
        std::all_of(key.begin(), key.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '_';
        });
}

bool parseUnsigned(const std::string& text,
                   unsigned int& result,
                   std::string& error)
{
    if (text.empty() ||
        !std::all_of(text.begin(), text.end(), [](unsigned char character) {
            return std::isdigit(character) != 0;
        })) {
        error = "expected an unsigned decimal integer";
        return false;
    }
    try {
        const unsigned long parsed = std::stoul(text);
        if (parsed > static_cast<unsigned long>(
                         std::numeric_limits<int>::max())) {
            error = "unsigned decimal integer is out of range";
            return false;
        }
        result = static_cast<unsigned int>(parsed);
        return true;
    } catch (...) {
        error = "invalid unsigned decimal integer";
        return false;
    }
}

bool parseLine(const std::string& line,
               ParsedLine& parsed,
               std::string& error,
               std::size_t lineNumber)
{
    parsed = ParsedLine{};
    if (line.empty() || line.front() == '#') {
        return true;
    }
    if (std::any_of(line.begin(), line.end(), [](unsigned char character) {
            return std::isspace(character) != 0;
        })) {
        error = "passwdqc config line " + std::to_string(lineNumber) +
            " contains whitespace; expected option=value";
        return false;
    }
    const auto equals = line.find('=');
    if (equals == std::string::npos || equals == 0 ||
        equals + 1 == line.size() || line.find('=', equals + 1) !=
            std::string::npos) {
        error = "malformed passwdqc config line " +
            std::to_string(lineNumber) + "; expected option=value";
        return false;
    }
    parsed.assignment = true;
    parsed.key = line.substr(0, equals);
    parsed.value = line.substr(equals + 1);
    if (!validKey(parsed.key)) {
        error = "invalid passwdqc option on line " +
            std::to_string(lineNumber);
        return false;
    }
    return true;
}

std::vector<std::string> splitLines(const std::string& content)
{
    std::vector<std::string> lines;
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

std::string joinLines(const std::vector<std::string>& lines)
{
    std::string result;
    for (const auto& line : lines) {
        result += line;
        result.push_back('\n');
    }
    return result;
}

bool readFile(const std::filesystem::path& path,
              bool& existed,
              std::string& content,
              std::string& error)
{
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
    std::ostringstream buffer;
    if (!input.is_open()) {
        error = "could not open " + path.string();
        return false;
    }
    buffer << input.rdbuf();
    if (!input.good() && !input.eof()) {
        error = "could not read " + path.string();
        return false;
    }
    content = buffer.str();
    return true;
}

bool parseDocument(const std::string& content,
                   std::vector<std::string>& lines,
                   std::string& error)
{
    static const std::set<std::string> managedOptions = {
        "min", "passphrase", "match", "similar", "enforce", "retry"
    };
    lines = splitLines(content);
    std::set<std::string> options;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        ParsedLine parsed;
        if (!parseLine(lines[index], parsed, error, index + 1)) {
            return false;
        }
        if (parsed.assignment && !options.insert(parsed.key).second) {
            error = "duplicate passwdqc option " + parsed.key;
            return false;
        }
        if (parsed.assignment &&
            managedOptions.find(parsed.key) != managedOptions.end() &&
            !PasswdqcConfigFile::validateNativeValue(
                parsed.key, parsed.value, error)) {
            error = "invalid passwdqc value on line " +
                std::to_string(index + 1) + ": " + error;
            return false;
        }
    }
    return true;
}

AtomicWriteOptions writeOptions()
{
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.fileMode = 0644;
    options.fileOwner = ::geteuid();
    options.fileGroup = ::getegid();
    return options;
}

} // namespace

bool PasswdqcMinimumsCodec::parse(const std::string& value,
                                  PasswdqcMinimums& result,
                                  std::string& error)
{
    std::array<std::string, 5> fields;
    std::size_t begin = 0;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        const auto comma = value.find(',', begin);
        if ((index + 1 < fields.size() && comma == std::string::npos) ||
            (index + 1 == fields.size() && comma != std::string::npos)) {
            error = "passwdqc min requires exactly five comma-separated values";
            return false;
        }
        fields[index] = value.substr(
            begin, comma == std::string::npos ? std::string::npos : comma - begin);
        begin = comma == std::string::npos ? value.size() : comma + 1;
    }

    PasswdqcMinimums parsed;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (fields[index] == "disabled") {
            parsed.values[index] = std::nullopt;
            continue;
        }
        unsigned int number = 0;
        if (!parseUnsigned(fields[index], number, error)) {
            error = "invalid passwdqc min field " +
                std::to_string(index + 1) + ": " + error;
            return false;
        }
        parsed.values[index] = number;
    }

    const auto rank = [](const std::optional<unsigned int>& field) {
        return field.has_value()
            ? static_cast<unsigned long long>(*field)
            : std::numeric_limits<unsigned long long>::max();
    };
    for (std::size_t index = 1; index < parsed.values.size(); ++index) {
        if (rank(parsed.values[index]) > rank(parsed.values[index - 1])) {
            error = "each passwdqc min value must not exceed the previous one";
            return false;
        }
    }
    result = parsed;
    error.clear();
    return true;
}

std::string PasswdqcMinimumsCodec::serialize(const PasswdqcMinimums& value)
{
    std::string result;
    for (std::size_t index = 0; index < value.values.size(); ++index) {
        if (index != 0) {
            result.push_back(',');
        }
        result += value.values[index].has_value()
            ? std::to_string(*value.values[index])
            : "disabled";
    }
    return result;
}

bool PasswdqcConfigFile::validateNativeValue(const std::string& option,
                                              const std::string& value,
                                              std::string& error)
{
    if (!validKey(option) || value.empty() ||
        value.find_first_of(" \t\r\n#=") != std::string::npos) {
        error = "invalid passwdqc option assignment";
        return false;
    }
    if (option == "min") {
        PasswdqcMinimums parsed;
        return PasswdqcMinimumsCodec::parse(value, parsed, error);
    }
    if (option == "similar") {
        if (value == "permit" || value == "deny") {
            error.clear();
            return true;
        }
        error = "passwdqc similar must be permit or deny";
        return false;
    }
    if (option == "enforce") {
        if (value == "none" || value == "users" || value == "everyone") {
            error.clear();
            return true;
        }
        error = "passwdqc enforce must be none, users or everyone";
        return false;
    }
    if (option == "passphrase" || option == "match" || option == "retry") {
        unsigned int unused = 0;
        return parseUnsigned(value, unused, error);
    }
    error = "unsupported managed passwdqc option: " + option;
    return false;
}

bool PasswdqcConfigFile::hasOnlyValue(
    const std::filesystem::path& path,
    const std::string& option,
    const std::string& expectedValue,
    std::string& error)
{
    if (!validateNativeValue(option, expectedValue, error)) {
        return false;
    }
    bool existed = false;
    std::string content;
    if (!readFile(path, existed, content, error) || !existed) {
        if (error.empty()) {
            error = "passwdqc config does not exist: " + path.string();
        }
        return false;
    }
    std::vector<std::string> lines;
    if (!parseDocument(content, lines, error)) {
        return false;
    }
    for (std::size_t index = 0; index < lines.size(); ++index) {
        ParsedLine parsed;
        if (!parseLine(lines[index], parsed, error, index + 1)) {
            return false;
        }
        if (parsed.assignment && parsed.key == option) {
            if (parsed.value == expectedValue) {
                error.clear();
                return true;
            }
            error = "unexpected value for " + option + " in " +
                path.string() + ": " + parsed.value;
            return false;
        }
    }
    error = "option " + option + " was not found in " + path.string();
    return false;
}

bool PasswdqcConfigFile::setValue(const std::filesystem::path& path,
                                  const std::string& option,
                                  const std::string& value,
                                  std::string& error,
                                  Writer writer)
{
    if (!validateNativeValue(option, value, error)) {
        return false;
    }
    bool existed = false;
    std::string original;
    if (!readFile(path, existed, original, error)) {
        return false;
    }
    std::vector<std::string> lines;
    if (!parseDocument(original, lines, error)) {
        return false;
    }
    bool replaced = false;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        ParsedLine parsed;
        if (!parseLine(lines[index], parsed, error, index + 1)) {
            return false;
        }
        if (parsed.assignment && parsed.key == option) {
            lines[index] = option + "=" + value;
            replaced = true;
        }
    }
    if (!replaced) {
        lines.push_back(option + "=" + value);
    }
    if (!writer) {
        writer = AtomicFileWriter::write;
    }
    if (!writer(path.string(), joinLines(lines), writeOptions(), &error)) {
        return false;
    }
    if (hasOnlyValue(path, option, value, error)) {
        return true;
    }

    std::string rollbackError;
    if (existed) {
        if (!writer(path.string(), original, writeOptions(), &rollbackError)) {
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

} // namespace fic::identity::pam
