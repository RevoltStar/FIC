#include "modules/dac/submodules/sudo/SudoersConfiguration.h"

#include <fic/core/AtomicFileWriter.h>
#include <fic/core/ProcessExecutor.h>
#include <fic/core/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

std::string trimCopy(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char c) {
        return !std::isspace(c);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char c) {
        return !std::isspace(c);
    }).base(), value.end());
    return value;
}

bool readExistingFile(const std::filesystem::path& path, std::string& content, std::string& error) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        error = "Не удалось открыть sudoers-файл: " + path.string();
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        error = "Не удалось прочитать sudoers-файл: " + path.string();
        return false;
    }
    content = buffer.str();
    return true;
}

std::vector<std::pair<size_t, std::string>> physicalLines(const std::string& content) {
    std::vector<std::pair<size_t, std::string>> result;
    std::istringstream stream(content);
    std::string line;
    size_t number = 1;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        result.emplace_back(number++, line);
    }
    if (content.empty()) {
        return result;
    }
    return result;
}

size_t commentPosition(const std::string& line) {
    bool single = false;
    bool doubleQuoted = false;
    bool escaped = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '\'' && !doubleQuoted) {
            single = !single;
            continue;
        }
        if (c == '"' && !single) {
            doubleQuoted = !doubleQuoted;
            continue;
        }
        if (c == '#' && !single && !doubleQuoted) {
            return i;
        }
    }
    return std::string::npos;
}

std::string stripInlineComment(const std::string& line) {
    const size_t position = commentPosition(line);
    return position == std::string::npos ? line : line.substr(0, position);
}

bool hasContinuation(const std::string& line) {
    std::string trimmed = trimCopy(line);
    if (trimmed.empty() || trimmed.back() != '\\') {
        return false;
    }
    size_t slashCount = 0;
    for (size_t i = trimmed.size(); i > 0 && trimmed[i - 1] == '\\'; --i) {
        ++slashCount;
    }
    return slashCount % 2 == 1;
}

std::string unquotePath(std::string path) {
    path = trimCopy(path);
    if (path.size() >= 2 &&
        ((path.front() == '"' && path.back() == '"') ||
         (path.front() == '\'' && path.back() == '\''))) {
        return path.substr(1, path.size() - 2);
    }
    return path;
}

enum class IncludeKind { None, File, Directory };

IncludeKind parseInclude(const std::string& logicalLine, std::string& path) {
    const std::string trimmed = trimCopy(logicalLine);
    const std::pair<const char*, IncludeKind> prefixes[] = {
        {"@includedir", IncludeKind::Directory},
        {"#includedir", IncludeKind::Directory},
        {"@include", IncludeKind::File},
        {"#include", IncludeKind::File}
    };
    for (const auto& [prefix, kind] : prefixes) {
        const size_t length = std::char_traits<char>::length(prefix);
        if (trimmed.compare(0, length, prefix) == 0 &&
            (trimmed.size() == length || std::isspace(static_cast<unsigned char>(trimmed[length])))) {
            path = unquotePath(trimmed.substr(length));
            return path.empty() ? IncludeKind::None : kind;
        }
    }
    return IncludeKind::None;
}

bool ignoredIncludedirName(const std::string& name) {
    return name.empty() || name.front() == '.' || name.back() == '~' ||
           name.find('.') != std::string::npos;
}

std::vector<std::string> splitDefaultsParameters(const std::string& input) {
    std::vector<std::string> result;
    std::string current;
    bool single = false;
    bool doubleQuoted = false;
    bool escaped = false;
    for (char c : input) {
        if (escaped) {
            current.push_back(c);
            escaped = false;
            continue;
        }
        if (c == '\\') {
            current.push_back(c);
            escaped = true;
            continue;
        }
        if (c == '\'' && !doubleQuoted) {
            single = !single;
        } else if (c == '"' && !single) {
            doubleQuoted = !doubleQuoted;
        }
        if (c == ',' && !single && !doubleQuoted) {
            result.push_back(trimCopy(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!trimCopy(current).empty()) {
        result.push_back(trimCopy(current));
    }
    return result;
}

bool parseGlobalDefaults(const std::string& logicalLine,
                         const std::string& requestedKey,
                         std::string& value) {
    std::string line = trimCopy(stripInlineComment(logicalLine));
    constexpr const char* prefix = "Defaults";
    constexpr size_t prefixLength = 8;
    if (line.compare(0, prefixLength, prefix) != 0 || line.size() <= prefixLength ||
        !std::isspace(static_cast<unsigned char>(line[prefixLength]))) {
        return false;
    }

    bool found = false;
    for (std::string parameter : splitDefaultsParameters(line.substr(prefixLength))) {
        parameter = trimCopy(parameter);
        if (parameter == requestedKey) {
            value = "ENABLE";
            found = true;
            continue;
        }
        if (parameter == "!" + requestedKey) {
            value = "DISABLE";
            found = true;
            continue;
        }

        size_t operatorPosition = parameter.find("+=");
        size_t operatorLength = 2;
        if (operatorPosition == std::string::npos) {
            operatorPosition = parameter.find("-=");
        }
        if (operatorPosition == std::string::npos) {
            operatorPosition = parameter.find('=');
            operatorLength = 1;
        }
        if (operatorPosition == std::string::npos) {
            continue;
        }
        if (trimCopy(parameter.substr(0, operatorPosition)) == requestedKey) {
            value = trimCopy(parameter.substr(operatorPosition + operatorLength));
            found = true;
        }
    }
    return found;
}

bool startsManagedDefault(const std::string& line, const std::string& key) {
    std::string ignored;
    return parseGlobalDefaults(line, key, ignored);
}

bool tokenBoundary(char c) {
    return !(std::isalnum(static_cast<unsigned char>(c)) || c == '_');
}

bool outsideQuotesAt(const std::string& text, size_t requestedPosition) {
    bool single = false;
    bool doubleQuoted = false;
    bool escaped = false;
    for (size_t i = 0; i < requestedPosition && i < text.size(); ++i) {
        const char c = text[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '\'' && !doubleQuoted) {
            single = !single;
        } else if (c == '"' && !single) {
            doubleQuoted = !doubleQuoted;
        }
    }
    return !single && !doubleQuoted;
}

bool sudoersOptionName(const std::string& name) {
    return name == "CWD" || name == "CHROOT" || name == "TIMEOUT" ||
           name == "NOTBEFORE" || name == "NOTAFTER" || name == "ROLE" ||
           name == "TYPE" || name == "APPARMOR_PROFILE" || name == "PRIVS" ||
           name == "LIMITPRIVS";
}

bool sudoersOptionToken(const std::string& token) {
    const size_t equals = token.find('=');
    return equals != std::string::npos && sudoersOptionName(token.substr(0, equals));
}

size_t rewriteCommandSpecSegment(std::string& segment) {
    size_t cursor = 0;
    while (cursor < segment.size() && std::isspace(static_cast<unsigned char>(segment[cursor]))) {
        ++cursor;
    }

    if (cursor < segment.size() && segment[cursor] == '(') {
        bool single = false;
        bool doubleQuoted = false;
        bool escaped = false;
        int depth = 0;
        for (; cursor < segment.size(); ++cursor) {
            const char c = segment[cursor];
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '\'' && !doubleQuoted) {
                single = !single;
            } else if (c == '"' && !single) {
                doubleQuoted = !doubleQuoted;
            } else if (!single && !doubleQuoted && c == '(') {
                ++depth;
            } else if (!single && !doubleQuoted && c == ')' && --depth == 0) {
                ++cursor;
                break;
            }
        }
    }

    size_t changes = 0;
    while (cursor < segment.size()) {
        while (cursor < segment.size() && std::isspace(static_cast<unsigned char>(segment[cursor]))) {
            ++cursor;
        }
        const size_t tokenStart = cursor;
        while (cursor < segment.size() &&
               !std::isspace(static_cast<unsigned char>(segment[cursor])) &&
               segment[cursor] != ':') {
            ++cursor;
        }
        if (tokenStart == cursor) {
            break;
        }
        const std::string token = segment.substr(tokenStart, cursor - tokenStart);
        size_t afterToken = cursor;
        while (afterToken < segment.size() &&
               std::isspace(static_cast<unsigned char>(segment[afterToken]))) {
            ++afterToken;
        }

        if (afterToken < segment.size() && segment[afterToken] == ':') {
            if (token == "NOPASSWD") {
                segment.replace(tokenStart, token.size(), "PASSWD");
                const size_t shrink = token.size() - std::string("PASSWD").size();
                afterToken -= shrink;
                ++changes;
            }
            cursor = afterToken + 1;
            continue;
        }
        if (sudoersOptionToken(token)) {
            cursor = afterToken;
            continue;
        }
        if (sudoersOptionName(token) && afterToken < segment.size() &&
            segment[afterToken] == '=') {
            cursor = afterToken + 1;
            while (cursor < segment.size() &&
                   std::isspace(static_cast<unsigned char>(segment[cursor]))) {
                ++cursor;
            }
            while (cursor < segment.size() &&
                   !std::isspace(static_cast<unsigned char>(segment[cursor]))) {
                ++cursor;
            }
            continue;
        }
        break;
    }
    return changes;
}

size_t replaceNoPasswordTags(std::string& code) {
    const size_t firstEquals = code.find('=');
    if (firstEquals == std::string::npos) {
        return 0;
    }

    std::string rewritten = code.substr(0, firstEquals + 1);
    const std::string commandList = code.substr(firstEquals + 1);
    size_t segmentStart = 0;
    bool single = false;
    bool doubleQuoted = false;
    bool escaped = false;
    int parenthesisDepth = 0;
    size_t changes = 0;

    for (size_t i = 0; i <= commandList.size(); ++i) {
        const bool atEnd = i == commandList.size();
        const char c = atEnd ? '\0' : commandList[i];
        if (!atEnd) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '\'' && !doubleQuoted) {
                single = !single;
            } else if (c == '"' && !single) {
                doubleQuoted = !doubleQuoted;
            } else if (!single && !doubleQuoted && c == '(') {
                ++parenthesisDepth;
            } else if (!single && !doubleQuoted && c == ')' && parenthesisDepth > 0) {
                --parenthesisDepth;
            }
        }

        if (!atEnd && (c != ',' || single || doubleQuoted || parenthesisDepth != 0)) {
            continue;
        }

        std::string segment = commandList.substr(segmentStart, i - segmentStart);
        changes += rewriteCommandSpecSegment(segment);
        rewritten += segment;
        if (!atEnd) {
            rewritten.push_back(',');
        }
        segmentStart = i + 1;
    }

    code = std::move(rewritten);
    return changes;
}

bool containsTokenFollowedByColon(const std::string& code, const std::string& token,
                                  size_t start = 0) {
    size_t position = start;
    while ((position = code.find(token, position)) != std::string::npos) {
        const bool leftBoundary = position == 0 || tokenBoundary(code[position - 1]);
        size_t after = position + token.size();
        const bool rightBoundary = after == code.size() || tokenBoundary(code[after]);
        if (leftBoundary && rightBoundary && outsideQuotesAt(code, position)) {
            while (after < code.size() &&
                   std::isspace(static_cast<unsigned char>(code[after]))) {
                ++after;
            }
            if (after < code.size() && code[after] == ':') {
                return true;
            }
        }
        position += token.size();
    }
    return false;
}

bool hasAmbiguousAdditionalHostSpec(const std::string& code) {
    const size_t firstEquals = code.find('=');
    if (firstEquals == std::string::npos) {
        return false;
    }

    size_t colon = code.find(':', firstEquals + 1);
    while (colon != std::string::npos) {
        if (!outsideQuotesAt(code, colon)) {
            colon = code.find(':', colon + 1);
            continue;
        }
        const size_t additionalEquals = code.find('=', colon + 1);
        if (additionalEquals == std::string::npos) {
            return false;
        }
        if (outsideQuotesAt(code, additionalEquals) &&
            containsTokenFollowedByColon(code, "NOPASSWD", additionalEquals + 1)) {
            return true;
        }
        colon = code.find(':', colon + 1);
    }
    return false;
}

size_t replacePlainToken(std::string& code,
                         const std::string& from,
                         const std::string& to) {
    size_t changes = 0;
    size_t position = 0;
    while ((position = code.find(from, position)) != std::string::npos) {
        const bool leftBoundary = position == 0 || tokenBoundary(code[position - 1]);
        const size_t end = position + from.size();
        const bool rightBoundary = end == code.size() || tokenBoundary(code[end]);
        if (leftBoundary && rightBoundary && outsideQuotesAt(code, position)) {
            code.replace(position, from.size(), to);
            position += to.size();
            ++changes;
        } else {
            position = end;
        }
    }
    return changes;
}

size_t disableExemptGroup(std::string& code) {
    size_t changes = 0;
    size_t position = 0;
    constexpr const char* key = "exempt_group";
    constexpr size_t keyLength = 12;
    while ((position = code.find(key, position)) != std::string::npos) {
        const bool leftBoundary = position == 0 || tokenBoundary(code[position - 1]);
        size_t after = position + keyLength;
        const bool rightBoundary = after == code.size() || tokenBoundary(code[after]);
        if (!leftBoundary || !rightBoundary || !outsideQuotesAt(code, position) ||
            (position > 0 && code[position - 1] == '!')) {
            position = after;
            continue;
        }
        while (after < code.size() && std::isspace(static_cast<unsigned char>(code[after]))) {
            ++after;
        }
        if (after >= code.size() || code[after] != '=') {
            position = after;
            continue;
        }
        size_t end = code.find(',', after + 1);
        if (end == std::string::npos) {
            end = code.size();
        }
        code.replace(position, end - position, "!exempt_group");
        position += keyLength + 1;
        ++changes;
    }
    return changes;
}

struct RewriteResult {
    std::string content;
    std::vector<std::string> diagnostics;
    size_t changes = 0;
};

bool multilineBlockMayDisableAuthentication(
    const std::vector<std::pair<size_t, std::string>>& lines,
    size_t begin,
    size_t end) {
    std::string logical;
    for (size_t index = begin; index <= end; ++index) {
        std::string code = stripInlineComment(lines[index].second);
        if (hasContinuation(code)) {
            const size_t slash = code.find_last_not_of(" \t\r\n");
            code.erase(slash);
        }
        logical += " " + code;
    }
    if (containsTokenFollowedByColon(logical, "NOPASSWD")) {
        return true;
    }
    std::string rewritten = logical;
    return replacePlainToken(rewritten, "!authenticate", "authenticate") > 0 ||
           disableExemptGroup(rewritten) > 0;
}

RewriteResult rewriteAuthentication(const std::filesystem::path& path,
                                    const std::string& content) {
    RewriteResult result;
    const bool finalNewline = !content.empty() && content.back() == '\n';
    const auto lines = physicalLines(content);
    for (size_t index = 0; index < lines.size(); ++index) {
        size_t blockEnd = index;
        while (blockEnd + 1 < lines.size() && hasContinuation(lines[blockEnd].second)) {
            ++blockEnd;
        }
        if (blockEnd > index && multilineBlockMayDisableAuthentication(lines, index, blockEnd)) {
            result.diagnostics.push_back(path.string() + ":" +
                                         std::to_string(lines[index].first) +
                                         " (неподдерживаемое многострочное правило)");
            for (size_t originalIndex = index; originalIndex <= blockEnd; ++originalIndex) {
                result.content += lines[originalIndex].second;
                if (originalIndex + 1 < lines.size() || finalNewline) {
                    result.content.push_back('\n');
                }
            }
            index = blockEnd;
            continue;
        }

        std::string line = lines[index].second;
        const size_t comment = commentPosition(line);
        std::string code = comment == std::string::npos ? line : line.substr(0, comment);
        const std::string suffix = comment == std::string::npos ? "" : line.substr(comment);
        const std::string trimmed = trimCopy(code);
        size_t lineChanges = 0;

        if (trimmed.compare(0, 8, "Defaults") == 0) {
            lineChanges += replacePlainToken(code, "!authenticate", "authenticate");
            lineChanges += disableExemptGroup(code);
        } else {
            if (hasAmbiguousAdditionalHostSpec(code)) {
                result.diagnostics.push_back(path.string() + ":" +
                                             std::to_string(lines[index].first) +
                                             " (неподдерживаемый составной Host_Spec)");
            } else {
                lineChanges += replaceNoPasswordTags(code);
            }
        }

        if (lineChanges > 0) {
            result.diagnostics.push_back(path.string() + ":" +
                                         std::to_string(lines[index].first));
            result.changes += lineChanges;
        }
        result.content += code + suffix;
        if (index + 1 < lines.size() || finalNewline) {
            result.content.push_back('\n');
        }
    }
    return result;
}

std::filesystem::path normalizedExistingPath(const std::filesystem::path& path) {
    std::error_code error;
    const auto result = std::filesystem::canonical(path, error);
    return error ? std::filesystem::absolute(path).lexically_normal() : result;
}

} // namespace

SudoersConfiguration::SudoersConfiguration(SudoersConfigurationOptions options)
    : options_(std::move(options)) {
}

void SudoersConfiguration::clear() {
    documents_.clear();
    orderedLines_.clear();
    includedDirectories_.clear();
}

bool SudoersConfiguration::load(std::string& error) {
    clear();
    std::error_code existsError;
    if (!std::filesystem::exists(options_.mainPath, existsError) || existsError) {
        error = "Основной sudoers-файл не существует: " + options_.mainPath.string();
        return false;
    }
    std::vector<std::filesystem::path> stack;
    return expandFile(options_.mainPath, stack, 0, error);
}

std::optional<size_t> SudoersConfiguration::loadDocument(const std::filesystem::path& path,
                                                         std::string& error) {
    struct stat linkInfo {};
    if (::lstat(path.c_str(), &linkInfo) != 0) {
        error = "Не удалось проверить sudoers-файл: " + path.string();
        return std::nullopt;
    }
    if (S_ISLNK(linkInfo.st_mode)) {
        error = "Символические ссылки sudoers не поддерживаются: " + path.string();
        return std::nullopt;
    }
    const std::filesystem::path normalized = normalizedExistingPath(path);
    for (size_t i = 0; i < documents_.size(); ++i) {
        if (documents_[i].path == normalized) {
            return i;
        }
    }
    if (!checkDocumentSafety(normalized, error)) {
        return std::nullopt;
    }
    Document document;
    document.path = normalized;
    if (!readExistingFile(normalized, document.content, error)) {
        return std::nullopt;
    }
    documents_.push_back(std::move(document));
    return documents_.size() - 1;
}

bool SudoersConfiguration::expandFile(const std::filesystem::path& path,
                                      std::vector<std::filesystem::path>& includeStack,
                                      size_t depth,
                                      std::string& error) {
    if (depth > options_.maximumIncludeDepth) {
        error = "Превышена максимальная глубина include sudoers";
        return false;
    }
    std::error_code existsError;
    if (!std::filesystem::exists(path, existsError)) {
        if (existsError) {
            error = "Не удалось проверить include sudoers: " + path.string();
            return false;
        }
        return true;
    }
    const auto index = loadDocument(path, error);
    return index.has_value() && expandDocument(*index, includeStack, depth, error);
}

bool SudoersConfiguration::expandDocument(size_t documentIndex,
                                          std::vector<std::filesystem::path>& includeStack,
                                          size_t depth,
                                          std::string& error) {
    const std::filesystem::path documentPath = documents_[documentIndex].path;
    const std::string documentContent = documents_[documentIndex].content;
    if (std::find(includeStack.begin(), includeStack.end(), documentPath) != includeStack.end()) {
        error = "Обнаружен цикл include sudoers: " + documentPath.string();
        return false;
    }
    includeStack.push_back(documentPath);

    const auto lines = physicalLines(documentContent);
    for (size_t i = 0; i < lines.size(); ++i) {
        const size_t firstLine = lines[i].first;
        std::string logical = lines[i].second;
        while (hasContinuation(logical) && i + 1 < lines.size()) {
            std::string trimmed = trimCopy(logical);
            trimmed.pop_back();
            logical = trimmed + " " + trimCopy(lines[++i].second);
        }

        std::string includePath;
        const IncludeKind kind = parseInclude(logical, includePath);
        if (kind == IncludeKind::None) {
            orderedLines_.push_back({documentIndex, firstLine, logical});
            continue;
        }

        if (includePath.find('%') != std::string::npos) {
            error = "Include sudoers с подстановками % пока не поддерживается: " + includePath;
            includeStack.pop_back();
            return false;
        }

        std::filesystem::path resolved(includePath);
        if (resolved.is_relative()) {
            resolved = documentPath.parent_path() / resolved;
        }
        if (kind == IncludeKind::File) {
            if (!expandFile(resolved, includeStack, depth + 1, error)) {
                includeStack.pop_back();
                return false;
            }
            continue;
        }

        includedDirectories_.push_back(normalizedExistingPath(resolved));
        std::error_code directoryError;
        if (!std::filesystem::exists(resolved, directoryError)) {
            if (directoryError) {
                error = "Не удалось проверить include-каталог: " + resolved.string();
                includeStack.pop_back();
                return false;
            }
            continue;
        }
        if (!std::filesystem::is_directory(resolved, directoryError) || directoryError) {
            error = "Include-путь не является каталогом: " + resolved.string();
            includeStack.pop_back();
            return false;
        }
        if (!checkDirectorySafety(resolved, error)) {
            includeStack.pop_back();
            return false;
        }

        std::vector<std::filesystem::path> entries;
        for (const auto& entry : std::filesystem::directory_iterator(resolved, directoryError)) {
            if (directoryError) {
                break;
            }
            const std::string name = entry.path().filename().string();
            if (!ignoredIncludedirName(name)) {
                entries.push_back(entry.path());
            }
        }
        if (directoryError) {
            error = "Не удалось прочитать include-каталог: " + resolved.string();
            includeStack.pop_back();
            return false;
        }
        std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return left.filename().string() < right.filename().string();
        });
        for (const auto& entry : entries) {
            if (!expandFile(entry, includeStack, depth + 1, error)) {
                includeStack.pop_back();
                return false;
            }
        }
    }

    includeStack.pop_back();
    return true;
}

SudoersValueObservation SudoersConfiguration::inspectGlobalDefault(const std::string& key) const {
    SudoersValueObservation result;
    for (const OrderedLine& line : orderedLines_) {
        std::string value;
        if (!parseGlobalDefaults(line.text, key, value)) {
            continue;
        }
        result.found = true;
        result.value = std::move(value);
        result.source = {documents_[line.documentIndex].path, line.firstLine};
    }
    return result;
}

bool SudoersConfiguration::isManagedDirectoryIncluded() const {
    const auto managedDirectory = normalizedExistingPath(options_.managedPath.parent_path());
    return std::find(includedDirectories_.begin(), includedDirectories_.end(), managedDirectory) !=
           includedDirectories_.end();
}

bool SudoersConfiguration::checkDocumentSafety(const std::filesystem::path& path,
                                               std::string& error) const {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        error = "Не удалось проверить sudoers-файл: " + path.string();
        return false;
    }
    if (!S_ISREG(info.st_mode)) {
        error = "Sudoers-источник не является обычным файлом: " + path.string();
        return false;
    }
    if (options_.enforceOwnership) {
        if (info.st_uid != 0) {
            error = "Sudoers-файл не принадлежит root: " + path.string();
            return false;
        }
        if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            error = "Sudoers-файл доступен на запись группе или остальным: " + path.string();
            return false;
        }
    }
    return true;
}

bool SudoersConfiguration::checkDirectorySafety(const std::filesystem::path& path,
                                                std::string& error) const {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        error = "Не удалось проверить include-каталог: " + path.string();
        return false;
    }
    if (!S_ISDIR(info.st_mode)) {
        error = "Include-путь не является обычным каталогом: " + path.string();
        return false;
    }
    if (options_.enforceOwnership) {
        if (info.st_uid != 0) {
            error = "Include-каталог sudoers не принадлежит root: " + path.string();
            return false;
        }
        if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            error = "Include-каталог sudoers доступен на запись группе или остальным: " +
                    path.string();
            return false;
        }
    }
    return true;
}

bool SudoersConfiguration::contentUnchanged(const Document& document, std::string& error) const {
    std::string current;
    if (!readExistingFile(document.path, current, error)) {
        return false;
    }
    if (current != document.content) {
        error = "Sudoers-файл изменился после чтения: " + document.path.string();
        return false;
    }
    return true;
}

bool SudoersConfiguration::writeDocument(const std::filesystem::path& path,
                                         const std::string& content,
                                         bool managedFile,
                                         std::string& error) const {
    AtomicWriteOptions options;
    options.rejectSymlink = true;
    if (managedFile) {
        options.createIfMissing = true;
        options.metadataPolicy = FileMetadataPolicy::EnforceProvided;
        options.fileMode = 0440;
        if (options_.enforceOwnership) {
            options.fileOwner = 0;
            options.fileGroup = 0;
        }
    }
    return AtomicFileWriter::write(path.string(), content, options, &error);
}

bool SudoersConfiguration::validate(std::string& error) const {
    if (options_.validatorPath.empty()) {
        return true;
    }
    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    const std::vector<std::string> arguments = {"-c", "-f", options_.mainPath.string()};
    const ProcessResult result = options_.verifyValidatorHash
        ? VerifiedProcessExecutor::execute(options_.validatorPath, arguments, processOptions)
        : ProcessExecutor::execute(options_.validatorPath, arguments, processOptions);
    if (result.success()) {
        return true;
    }
    error = !result.error.empty() ? result.error : trimCopy(result.standardError);
    if (error.empty()) {
        error = "visudo завершился с кодом " + std::to_string(result.exitCode);
    }
    return false;
}

bool SudoersConfiguration::restoreManagedFile(bool existed,
                                              const std::string& content,
                                              std::string& error) const {
    if (existed) {
        return writeDocument(options_.managedPath, content, true, error);
    }
    std::error_code removeError;
    std::filesystem::remove(options_.managedPath, removeError);
    if (removeError) {
        error = "Не удалось удалить неэффективный managed-файл: " + removeError.message();
        return false;
    }
    const std::filesystem::path directory = options_.managedPath.parent_path();
    const int directoryFd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY);
    if (directoryFd < 0) {
        error = "Не удалось открыть каталог managed-файла после отката";
        return false;
    }
    const bool synced = ::fsync(directoryFd) == 0;
    const bool closed = ::close(directoryFd) == 0;
    if (!synced || !closed) {
        error = "Не удалось синхронизировать каталог managed-файла после отката";
        return false;
    }
    return true;
}

SudoersOperationResult SudoersConfiguration::ensureManagedGlobalDefault(
    const std::string& key,
    const std::string& renderedLine,
    const std::string& expectedValue) {
    SudoersOperationResult result;
    std::string error;
    if (!validate(error)) {
        result.message = "Исходная конфигурация sudoers не прошла проверку: " + error;
        return result;
    }
    if (!isManagedDirectoryIncluded()) {
        result.message = "Каталог managed-файла не подключен через includedir: " +
                         options_.managedPath.parent_path().string();
        return result;
    }

    const SudoersValueObservation before = inspectGlobalDefault(key);
    if (before.found && before.value == expectedValue) {
        result.ok = true;
        result.message = "Эффективное значение уже соответствует эталону";
        result.diagnostics.push_back(before.source.path.string() + ":" +
                                     std::to_string(before.source.line));
        return result;
    }

    std::error_code existsError;
    const bool managedExisted = std::filesystem::exists(options_.managedPath, existsError);
    if (existsError) {
        result.message = "Не удалось проверить managed-файл: " + existsError.message();
        return result;
    }
    std::string originalContent;
    if (managedExisted && !readExistingFile(options_.managedPath, originalContent, error)) {
        result.message = error;
        return result;
    }

    std::vector<std::string> lines;
    for (const auto& [number, line] : physicalLines(originalContent)) {
        (void)number;
        if (!startsManagedDefault(line, key)) {
            lines.push_back(line);
        }
    }
    if (lines.empty()) {
        lines.push_back("# Managed by FIC. Manual changes may be overwritten.");
    }
    lines.push_back(renderedLine);

    std::string newContent;
    for (const std::string& line : lines) {
        newContent += line + "\n";
    }
    if (!writeDocument(options_.managedPath, newContent, true, error)) {
        result.message = "Не удалось записать managed sudoers-файл: " + error;
        return result;
    }

    result.changed = true;
    if (!validate(error)) {
        std::string restoreError;
        restoreManagedFile(managedExisted, originalContent, restoreError);
        result.message = "Измененная конфигурация sudoers не прошла проверку: " + error;
        if (!restoreError.empty()) {
            result.diagnostics.push_back("Ошибка отката: " + restoreError);
        }
        return result;
    }

    if (!load(error)) {
        std::string restoreError;
        restoreManagedFile(managedExisted, originalContent, restoreError);
        result.message = "Не удалось перечитать sudoers после изменения: " + error;
        return result;
    }
    const SudoersValueObservation after = inspectGlobalDefault(key);
    if (!after.found || after.value != expectedValue) {
        std::string restoreError;
        restoreManagedFile(managedExisted, originalContent, restoreError);
        result.message = "Managed-файл не определяет эффективное значение параметра " + key;
        if (after.found) {
            result.diagnostics.push_back("Перекрывающий источник: " + after.source.path.string() +
                                         ":" + std::to_string(after.source.line));
        }
        return result;
    }

    result.ok = true;
    result.message = "Эталон записан в " + options_.managedPath.string();
    result.diagnostics.push_back(after.source.path.string() + ":" +
                                 std::to_string(after.source.line));
    return result;
}

std::vector<std::string> SudoersConfiguration::authenticationViolations() const {
    std::vector<std::string> result;
    for (const Document& document : documents_) {
        const RewriteResult rewrite = rewriteAuthentication(document.path, document.content);
        result.insert(result.end(), rewrite.diagnostics.begin(), rewrite.diagnostics.end());
    }
    return result;
}

SudoersOperationResult SudoersConfiguration::enforceAuthentication() {
    SudoersOperationResult result;
    std::string error;
    if (!validate(error)) {
        result.message = "Исходная конфигурация sudoers не прошла проверку: " + error;
        return result;
    }

    bool anyChange = false;
    for (Document& document : documents_) {
        const RewriteResult rewrite = rewriteAuthentication(document.path, document.content);
        if (rewrite.changes == 0) {
            continue;
        }
        if (!contentUnchanged(document, error)) {
            result.message = error;
            result.changed = anyChange;
            return result;
        }
        const std::string original = document.content;
        if (!writeDocument(document.path, rewrite.content, false, error)) {
            result.message = "Не удалось обновить " + document.path.string() + ": " + error;
            result.changed = anyChange;
            return result;
        }
        if (!validate(error)) {
            std::string restoreError;
            writeDocument(document.path, original, false, restoreError);
            result.message = "Конфигурация не прошла visudo после изменения " +
                             document.path.string() + ": " + error;
            if (!restoreError.empty()) {
                result.diagnostics.push_back("Ошибка отката: " + restoreError);
            }
            result.changed = anyChange;
            return result;
        }
        document.content = rewrite.content;
        result.diagnostics.insert(result.diagnostics.end(),
                                  rewrite.diagnostics.begin(), rewrite.diagnostics.end());
        anyChange = true;
    }

    if (!load(error)) {
        result.message = "Не удалось перечитать sudoers после исправления: " + error;
        result.changed = anyChange;
        return result;
    }
    const auto remaining = authenticationViolations();
    if (!remaining.empty()) {
        result.message = "После исправления остались способы запуска без аутентификации";
        result.diagnostics.insert(result.diagnostics.end(), remaining.begin(), remaining.end());
        result.changed = anyChange;
        return result;
    }

    result.ok = true;
    result.changed = anyChange;
    result.message = anyChange
        ? "Все локальные правила sudoers требуют аутентификацию"
        : "Нарушения требования аутентификации не обнаружены";
    return result;
}
