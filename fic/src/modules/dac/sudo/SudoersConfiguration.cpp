#include "SudoersAuthenticationGrammar.h"
#include "SudoersAuthenticationWrapper.h"
#include "modules/dac/sudo/SudoersConfiguration.h"
#include "modules/dac/sudo/SudoersDisabledWrapper.h"
#include "modules/dac/sudo/SudoersIncludeDirective.h"
#include "modules/dac/sudo/SudoersLogicalEntries.h"
#include "modules/dac/sudo/SudoersScopedDefaults.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/process/ProcessExecutor.h>
#include <fic/core/process/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <fstream>
#include <map>
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

// NOTE: include directive lexing lives in the dedicated
// SudoersIncludeDirective component: '#' is both the comment introducer and
// part of the '#include'/'#includedir' directives, so an include argument
// cannot be obtained by stripping an inline comment from the raw line.

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

std::filesystem::path normalizedExistingPath(const std::filesystem::path& path) {
    std::error_code error;
    const auto result = std::filesystem::canonical(path, error);
    return error ? std::filesystem::absolute(path).lexically_normal() : result;
}

} // namespace

std::mutex& SudoersConfiguration::mutationMutex() {
    static std::mutex mutex;
    return mutex;
}

SudoersConfiguration::SudoersConfiguration(SudoersConfigurationOptions options)
    : options_(std::move(options)) {
}

void SudoersConfiguration::clear() {
    documents_.clear();
    orderedLines_.clear();
    includedDirectories_.clear();
    includedDirectoryTopology_.clear();
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

// THE single "@includedir membership" implementation, shared by load() and by
// verifyIncludedDirectoryTopologyUnchanged(). Existence, directory safety, the
// eligibility filter and the lexical order are decided here ONCE, so the parser
// and the security-sensitive topology verifier can never disagree about what
// "@includedir" means.
bool SudoersConfiguration::enumerateIncludedirMembers(
    const std::filesystem::path& directory,
    std::vector<std::filesystem::path>& entries,
    bool& exists,
    std::string& error) const {
    entries.clear();
    exists = false;
    std::error_code directoryError;
    if (!std::filesystem::exists(directory, directoryError)) {
        if (directoryError) {
            error = "Не удалось проверить include-каталог: " + directory.string();
            return false;
        }
        // Parser semantics: a missing @includedir is skipped, not an error.
        return true;
    }
    if (!std::filesystem::is_directory(directory, directoryError) ||
        directoryError) {
        error = "Include-путь не является каталогом: " + directory.string();
        return false;
    }
    // Same contract as load(): a symlinked or otherwise unsafe directory is
    // refused, never silently traversed.
    if (!checkDirectorySafety(directory, error)) {
        return false;
    }
    exists = true;
    for (const auto& entry :
         std::filesystem::directory_iterator(directory, directoryError)) {
        if (directoryError) {
            break;
        }
        const std::string name = entry.path().filename().string();
        if (!ignoredIncludedirName(name)) {
            entries.push_back(entry.path());
        }
    }
    if (directoryError) {
        error = "Не удалось прочитать include-каталог: " + directory.string();
        return false;
    }
    // The SAME order sudoers itself would apply, so membership identity keeps
    // the parser meaning.
    std::sort(entries.begin(), entries.end(),
              [](const auto& left, const auto& right) {
                  return left.filename().string() < right.filename().string();
              });
    return true;
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

    // THE shared physical -> logical assembly. The snapshot-bound semantic
    // proof in ScopedDefaultsTransaction uses the very same assembler, so the
    // include graph and the security proof cannot disagree about how a
    // continuation is read.
    const std::vector<fic::sudoers::SudoLogicalEntry> entries =
        fic::sudoers::assembleSudoLogicalEntries(
            fic::sudoers::splitPhysicalLines(documentContent));
    for (const fic::sudoers::SudoLogicalEntry& entry : entries) {
        // Physical coordinates stay 1-based here, so existing diagnostics do not
        // shift by one.
        const size_t firstLine = entry.firstPhysicalLine + 1;
        const size_t consumed = entry.lineCount;
        std::string logical = entry.text;

        // The include directive is recognized BEFORE any comment handling:
        // '#' is the comment introducer but also part of the legacy
        // '#include'/'#includedir' directives.
        const fic::sudoers::IncludeDirective directive =
            fic::sudoers::parseIncludeDirective(logical);
        if (directive.kind == fic::sudoers::IncludeKind::None) {
            orderedLines_.push_back({documentIndex, firstLine, consumed, logical});
            continue;
        }
        if (directive.kind == fic::sudoers::IncludeKind::Unsupported) {
            // An include FIC does not model safely must never be silently
            // ignored: it would silently shrink the active include graph and
            // hide the Defaults that sudo actually applies.
            error = "Include sudoers не поддерживается: " + directive.error +
                    " (" + documentPath.string() + ":" + std::to_string(firstLine) + ")";
            includeStack.pop_back();
            return false;
        }

        const std::string& includePath = directive.path;
        if (includePath.find('%') != std::string::npos) {
            error = "Include sudoers с подстановками % пока не поддерживается: " + includePath;
            includeStack.pop_back();
            return false;
        }

        std::filesystem::path resolved(includePath);
        if (resolved.is_relative()) {
            resolved = documentPath.parent_path() / resolved;
        }
        if (directive.kind == fic::sudoers::IncludeKind::File) {
            if (!expandFile(resolved, includeStack, depth + 1, error)) {
                includeStack.pop_back();
                return false;
            }
            continue;
        }

        includedDirectories_.push_back(normalizedExistingPath(resolved));
        // Record the membership that produced THIS graph, so a later
        // security-sensitive decision can be invalidated if the directory
        // changes underneath it.
        std::vector<std::filesystem::path> entries;
        IncludedDirectoryTopology topology;
        topology.canonicalPath = normalizedExistingPath(resolved);
        std::error_code directoryError;
        if (!enumerateIncludedirMembers(resolved, entries, topology.existed,
                                        error)) {
            includeStack.pop_back();
            return false;
        }
        if (!topology.existed) {
            includedDirectoryTopology_.push_back(std::move(topology));
            continue;
        }
        for (const auto& entry : entries) {
            topology.eligibleMembers.push_back(entry.filename().string());
        }
        includedDirectoryTopology_.push_back(std::move(topology));
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

bool SudoersConfiguration::verifyIncludedDirectoryTopologyUnchanged(
    std::string& error) const {
    // Re-enumerate with the SAME implementation the parser used. Every failure
    // mode (not a directory, symlink where forbidden, permission, I/O error)
    // fails closed here instead of being silently read as "empty".
    for (const IncludedDirectoryTopology& expected : includedDirectoryTopology_) {
        std::vector<std::filesystem::path> entries;
        bool exists = false;
        if (!enumerateIncludedirMembers(expected.canonicalPath, entries, exists,
                                        error)) {
            error = "не удалось перепроверить состав include-каталога " +
                    expected.canonicalPath.string() + ": " + error;
            return false;
        }
        if (exists != expected.existed) {
            error = expected.existed
                        ? "include-каталог исчез после загрузки sudoers: "
                        : "include-каталог появился после загрузки sudoers: ";
            error += expected.canonicalPath.string();
            return false;
        }
        std::vector<std::string> members;
        members.reserve(entries.size());
        for (const std::filesystem::path& entry : entries) {
            members.push_back(entry.filename().string());
        }
        if (members == expected.eligibleMembers) {
            continue;
        }
        // A single changed name invalidates the proof. Whether it was added,
        // removed or renamed does not matter: the effective graph FIC planned
        // and proved against is no longer the graph on disk.
        error = "состав include-каталога изменился после загрузки sudoers (" +
                expected.canonicalPath.string() + "): было [";
        for (const std::string& name : expected.eligibleMembers) {
            error += name + " ";
        }
        error += "], стало [";
        for (const std::string& name : members) {
            error += name + " ";
        }
        error += "]";
        return false;
    }
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

SudoersValueObservation SudoersConfiguration::inspectManagedGlobalDefault(
    const std::string& key) const {
    SudoersValueObservation result;
    const auto managedDocument = std::find_if(
        documents_.begin(), documents_.end(),
        [this](const Document& document) {
            return document.path == options_.managedPath;
        });
    if (managedDocument == documents_.end()) {
        return result;
    }
    const size_t documentIndex =
        static_cast<size_t>(managedDocument - documents_.begin());
    for (const OrderedLine& line : orderedLines_) {
        if (line.documentIndex != documentIndex) {
            continue;
        }
        std::string value;
        if (!parseGlobalDefaults(line.text, key, value)) {
            continue;
        }
        result.found = true;
        result.value = std::move(value);
        result.source = {managedDocument->path, line.firstLine};
    }
    return result;
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

bool SudoersConfiguration::validate(std::string& error) const {
    if (options_.verifyProviderUnchanged && !options_.verifyProviderUnchanged(error)) return false;
    if (options_.validatorPath.empty()) {
        if (options_.requireValidator) {
            error = "Authoritative native sudoers validator is unavailable";
            return false;
        }
        return true;
    }
    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    const std::vector<std::string> arguments = {"-c", "-f", options_.mainPath.string()};
    const ProcessResult result = options_.verifyValidatorHash
        ? VerifiedProcessExecutor::execute(options_.validatorPath, arguments, processOptions)
        : ProcessExecutor::execute(options_.validatorPath, arguments, processOptions);
    if (result.success()) {
        return !options_.verifyProviderUnchanged || options_.verifyProviderUnchanged(error);
    }
    error = !result.error.empty() ? result.error : trimCopy(result.standardError);
    if (error.empty()) {
        error = "visudo завершился с кодом " + std::to_string(result.exitCode);
    }
    return false;
}

std::vector<std::string> SudoersConfiguration::authenticationViolations() const {
    std::vector<std::string> result;
    for (const auto& document : documents_) {
        const auto lines = fic::sudoers::splitPhysicalLines(document.content);
        std::vector<fic::sudoers::AuthenticationWrapper> frames;
        std::string error;
        if (!fic::sudoers::parseAuthenticationWrappers(lines, frames, error)) {
            result.push_back(document.path.string() + ": " + error); continue;
        }
        for (const auto& entry : fic::sudoers::assembleSudoLogicalEntries(lines, true)) {
            if (std::any_of(frames.begin(), frames.end(), [&](const auto& frame) {
                return entry.firstPhysicalLine >= frame.first && entry.firstPhysicalLine <= frame.last;
            })) continue;
            fic::sudoers::AuthenticationRule rule;
            if (!fic::sudoers::parseAuthenticationRule(entry, rule, error) || !rule.edits.empty())
                result.push_back(document.path.string() + ":" + std::to_string(entry.firstPhysicalLine + 1) +
                                 (error.empty() ? "" : ": " + error));
        }
    }
    return result;
}

std::vector<std::string> SudoersConfiguration::scopedDefaultsViolations() const {
    std::vector<std::string> result;
    for (const OrderedLine& line : orderedLines_) {
        const std::string scope = fic::sudoers::scopedDefaultsScope(line.text);
        if (scope.empty()) {
            continue;
        }
        result.push_back(fic::sudoers::scopedDefaultsLocation(
            {documents_[line.documentIndex].path, line.firstLine, line.lineCount,
             scope}));
    }
    return result;
}


std::vector<SudoersConfiguration::GraphDocument>
SudoersConfiguration::graphDocuments() const {
    std::vector<GraphDocument> documents;
    documents.reserve(documents_.size());
    for (const Document& document : documents_) {
        documents.push_back({document.path, document.content});
    }
    return documents;
}

std::vector<SudoersConfiguration::GraphEntry>
SudoersConfiguration::graphEntries() const {
    std::vector<GraphEntry> entries;
    entries.reserve(orderedLines_.size());
    for (const OrderedLine& line : orderedLines_) {
        entries.push_back({line.documentIndex, line.firstLine, line.lineCount,
                            line.text});
    }
    return entries;
}
