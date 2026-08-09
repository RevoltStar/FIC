#include "modules/sysctl/SysctlConfiguration.h"

#include <fic/core/AtomicFileWriter.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <system_error>

#include <fcntl.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr const char* managedHeader = "# Managed by FIC. Manual changes may be overwritten.";

std::string trimCopy(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char c) {
        return !std::isspace(c);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char c) {
        return !std::isspace(c);
    }).base(), value.end());
    return value;
}

bool hasConfSuffix(const std::string& name) {
    constexpr const char* suffix = ".conf";
    constexpr size_t suffixLength = 5;
    return name.size() > suffixLength &&
           name.compare(name.size() - suffixLength, suffixLength, suffix) == 0;
}

bool readFile(const std::filesystem::path& path,
              std::string& content,
              std::string& error) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        error = "Не удалось открыть sysctl-файл: " + path.string();
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        error = "Не удалось прочитать sysctl-файл: " + path.string();
        return false;
    }
    content = buffer.str();
    return true;
}

std::string normalizedKey(std::string key) {
    key = trimCopy(std::move(key));
    if (!key.empty() && key.front() == '-') {
        key.erase(key.begin());
        key = trimCopy(std::move(key));
    }
    constexpr const char* procPrefix = "/proc/sys/";
    if (key.compare(0, std::char_traits<char>::length(procPrefix), procPrefix) == 0) {
        key.erase(0, std::char_traits<char>::length(procPrefix));
    }
    std::replace(key.begin(), key.end(), '/', '.');
    while (!key.empty() && key.front() == '.') {
        key.erase(key.begin());
    }
    return key;
}

bool parseAssignmentLine(const std::string& physicalLine,
                         std::string& key,
                         std::string& value,
                         bool& ignored,
                         bool& exclusion,
                         bool& pattern) {
    std::string line = trimCopy(physicalLine);
    ignored = line.empty() || line.front() == '#' || line.front() == ';';
    exclusion = false;
    pattern = false;
    if (ignored) {
        return true;
    }
    const size_t equals = line.find('=');
    if (equals == std::string::npos) {
        if (line.front() != '-') {
            return false;
        }
        key = normalizedKey(line.substr(1));
        exclusion = true;
        pattern = key.find_first_of("*?[") != std::string::npos;
        return !key.empty();
    }
    key = normalizedKey(line.substr(0, equals));
    value = trimCopy(line.substr(equals + 1));
    pattern = key.find_first_of("*?[") != std::string::npos;
    return !key.empty();
}

std::vector<std::string> linesWithEndings(const std::string& content) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < content.size()) {
        const size_t newline = content.find('\n', start);
        if (newline == std::string::npos) {
            lines.push_back(content.substr(start));
            break;
        }
        lines.push_back(content.substr(start, newline - start + 1));
        start = newline + 1;
    }
    return lines;
}

std::string lineWithoutEnding(std::string line) {
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    return line;
}

struct ManagedAssignments {
    std::map<std::string, std::string> values;
};

bool inspectManagedAssignments(const std::vector<std::string>& lines,
                               ManagedAssignments& managed,
                               std::string& error) {
    for (const std::string& rawLine : lines) {
        const std::string line = lineWithoutEnding(rawLine);
        const std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed == managedHeader) {
            continue;
        }
        std::string key;
        std::string value;
        bool ignored = false;
        bool exclusion = false;
        bool pattern = false;
        if (!parseAssignmentLine(line, key, value, ignored, exclusion, pattern) || exclusion) {
            error = "Некорректная строка в managed sysctl-файле FIC";
            return false;
        }
        if (!ignored) {
            managed.values[key] = value;
        }
    }
    return true;
}

std::string renderManagedContent(const std::string& original,
                                 const std::map<std::string, std::string>& values) {
    (void)original;
    std::string base = managedHeader;
    base += '\n';
    for (const auto& [key, value] : values) {
        base += key + " = " + value + "\n";
    }
    return base;
}

bool removeAndSync(const std::filesystem::path& path, std::string& error) {
    if (::unlink(path.c_str()) < 0) {
        error = "Не удалось удалить созданный при откате файл " + path.string() +
                ": " + std::strerror(errno);
        return false;
    }
    const std::filesystem::path directory = path.parent_path();
    int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        error = "Не удалось открыть каталог при откате " + directory.string() +
                ": " + std::strerror(errno);
        return false;
    }
    const bool synced = ::fsync(fd) == 0;
    const int syncError = errno;
    const bool closed = ::close(fd) == 0;
    if (!synced || !closed) {
        error = "Не удалось синхронизировать каталог при откате " + directory.string() +
                ": " + std::strerror(synced ? errno : syncError);
        return false;
    }
    return true;
}

} // namespace

SysctlConfiguration::SysctlConfiguration(SysctlConfigurationOptions options)
    : options_(std::move(options)) {}

void SysctlConfiguration::clear() {
    documents_.clear();
    assignments_.clear();
    managedExisted_ = false;
    managedContent_.clear();
}

bool SysctlConfiguration::checkDirectorySafety(const std::filesystem::path& path,
                                                std::string& error) const {
    if (!options_.enforceOwnership) {
        return true;
    }
    struct stat status {};
    if (::stat(path.c_str(), &status) < 0) {
        error = "Не удалось проверить каталог sysctl " + path.string() +
                ": " + std::strerror(errno);
        return false;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != 0 || (status.st_mode & 0022) != 0) {
        error = "Небезопасные владелец или права каталога sysctl: " + path.string();
        return false;
    }
    return true;
}

bool SysctlConfiguration::checkFileSafety(const std::filesystem::path& path,
                                           bool allowDevNull,
                                           std::string& error) const {
    struct stat linkStatus {};
    if (::lstat(path.c_str(), &linkStatus) < 0) {
        error = "Не удалось проверить sysctl-файл " + path.string() +
                ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(linkStatus.st_mode)) {
        std::error_code canonicalError;
        const std::filesystem::path canonical = std::filesystem::canonical(path, canonicalError);
        if (allowDevNull && !canonicalError && canonical == "/dev/null") {
            return true;
        }
        error = "Sysctl-файл не должен быть symlink: " + path.string();
        return false;
    }
    std::error_code canonicalError;
    const std::filesystem::path canonical = std::filesystem::canonical(path, canonicalError);
    if (canonicalError) {
        error = "Не удалось разрешить путь sysctl-файла " + path.string() +
                ": " + canonicalError.message();
        return false;
    }
    if (allowDevNull && canonical == "/dev/null") {
        return true;
    }
    struct stat status {};
    if (::stat(canonical.c_str(), &status) < 0) {
        error = "Не удалось проверить sysctl-файл " + path.string() +
                ": " + std::strerror(errno);
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        error = "Sysctl-конфигурация не является обычным файлом: " + path.string();
        return false;
    }
    if (options_.enforceOwnership &&
        (status.st_uid != 0 || (status.st_mode & 0022) != 0)) {
        error = "Небезопасные владелец или права sysctl-файла: " + path.string();
        return false;
    }
    if (options_.enforceOwnership) {
        struct stat parentStatus {};
        const std::filesystem::path parent = canonical.parent_path();
        if (::stat(parent.c_str(), &parentStatus) < 0 || !S_ISDIR(parentStatus.st_mode) ||
            parentStatus.st_uid != 0 || (parentStatus.st_mode & 0022) != 0) {
            error = "Sysctl-файл находится в небезопасном каталоге: " + path.string();
            return false;
        }
    }
    return true;
}

bool SysctlConfiguration::addDocument(const std::filesystem::path& path,
                                      bool allowDevNullMask,
                                      std::string& error) {
    if (!checkFileSafety(path, allowDevNullMask, error)) {
        return false;
    }
    std::string content;
    if (!readFile(path, content, error)) {
        return false;
    }
    documents_.push_back({path, std::move(content), allowDevNullMask});
    return parseDocument(documents_.back(), error);
}

bool SysctlConfiguration::parseDocument(const Document& document, std::string& error) {
    std::istringstream stream(document.content);
    std::string line;
    size_t lineNumber = 1;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        std::string key;
        std::string value;
        bool ignored = false;
        bool exclusion = false;
        bool pattern = false;
        if (!parseAssignmentLine(line, key, value, ignored, exclusion, pattern)) {
            error = "Некорректная строка sysctl " + document.path.string() + ":" +
                    std::to_string(lineNumber);
            return false;
        }
        if (!ignored) {
            assignments_.push_back({std::move(key), std::move(value),
                                    {document.path, lineNumber}, pattern, exclusion});
        }
        ++lineNumber;
    }
    return true;
}

bool SysctlConfiguration::loadDirectoryDocuments(std::string& error) {
    std::set<std::string> selectedNames;
    std::set<std::filesystem::path> visitedDirectories;
    std::vector<std::pair<std::string, std::filesystem::path>> selected;

    for (const std::filesystem::path& directory : options_.directories) {
        std::error_code existsError;
        const bool exists = std::filesystem::exists(directory, existsError);
        if (existsError) {
            error = "Не удалось проверить каталог sysctl " + directory.string() +
                    ": " + existsError.message();
            return false;
        }
        if (!exists) {
            continue;
        }
        if (!checkDirectorySafety(directory, error)) {
            return false;
        }
        std::error_code canonicalError;
        const std::filesystem::path canonicalDirectory =
            std::filesystem::canonical(directory, canonicalError);
        if (canonicalError) {
            error = "Не удалось разрешить каталог sysctl " + directory.string() +
                    ": " + canonicalError.message();
            return false;
        }
        if (!visitedDirectories.insert(canonicalDirectory).second) {
            continue;
        }

        std::error_code iteratorError;
        std::filesystem::directory_iterator iterator(directory, iteratorError);
        if (iteratorError) {
            error = "Не удалось прочитать каталог sysctl " + directory.string() +
                    ": " + iteratorError.message();
            return false;
        }
        const std::filesystem::directory_iterator end;
        while (iterator != end) {
            const auto entry = *iterator;
            const std::string name = entry.path().filename().string();
            if (hasConfSuffix(name) && selectedNames.count(name) == 0) {
                selectedNames.insert(name);
                selected.emplace_back(name, entry.path());
            }
            iterator.increment(iteratorError);
            if (iteratorError) {
                error = "Не удалось полностью прочитать каталог sysctl " + directory.string() +
                        ": " + iteratorError.message();
                return false;
            }
        }
    }

    std::sort(selected.begin(), selected.end(), [](const auto& left, const auto& right) {
        return left.first < right.first;
    });
    for (const auto& [name, path] : selected) {
        (void)name;
        if (!addDocument(path, true, error)) {
            return false;
        }
    }
    return true;
}

bool SysctlConfiguration::loadProcpsMainDocument(std::string& error) {
    std::error_code existsError;
    const bool exists = std::filesystem::exists(options_.procpsMainPath, existsError);
    if (existsError) {
        error = "Не удалось проверить " + options_.procpsMainPath.string() +
                ": " + existsError.message();
        return false;
    }
    if (!exists) {
        return true;
    }
    if (!addDocument(options_.procpsMainPath, false, error)) {
        return false;
    }
    return true;
}

bool SysctlConfiguration::loadManagedDocument(std::string& error) {
    const std::filesystem::path& path = options_.platform.managedConfigPath;
    if (path.empty()) {
        error = "Не задан managed sysctl-файл FIC";
        return false;
    }
    std::error_code existsError;
    managedExisted_ = std::filesystem::exists(path, existsError);
    if (existsError) {
        error = "Не удалось проверить " + path.string() +
                ": " + existsError.message();
        return false;
    }
    if (!managedExisted_) {
        managedContent_.clear();
        return true;
    }
    if (!checkFileSafety(path, false, error)) {
        return false;
    }
    return readFile(path, managedContent_, error);
}

bool SysctlConfiguration::load(std::string& error) {
    clear();
    if (!loadDirectoryDocuments(error)) {
        clear();
        return false;
    }
    if (options_.platform.loader == fic::platform::SysctlLoaderKind::ProcpsSystem &&
        !loadProcpsMainDocument(error)) {
        clear();
        return false;
    }
    if (!loadManagedDocument(error)) {
        clear();
        return false;
    }
    return true;
}

SysctlValueObservation SysctlConfiguration::inspect(const std::string& key) const {
    SysctlValueObservation result;
    const std::string requested = normalizedKey(key);
    bool excludedFromGlobs = false;
    for (const Assignment& assignment : assignments_) {
        if (assignment.exclusion &&
            ((assignment.pattern && ::fnmatch(assignment.key.c_str(), requested.c_str(), 0) == 0) ||
             (!assignment.pattern && assignment.key == requested))) {
            excludedFromGlobs = true;
        }
        if (!assignment.exclusion && !assignment.pattern && assignment.key == requested) {
            excludedFromGlobs = true;
        }
    }
    for (const Assignment& assignment : assignments_) {
        if (assignment.exclusion) {
            continue;
        }
        const bool matchesExact = !assignment.pattern && assignment.key == requested;
        const bool matchesGlob = assignment.pattern && !excludedFromGlobs &&
            ::fnmatch(assignment.key.c_str(), requested.c_str(), 0) == 0;
        if (matchesExact || matchesGlob) {
            result.found = true;
            result.value = assignment.value;
            result.source = assignment.source;
        }
    }
    return result;
}

bool SysctlConfiguration::snapshotUnchanged(std::string& error) const {
    SysctlConfiguration current(options_);
    if (!current.load(error)) {
        return false;
    }
    if (managedExisted_ != current.managedExisted_ ||
        managedContent_ != current.managedContent_ ||
        documents_.size() != current.documents_.size()) {
        error = "Набор активных sysctl-файлов изменился во время проверки";
        return false;
    }
    for (size_t i = 0; i < documents_.size(); ++i) {
        if (documents_[i].path != current.documents_[i].path ||
            documents_[i].content != current.documents_[i].content) {
            error = "Sysctl-файл изменился во время проверки: " + documents_[i].path.string();
            return false;
        }
    }
    return true;
}

bool SysctlConfiguration::writeManaged(const std::string& content, std::string& error) const {
    const std::filesystem::path& path = options_.platform.managedConfigPath;
    if (!hasConfSuffix(path.filename().string())) {
        error = "Managed sysctl-файл FIC должен иметь расширение .conf: " + path.string();
        return false;
    }
    const std::filesystem::path parent = path.parent_path();
    if (!std::filesystem::exists(parent)) {
        std::error_code createError;
        std::filesystem::create_directories(parent, createError);
        if (createError) {
            error = "Не удалось создать каталог managed sysctl-файла " +
                    parent.string() + ": " + createError.message();
            return false;
        }
    }
    if (!checkDirectorySafety(parent, error)) {
        return false;
    }
    if (std::filesystem::exists(path)) {
        struct stat linkStatus {};
        if (::lstat(path.c_str(), &linkStatus) < 0) {
            error = "Не удалось проверить managed sysctl-файл " + path.string() +
                    ": " + std::strerror(errno);
            return false;
        }
        if (S_ISLNK(linkStatus.st_mode)) {
            error = "Managed sysctl-файл FIC не должен быть symlink: " + path.string();
            return false;
        }
    }
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.metadataPolicy = options_.enforceOwnership
        ? FileMetadataPolicy::EnforceProvided
        : FileMetadataPolicy::PreserveExisting;
    options.fileMode = 0644;
    if (options_.enforceOwnership) {
        options.fileOwner = 0;
        options.fileGroup = 0;
    }
    return AtomicFileWriter::write(path.string(), content, options, &error);
}

bool SysctlConfiguration::restoreManaged(std::string& error) const {
    if (managedExisted_) {
        return writeManaged(managedContent_, error);
    }
    return removeAndSync(options_.platform.managedConfigPath, error);
}

SysctlOperationResult SysctlConfiguration::ensureManagedValue(const std::string& key,
                                                              const std::string& value) {
    SysctlOperationResult result;
    const std::string requested = normalizedKey(key);
    if (requested.empty()) {
        result.message = "Пустое имя sysctl-параметра";
        return result;
    }

    ManagedAssignments managed;
    const std::vector<std::string> managedLines = linesWithEndings(managedContent_);
    std::string error;
    if (!inspectManagedAssignments(managedLines, managed, error)) {
        result.message = error;
        return result;
    }

    const SysctlValueObservation before = inspect(requested);
    if (before.found && before.value == value) {
        result.ok = true;
        result.message = "Отклонений не обнаружено";
        return result;
    }

    managed.values[requested] = value;
    const std::string desired = renderManagedContent(managedContent_, managed.values);
    if (desired == managedContent_) {
        const std::string actual = before.found ? before.value : "[NOT SET]";
        const std::string source = before.found
            ? before.source.path.string() + ":" + std::to_string(before.source.line)
            : "[NO SOURCE]";
        result.message = "Не удалось установить boot-effective значение " + requested +
                         ". Ожидается: " + value + ". Получено: " + actual +
                         ". Перекрывающий источник: " + source;
        return result;
    }
    if (!snapshotUnchanged(error)) {
        result.message = error;
        return result;
    }
    if (!writeManaged(desired, error)) {
        result.message = "Не удалось записать managed sysctl-файл FIC: " + error;
        return result;
    }

    SysctlConfiguration verification(options_);
    if (!verification.load(error)) {
        std::string rollbackError;
        const bool rolledBack = restoreManaged(rollbackError);
        result.message = "Не удалось перечитать sysctl после записи: " + error;
        if (!rolledBack) {
            result.message += ". Ошибка отката: " + rollbackError;
        }
        return result;
    }
    const SysctlValueObservation after = verification.inspect(requested);
    if (!after.found || after.value != value) {
        std::string rollbackError;
        const bool rolledBack = restoreManaged(rollbackError);
        const std::string actual = after.found ? after.value : "[NOT SET]";
        const std::string source = after.found
            ? after.source.path.string() + ":" + std::to_string(after.source.line)
            : "[NO SOURCE]";
        result.message = "Не удалось установить boot-effective значение " + requested +
                         ". Ожидается: " + value + ". Получено: " + actual +
                         ". Перекрывающий источник: " + source;
        if (!rolledBack) {
            result.message += ". Ошибка отката: " + rollbackError;
        }
        return result;
    }

    result.ok = true;
    result.changed = true;
    result.message = "Отклонение sysctl исправлено в managed sysctl-файле FIC";
    if (before.found) {
        result.diagnostics.push_back("Предыдущее эффективное значение " + requested +
                                     " = " + before.value + " из " +
                                     before.source.path.string() + ":" +
                                     std::to_string(before.source.line));
    } else {
        result.diagnostics.push_back("Параметр " + requested +
                                     " отсутствовал в активной конфигурации sysctl");
    }
    return result;
}
