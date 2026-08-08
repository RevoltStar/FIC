#include "modules/oss/submodules/GrubConfiguration.h"

#include <fic/core/AtomicFileWriter.h>
#include <fic/core/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

#include <sys/stat.h>

namespace {

constexpr std::uintmax_t kMaximumGrubDefaultsSize = 1024U * 1024U;

struct ParsedTargetAssignment {
    bool target = false;
    bool valid = true;
    std::string value;
    std::string commentSuffix;
    std::string error;
};

std::string trimCopy(std::string value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char ch) {
            return std::isspace(ch) != 0;
        });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char ch) {
            return std::isspace(ch) != 0;
        }).base();
    return std::string(first, last);
}

bool validKey(const std::string& key) {
    if (key.empty() ||
        !(std::isalpha(static_cast<unsigned char>(key.front())) != 0 ||
          key.front() == '_')) {
        return false;
    }
    return std::all_of(
        key.begin() + 1, key.end(), [](unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '_';
        });
}

std::string withoutLineEnding(std::string line) {
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    return line;
}

std::vector<std::string> physicalLines(const std::string& content) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < content.size()) {
        const size_t newline = content.find('\n', start);
        if (newline == std::string::npos) {
            lines.push_back(content.substr(start));
            return lines;
        }
        lines.push_back(content.substr(start, newline - start + 1));
        start = newline + 1;
    }
    return lines;
}

bool parseLiteral(const std::string& input,
                  std::string& value,
                  std::string& commentSuffix,
                  std::string& error) {
    const std::string text = trimCopy(input);
    value.clear();
    commentSuffix.clear();
    if (text.empty()) {
        return true;
    }

    size_t index = 0;
    if (text.front() == '\'') {
        const size_t closing = text.find('\'', 1);
        if (closing == std::string::npos) {
            error = "незакрытая одинарная кавычка";
            return false;
        }
        value = text.substr(1, closing - 1);
        index = closing + 1;
    } else if (text.front() == '"') {
        bool closed = false;
        for (index = 1; index < text.size(); ++index) {
            const char ch = text[index];
            if (ch == '"') {
                ++index;
                closed = true;
                break;
            }
            if (ch == '$' || ch == '`') {
                error = "динамическое shell-выражение не поддерживается";
                return false;
            }
            if (ch == '\\') {
                if (index + 1 >= text.size()) {
                    error = "незавершённая escape-последовательность";
                    return false;
                }
                const char escaped = text[++index];
                if (escaped == '"' || escaped == '\\' ||
                    escaped == '$' || escaped == '`') {
                    value.push_back(escaped);
                } else {
                    value.push_back('\\');
                    value.push_back(escaped);
                }
                continue;
            }
            value.push_back(ch);
        }
        if (!closed) {
            error = "незакрытая двойная кавычка";
            return false;
        }
    } else {
        for (; index < text.size(); ++index) {
            const unsigned char ch = static_cast<unsigned char>(text[index]);
            if (std::isspace(ch) != 0) {
                break;
            }
            if (std::strchr("'\\\"$`;|&()<>*?[]{}!", ch) != nullptr) {
                error = "неподдерживаемый shell-метасимвол";
                return false;
            }
            value.push_back(static_cast<char>(ch));
        }
    }

    const std::string trailing = trimCopy(text.substr(index));
    if (!trailing.empty()) {
        if (trailing.front() != '#') {
            error = "после значения обнаружено неподдерживаемое shell-выражение";
            return false;
        }
        commentSuffix = " " + trailing;
    }
    return true;
}

ParsedTargetAssignment parseTargetAssignment(const std::string& physicalLine,
                                              const std::string& key) {
    ParsedTargetAssignment result;
    std::string line = trimCopy(withoutLineEnding(physicalLine));
    if (line.empty() || line.front() == '#') {
        return result;
    }
    if (line.compare(0, 6, "export") == 0 && line.size() > 6 &&
        std::isspace(static_cast<unsigned char>(line[6])) != 0) {
        line = trimCopy(line.substr(7));
    }
    const size_t equals = line.find('=');
    if (equals == std::string::npos ||
        trimCopy(line.substr(0, equals)) != key) {
        return result;
    }

    result.target = true;
    result.valid = parseLiteral(
        line.substr(equals + 1), result.value, result.commentSuffix,
        result.error);
    return result;
}

std::string quoteLiteral(const std::string& value) {
    std::string quoted = "\"";
    for (const char ch : value) {
        if (ch == '\\' || ch == '"' || ch == '$' || ch == '`') {
            quoted.push_back('\\');
        }
        quoted.push_back(ch);
    }
    quoted.push_back('"');
    return quoted;
}

bool readFile(const std::filesystem::path& path,
              std::string& content,
              std::string& error) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        error = "Не удалось открыть файл GRUB: " + path.string();
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        error = "Не удалось прочитать файл GRUB: " + path.string();
        return false;
    }
    content = buffer.str();
    return true;
}

std::string processFailure(const ProcessResult& result) {
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "команда пересборки GRUB превысила таймаут";
    }
    if (!result.standardError.empty()) {
        return trimCopy(result.standardError);
    }
    return "код возврата " + std::to_string(result.exitCode);
}

} // namespace

GrubConfiguration::GrubConfiguration(GrubConfigurationOptions options,
                                     GrubCommandRunner runner)
    : options_(std::move(options)),
      runner_(std::move(runner)) {
    if (!runner_) {
        runner_ = [](const std::string& executable,
                     const std::vector<std::string>& arguments,
                     const ProcessOptions& processOptions) {
            return VerifiedProcessExecutor::execute(
                executable, arguments, processOptions);
        };
    }
}

void GrubConfiguration::clear() {
    document_ = {};
    originalContent_.clear();
}

bool GrubConfiguration::checkFileSafety(std::string& error) const {
    struct stat status {};
    if (::lstat(options_.defaultsPath.c_str(), &status) != 0) {
        error = "Не удалось проверить GRUB-файл " +
            options_.defaultsPath.string() + ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(status.st_mode)) {
        error = "GRUB-конфигурация не должна быть symbolic link: " +
            options_.defaultsPath.string();
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        error = "GRUB-конфигурация не является обычным файлом: " +
            options_.defaultsPath.string();
        return false;
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        kMaximumGrubDefaultsSize) {
        error = "GRUB-конфигурация превышает допустимый размер";
        return false;
    }
    if (!options_.enforceOwnership) {
        return true;
    }
    if (status.st_uid != 0 || (status.st_mode & 0022) != 0) {
        error = "Небезопасные владелец или права GRUB-файла: " +
            options_.defaultsPath.string();
        return false;
    }

    std::filesystem::path current = options_.defaultsPath.parent_path();
    while (!current.empty()) {
        struct stat directoryStatus {};
        if (::lstat(current.c_str(), &directoryStatus) != 0 ||
            S_ISLNK(directoryStatus.st_mode) ||
            !S_ISDIR(directoryStatus.st_mode) ||
            directoryStatus.st_uid != 0 ||
            (directoryStatus.st_mode & 0022) != 0) {
            error = "GRUB-файл находится в небезопасном каталоге: " +
                current.string();
            return false;
        }
        if (current == current.root_path()) {
            break;
        }
        current = current.parent_path();
    }
    return true;
}

bool GrubConfiguration::readDocument(std::string& error) {
    if (!options_.defaultsPath.is_absolute() ||
        options_.defaultsPath != options_.defaultsPath.lexically_normal()) {
        error = "Путь GRUB-конфигурации должен быть абсолютным и нормализованным";
        return false;
    }
    if (!checkFileSafety(error)) {
        return false;
    }
    std::string content;
    if (!readFile(options_.defaultsPath, content, error)) {
        return false;
    }
    document_ = {options_.defaultsPath, std::move(content)};
    originalContent_ = document_.content;
    return true;
}

bool GrubConfiguration::load(std::string& error) {
    clear();
    if (!readDocument(error)) {
        clear();
        return false;
    }
    return true;
}

GrubValueObservation GrubConfiguration::inspect(const std::string& key) const {
    GrubValueObservation result;
    const std::string requested = trimCopy(key);
    if (!validKey(requested)) {
        result.valid = false;
        result.error = "Некорректное имя GRUB-параметра";
        return result;
    }

    size_t lineNumber = 0;
    for (const std::string& line : physicalLines(document_.content)) {
        ++lineNumber;
        const ParsedTargetAssignment parsed =
            parseTargetAssignment(line, requested);
        if (!parsed.target) {
            continue;
        }
        if (!parsed.valid) {
            result.valid = false;
            result.error = document_.path.string() + ":" +
                std::to_string(lineNumber) + ": " + parsed.error;
            return result;
        }
        if (result.found) {
            result.valid = false;
            result.error = document_.path.string() + ":" +
                std::to_string(lineNumber) +
                ": неоднозначное повторное определение " + requested;
            return result;
        }
        result.found = true;
        result.value = parsed.value;
        result.source = document_.path;
        result.line = lineNumber;
    }
    return result;
}

bool GrubConfiguration::snapshotUnchanged(std::string& error) const {
    GrubConfiguration current(options_, runner_);
    if (!current.load(error)) {
        return false;
    }
    if (document_.content != current.document_.content) {
        error = "Файл GRUB-конфигурации изменился во время проверки";
        return false;
    }
    return true;
}

bool GrubConfiguration::writeDocument(const std::string& content,
                                      std::string& error) const {
    AtomicWriteOptions options;
    options.createIfMissing = false;
    options.rejectSymlink = true;
    options.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    return AtomicFileWriter::write(
        options_.defaultsPath.string(), content, options, &error);
}

bool GrubConfiguration::restoreDocument(std::string& error) const {
    return writeDocument(originalContent_, error);
}

bool GrubConfiguration::verifyOriginalRestored(std::string& error) const {
    GrubConfiguration verification(options_, runner_);
    if (!verification.load(error)) {
        return false;
    }
    if (verification.document_.content != originalContent_) {
        error = "исходная GRUB-конфигурация не восстановлена";
        return false;
    }
    return true;
}

bool GrubConfiguration::rebuild(std::string& error) const {
    if (options_.rebuildExecutable.empty() ||
        !options_.rebuildExecutable.is_absolute()) {
        error = "Профиль платформы не задаёт команду пересборки GRUB";
        return false;
    }

    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    processOptions.timeout = std::chrono::seconds(60);
    const ProcessResult result = runner_(
        options_.rebuildExecutable.string(), options_.rebuildArguments,
        processOptions);
    if (!result.success()) {
        error = "Не удалось пересобрать конфигурацию GRUB: " +
            processFailure(result);
        return false;
    }
    error.clear();
    return true;
}

bool GrubConfiguration::rollbackAfterRebuildFailure(std::string& error) const {
    std::string rollbackError;
    if (!restoreDocument(rollbackError)) {
        error = "не удалось восстановить исходный defaults-файл: " +
            rollbackError;
        return false;
    }
    if (!verifyOriginalRestored(rollbackError)) {
        error = rollbackError;
        return false;
    }
    if (!rebuild(rollbackError)) {
        error = "исходный defaults-файл восстановлен, но не удалось "
            "восстановить сгенерированный grub.cfg: " + rollbackError;
        return false;
    }
    return true;
}

GrubOperationResult GrubConfiguration::ensureManagedValue(
    const std::string& key,
    const std::string& value) {
    GrubOperationResult result;
    const std::string requested = trimCopy(key);
    if (!validKey(requested)) {
        result.message = "Некорректное имя GRUB-параметра";
        return result;
    }
    if (value.find_first_of("\r\n") != std::string::npos ||
        value.find('\0') != std::string::npos) {
        result.message = "Значение GRUB-параметра содержит запрещённые символы";
        return result;
    }

    const GrubValueObservation before = inspect(requested);
    if (!before.valid) {
        result.message = before.error;
        return result;
    }
    if (before.found && before.value == value) {
        std::string rebuildError;
        if (!rebuild(rebuildError)) {
            result.message = rebuildError;
            return result;
        }
        result.ok = true;
        result.message =
            "Persistent-значение GRUB соответствует политике; grub.cfg пересобран";
        return result;
    }

    std::string desired;
    bool replaced = false;
    for (const std::string& line : physicalLines(document_.content)) {
        const ParsedTargetAssignment parsed =
            parseTargetAssignment(line, requested);
        if (!parsed.target) {
            desired += line;
            continue;
        }
        desired += requested + "=" + quoteLiteral(value) +
            parsed.commentSuffix;
        if (!line.empty() && line.back() == '\n') {
            desired.push_back('\n');
        }
        replaced = true;
    }
    if (!replaced) {
        desired = document_.content;
        if (!desired.empty() && desired.back() != '\n') {
            desired.push_back('\n');
        }
        desired += requested + "=" + quoteLiteral(value) + "\n";
    }

    std::string error;
    if (!snapshotUnchanged(error)) {
        result.message = error;
        return result;
    }
    if (!writeDocument(desired, error)) {
        result.message = "Не удалось записать GRUB-конфигурацию: " + error;
        return result;
    }

    GrubConfiguration verification(options_, runner_);
    if (!verification.load(error)) {
        std::string rollbackError;
        bool rolledBack = restoreDocument(rollbackError);
        if (rolledBack) {
            rolledBack = verifyOriginalRestored(rollbackError);
        }
        result.message = "Не удалось перечитать GRUB после записи: " + error;
        if (!rolledBack) {
            result.message += ". Ошибка отката: " + rollbackError;
        }
        return result;
    }
    const GrubValueObservation after = verification.inspect(requested);
    if (!after.valid || !after.found || after.value != value) {
        std::string rollbackError;
        bool rolledBack = restoreDocument(rollbackError);
        if (rolledBack) {
            rolledBack = verifyOriginalRestored(rollbackError);
        }
        result.message = after.valid
            ? "GRUB-параметр не стал итоговым значением после записи"
            : after.error;
        if (!rolledBack) {
            result.message += ". Ошибка отката: " + rollbackError;
        }
        return result;
    }

    if (!rebuild(error)) {
        std::string rollbackError;
        const bool rolledBack = rollbackAfterRebuildFailure(rollbackError);
        result.message = "Новая GRUB-конфигурация не активирована: " + error;
        if (!rolledBack) {
            result.message += ". Ошибка компенсирующего отката: " +
                rollbackError;
        }
        return result;
    }

    result.ok = true;
    result.changed = true;
    result.message = "Отклонение GRUB исправлено и grub.cfg пересобран";
    if (before.found) {
        result.diagnostics.push_back(
            "Предыдущее значение " + requested + " = " + before.value +
            " из " + before.source.string() + ":" +
            std::to_string(before.line));
    } else {
        result.diagnostics.push_back(
            "Параметр " + requested + " отсутствовал в GRUB-конфигурации");
    }
    return result;
}
