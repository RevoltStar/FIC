#include "modules/oss/submodules/GrubConfiguration.h"

#include <fic/core/AtomicFileWriter.h>
#include <fic/core/VerifiedProcessExecutor.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <system_error>

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
            return VerifiedProcessExecutor::execute(executable, arguments, processOptions);
        };
    }
}

void GrubConfiguration::clear() {
    document_ = {};
    existed_ = false;
    originalContent_.clear();
}

bool GrubConfiguration::checkFileSafety(std::string& error) const {
    if (!options_.enforceOwnership) {
        return true;
    }
    std::error_code canonicalError;
    const std::filesystem::path canonical =
        std::filesystem::canonical(options_.defaultsPath, canonicalError);
    if (canonicalError) {
        error = "Не удалось разрешить путь GRUB-конфигурации " +
                options_.defaultsPath.string() + ": " + canonicalError.message();
        return false;
    }
    struct stat status {};
    if (::stat(canonical.c_str(), &status) < 0) {
        error = "Не удалось проверить GRUB-файл " + canonical.string() +
                ": " + std::strerror(errno);
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        error = "GRUB-конфигурация не является обычным файлом: " + canonical.string();
        return false;
    }
    if (status.st_uid != 0 || (status.st_mode & 0022) != 0) {
        error = "Небезопасные владелец или права GRUB-файла: " + canonical.string();
        return false;
    }
    struct stat parentStatus {};
    const std::filesystem::path parent = canonical.parent_path();
    if (::stat(parent.c_str(), &parentStatus) < 0 || !S_ISDIR(parentStatus.st_mode) ||
        parentStatus.st_uid != 0 || (parentStatus.st_mode & 0022) != 0) {
        error = "GRUB-файл находится в небезопасном каталоге: " + canonical.string();
        return false;
    }
    return true;
}

bool GrubConfiguration::readDocument(std::string& error) {
    std::error_code existsError;
    existed_ = std::filesystem::exists(options_.defaultsPath, existsError);
    if (existsError) {
        error = "Не удалось проверить " + options_.defaultsPath.string() +
                ": " + existsError.message();
        return false;
    }
    if (!existed_) {
        document_ = {};
        originalContent_.clear();
        return true;
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
    if (requested.empty()) {
        return result;
    }

    std::istringstream stream(document_.content);
    std::string line;
    size_t lineNumber = 1;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed.front() == '#') {
            ++lineNumber;
            continue;
        }
        const size_t equals = trimmed.find('=');
        if (equals == std::string::npos) {
            ++lineNumber;
            continue;
        }
        const std::string name = trimCopy(trimmed.substr(0, equals));
        if (name == requested) {
            result.found = true;
            result.value = trimCopy(trimmed.substr(equals + 1));
            result.source = document_.path;
            result.line = lineNumber;
            return result;
        }
        ++lineNumber;
    }
    return result;
}

bool GrubConfiguration::snapshotUnchanged(std::string& error) const {
    GrubConfiguration current(options_, runner_);
    if (!current.load(error)) {
        return false;
    }
    if (existed_ != current.existed_ ||
        document_.content != current.document_.content) {
        error = "Файл GRUB-конфигурации изменился во время проверки";
        return false;
    }
    return true;
}

bool GrubConfiguration::writeDocument(const std::string& content,
                                      std::string& error) const {
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
    return AtomicFileWriter::write(options_.defaultsPath.string(), content,
                                   options, &error);
}

bool GrubConfiguration::restoreDocument(std::string& error) const {
    if (existed_) {
        return writeDocument(originalContent_, error);
    }
    if (::unlink(options_.defaultsPath.c_str()) < 0) {
        error = "Не удалось удалить созданный при откате файл " +
                options_.defaultsPath.string() + ": " + std::strerror(errno);
        return false;
    }
    const std::filesystem::path directory = options_.defaultsPath.parent_path();
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
        error = "Не удалось синхронизировать каталог при откате " +
                directory.string() + ": " +
                std::strerror(synced ? errno : syncError);
        return false;
    }
    return true;
}

bool GrubConfiguration::rebuild(std::string& error) const {
    if (options_.rebuildCandidates.empty()) {
        error = "Профиль платформы не задаёт команду пересборки GRUB";
        return false;
    }

    ProcessOptions processOptions;
    processOptions.clearEnvironment = true;
    processOptions.timeout = std::chrono::seconds(60);

    std::string lastFailure;
    for (const std::filesystem::path& candidate : options_.rebuildCandidates) {
        const ProcessResult result = runner_(
            candidate.string(), {}, processOptions);
        if (result.success()) {
            error.clear();
            return true;
        }
        lastFailure = processFailure(result);
    }

    error = "Не удалось пересобрать конфигурацию GRUB: " + lastFailure;
    return false;
}

GrubOperationResult GrubConfiguration::ensureManagedValue(
    const std::string& key,
    const std::string& value) {
    GrubOperationResult result;
    const std::string requested = trimCopy(key);
    if (requested.empty()) {
        result.message = "Пустое имя GRUB-параметра";
        return result;
    }

    const GrubValueObservation before = inspect(requested);
    if (before.found && before.value == value) {
        result.ok = true;
        result.message = "Отклонений не обнаружено";
        return result;
    }

    std::string desired = document_.content;
    if (before.found) {
        // Replace the existing assignment in place, preserving line endings.
        std::istringstream stream(document_.content);
        std::ostringstream output;
        std::string line;
        bool replaced = false;
        while (std::getline(stream, line)) {
            const bool hasMore = !stream.eof();
            std::string physical = line;
            if (!physical.empty() && physical.back() == '\r') {
                physical.pop_back();
            }
            const std::string trimmed = trimCopy(physical);
            bool match = false;
            if (!trimmed.empty() && trimmed.front() != '#') {
                const size_t equals = trimmed.find('=');
                if (equals != std::string::npos &&
                    trimCopy(trimmed.substr(0, equals)) == requested) {
                    match = true;
                }
            }
            if (match && !replaced) {
                output << requested << "=" << value;
                replaced = true;
            } else {
                output << line;
            }
            if (hasMore) {
                output << '\n';
            }
        }
        if (!replaced) {
            result.message = "Не удалось заменить GRUB-параметр " + requested;
            return result;
        }
        desired = output.str();
    } else {
        // Append a new assignment at the end of the file.
        if (!desired.empty() && desired.back() != '\n') {
            desired += '\n';
        }
        desired += requested + "=" + value + "\n";
    }

    if (desired == document_.content) {
        result.ok = true;
        result.message = "Отклонений не обнаружено";
        return result;
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
        const bool rolledBack = restoreDocument(rollbackError);
        result.message = "Не удалось перечитать GRUB после записи: " + error;
        if (!rolledBack) {
            result.message += ". Ошибка отката: " + rollbackError;
        }
        return result;
    }
    const GrubValueObservation after = verification.inspect(requested);
    if (!after.found || after.value != value) {
        std::string rollbackError;
        const bool rolledBack = restoreDocument(rollbackError);
        result.message = "GRUB-параметр " + requested +
                         " не стал итоговым значением после записи";
        if (!rolledBack) {
            result.message += ". Ошибка отката: " + rollbackError;
        }
        return result;
    }

    if (!rebuild(error)) {
        std::string rollbackError;
        const bool rolledBack = restoreDocument(rollbackError);
        result.message = "Persistent-конфигурация GRUB записана, но пересборка "
                         "не завершена: " + error;
        if (!rolledBack) {
            result.message += ". Ошибка отката: " + rollbackError;
        }
        return result;
    }

    result.ok = true;
    result.changed = true;
    result.message = "Отклонение GRUB исправлено и конфигурация пересобрана";
    if (before.found) {
        result.diagnostics.push_back("Предыдущее значение " + requested +
                                     " = " + before.value + " из " +
                                     before.source.string() + ":" +
                                     std::to_string(before.line));
    } else {
        result.diagnostics.push_back("Параметр " + requested +
                                     " отсутствовал в GRUB-конфигурации");
    }
    return result;
}