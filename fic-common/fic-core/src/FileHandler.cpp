#include <fic/core/FileHandler.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

bool writeAll(int fd, const char* data, size_t size) {
    while (size > 0) {
        ssize_t written = ::write(fd, data, size);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            errno = EIO;
            return false;
        }

        data += written;
        size -= static_cast<size_t>(written);
    }

    return true;
}

bool writeLine(int fd, const std::string& line) {
    return writeAll(fd, line.data(), line.size()) && writeAll(fd, "\n", 1);
}

bool closeFd(int& fd) {
    if (fd < 0) {
        return true;
    }

    while (::close(fd) < 0) {
        if (errno == EINTR) {
            continue;
        }
        fd = -1;
        return false;
    }

    fd = -1;
    return true;
}

void cleanupTempFile(int& fd, const std::filesystem::path& tempPath) {
    closeFd(fd);
    std::error_code error;
    std::filesystem::remove(tempPath, error);
}

std::string errnoMessage() {
    return std::strerror(errno);
}

} // namespace

FileHandler::FileHandler(const std::string& filepath, const std::string& delimiter){
    this->filepath_ = filepath;
    this->delimiter_ = delimiter;
}

bool FileHandler::loadConfig() {
    return false;
}

std::string FileHandler::collapseSpaces(const std::string &input){
    std::string result = "";
    bool inQuotes = false;
    bool spaceFound = false;

    for (char c : input) {
        if (c == '"') {
            inQuotes = !inQuotes;  // Переключаем состояние "внутри кавычек"
            result += c;
            spaceFound = false; // Сбрасываем флаг пробела после кавычки
        } else if (std::isspace(c, std::locale::classic())) {
            if (inQuotes) {
                // Внутри кавычек, сохраняем все пробелы
                result += c;
            } else {
                // Вне кавычек, преобразуем несколько пробелов в один
                if (!spaceFound) {
                    result += ' ';
                    spaceFound = true;
                }
            }
        } else {
            result += c;
            spaceFound = false; // Сброс флага пробела, если встречен не пробельный символ
        }
    }

    // Удаляем лишний пробел в начале строки, если он есть.
    if (!result.empty() && result[0] == ' ') {
        result.erase(0, 1);
    }

    return result;
}
/*
bool FileHandler::commentAllParameters() {
    // Базовая реализация
    return false;
}
*/
bool FileHandler::loadFile(){
    //std::cout << "Путь к файлу:" + filepath_ << std::endl;
    std::ifstream file(filepath_);
    if (!file.is_open()) {
        // Попытка создать файл, если он не существует
        std::ofstream createFile(filepath_);
        if (!createFile.is_open()) {
            std::cerr << "Error: Could not open or create file: " << filepath_ << std::endl;
            return false;
        }
        createFile.close();

        // Повторная попытка открыть файл для чтения
        file.open(filepath_);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file after creation: " << filepath_ << std::endl;
            return false;
        }
    }
    // Очищаем вектор перед загрузкой
    original_lines_.clear();
    //Строка в файле
    std::string line;
    while (std::getline(file, line)) {
        // Сохраняем исходную строку с комментариями
        original_lines_.push_back(line);
    }
    file.close();
    return true;
}

bool FileHandler::saveFile(){
    std::error_code error;
    const std::filesystem::path requestedPath(filepath_);
    const bool targetExists = std::filesystem::exists(requestedPath, error);
    if (error) {
        std::cerr << "Error: Could not check file existence: " << filepath_
                  << ": " << error.message() << std::endl;
        return false;
    }

    const std::filesystem::path targetPath = targetExists
        ? std::filesystem::canonical(requestedPath, error)
        : std::filesystem::absolute(requestedPath, error);

    if (error) {
        std::cerr << "Error: Could not resolve file path: " << filepath_
                  << ": " << error.message() << std::endl;
        return false;
    }

    const std::filesystem::path targetDir = targetPath.parent_path();
    if (targetDir.empty()) {
        std::cerr << "Error: Could not determine parent directory: " << filepath_ << std::endl;
        return false;
    }

    struct stat targetStat {};
    const bool hasTargetStat = ::stat(targetPath.c_str(), &targetStat) == 0;
    if (!hasTargetStat && errno != ENOENT) {
        std::cerr << "Error: Could not stat file: " << targetPath
                  << ": " << errnoMessage() << std::endl;
        return false;
    }

    std::string tempTemplate =
        (targetDir / ("." + targetPath.filename().string() + ".tmp.XXXXXX")).string();

    int tempFd = ::mkstemp(tempTemplate.data());
    if (tempFd < 0) {
        std::cerr << "Error: Could not create temporary file for: " << targetPath
                  << ": " << errnoMessage() << std::endl;
        return false;
    }

    const std::filesystem::path tempPath(tempTemplate);

    if (hasTargetStat) {
        if (::fchown(tempFd, targetStat.st_uid, targetStat.st_gid) < 0) {
            std::cerr << "Error: Could not set temporary file owner: " << tempPath
                      << ": " << errnoMessage() << std::endl;
            cleanupTempFile(tempFd, tempPath);
            return false;
        }

        if (::fchmod(tempFd, targetStat.st_mode & 07777) < 0) {
            std::cerr << "Error: Could not set temporary file mode: " << tempPath
                      << ": " << errnoMessage() << std::endl;
            cleanupTempFile(tempFd, tempPath);
            return false;
        }
    }

    for (const std::string& line : original_lines_) {
        if (!writeLine(tempFd, line)) {
            std::cerr << "Error: Could not write temporary file: " << tempPath
                      << ": " << errnoMessage() << std::endl;
            cleanupTempFile(tempFd, tempPath);
            return false;
        }
    }

    if (::fsync(tempFd) < 0) {
        std::cerr << "Error: Could not fsync temporary file: " << tempPath
                  << ": " << errnoMessage() << std::endl;
        cleanupTempFile(tempFd, tempPath);
        return false;
    }

    if (!closeFd(tempFd)) {
        std::cerr << "Error: Could not close temporary file: " << tempPath
                  << ": " << errnoMessage() << std::endl;
        cleanupTempFile(tempFd, tempPath);
        return false;
    }

    if (::rename(tempPath.c_str(), targetPath.c_str()) < 0) {
        std::cerr << "Error: Could not replace file: " << targetPath
                  << ": " << errnoMessage() << std::endl;
        cleanupTempFile(tempFd, tempPath);
        return false;
    }

    int dirFd = ::open(targetDir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dirFd < 0) {
        std::cerr << "Error: Could not open directory for fsync: " << targetDir
                  << ": " << errnoMessage() << std::endl;
        return false;
    }

    if (::fsync(dirFd) < 0) {
        std::cerr << "Error: Could not fsync directory: " << targetDir
                  << ": " << errnoMessage() << std::endl;
        closeFd(dirFd);
        return false;
    }

    if (!closeFd(dirFd)) {
        std::cerr << "Error: Could not close directory: " << targetDir
                  << ": " << errnoMessage() << std::endl;
        return false;
    }

    return true;
}

// Вспомогательная функция для удаления пробелов
void FileHandler::trim(std::string& str, bool needMid) const{
    str.erase(0, str.find_first_not_of(" \t\r\n"));
    str.erase(str.find_last_not_of(" \t\r\n") + 1);

    // Замена последовательностей пробельных символов в середине на один пробел
    if (needMid) {
            bool space = false;
            auto end = std::remove_if(str.begin(), str.end(), [&space](char c) {
                if (std::isspace(static_cast<unsigned char>(c))) {
                    if (space) {
                        // Удаляем, если уже был пробел
                        return true;
                    }
                    space = true;
                    // Заменяем на обычный пробел
                    c = ' ';
                    return false;
                } else {
                    space = false;
                    return false;
                }
            });
            str.erase(end, str.end());
        }
}

std::string FileHandler::getValue(const std::string& parameter) const {
    return "";
}


void FileHandler::printConfig() const {
    // Ничего не делаем
}
