#include <fic/core/fs/FileHandler.h>

#include <cerrno>
#include <utility>

#include <sys/stat.h>

FileHandler::FileHandler(const std::string& filepath,
                         const std::string& delimiter,
                         FileHandlerOptions options)
    : options_(std::move(options)) {
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
    struct stat linkInfo {};
    if (::lstat(filepath_.c_str(), &linkInfo) != 0) {
        if (errno != ENOENT) {
            std::cerr << "Error: Could not inspect file: " << filepath_ << std::endl;
            return false;
        }
        if (!options_.writeOptions.createIfMissing) {
            std::cerr << "Error: File does not exist: " << filepath_ << std::endl;
            return false;
        }
        std::string error;
        if (!AtomicFileWriter::write(filepath_, "", options_.writeOptions, &error)) {
            std::cerr << "Error: " << error << std::endl;
            return false;
        }
    } else if (options_.writeOptions.rejectSymlink && S_ISLNK(linkInfo.st_mode)) {
        std::cerr << "Error: Refusing to read symbolic link: " << filepath_ << std::endl;
        return false;
    }

    std::ifstream file(filepath_);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file: " << filepath_ << std::endl;
        return false;
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
    std::string content;
    for (const std::string& line : original_lines_) {
        content += line;
        content.push_back('\n');
    }

    std::string error;
    if (!AtomicFileWriter::write(filepath_, content, options_.writeOptions, &error)) {
        std::cerr << "Error: " << error << std::endl;
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
