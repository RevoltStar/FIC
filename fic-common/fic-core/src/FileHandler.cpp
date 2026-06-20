#include <fic/core/FileHandler.h>

FileHandler::FileHandler(const std::string& filepath, const std::string& delimeter){
    this->filepath_ = filepath;
    this->delimeter_ = delimeter;
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
    //Открываем файл (затирая содержимое)
    //std::cout << "Сохраняем файл" << std::endl;
    std::ofstream file(filepath_, std::ios::trunc | std::ios::out);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file for writing: " << filepath_ << std::endl;
        return false;
    }

    // Используем original_lines_, чтобы сохранить структуру файла, включая комментарии
    for (const std::string& line : original_lines_) {
         file << line << '\n';
    }

    file.close();
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

