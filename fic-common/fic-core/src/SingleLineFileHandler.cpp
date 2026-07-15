#include <fic/core/SingleLineFileHandler.h>
#include <algorithm>
#include <utility>

SingleLineFileHandler::SingleLineFileHandler(const std::string& filepath,
                                             FileHandlerOptions options)
    : FileHandler(filepath, "", std::move(options)), data_line_index_(-1) {}

bool SingleLineFileHandler::loadConfig() {
    if (!loadFile()) {
        return false;
    }

    // Ищем первую непустую строку без комментариев
    for (size_t i = 0; i < original_lines_.size(); ++i) {
        std::string line = original_lines_[i];
        trim(line);

        // Пропускаем пустые строки и комментарии
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Нашли строку с данными
        current_line_ = line;
        data_line_index_ = static_cast<int>(i);
        return true;
    }

    // Если не нашли подходящую строку
    current_line_.clear();
    data_line_index_ = -1;
    return false;
}

std::string SingleLineFileHandler::getValue(const std::string& parameter) const {
    return current_line_;
}

bool SingleLineFileHandler::setValue(const std::string& parameter, const std::string& value) {
    if (data_line_index_ == -1) {
        // Если не было строки с данными, добавляем новую в конец
        original_lines_.push_back(value);
        data_line_index_ = static_cast<int>(original_lines_.size()) - 1;
    } else {

        //Если была строка, то удаляем ВСЁ лишнее и оставляем только "полезную строку"
        //Если нужно сохранить комментарии и прочее, то строку можно закомментировать
        original_lines_.clear();
        // Заменяем существующую строку
        original_lines_.push_back(value);
    }
    current_line_ = value;
    return true;
}

//Сохранить изменения
bool SingleLineFileHandler::saveConfig(){
    return FileHandler::saveFile();
}

void SingleLineFileHandler::printConfig() const {
    std::cout << "Current line: " << current_line_ << std::endl;
}
/*
bool SingleLineFileHandler::commentAllParameters() {
    return false;

    if (data_line_index_ == -1) {
        return false; // Нет строки для комментирования
    }

    std::string& line = original_lines_[data_line_index_];
    if (!line.empty() && line[0] != '#') {
        line = "# " + line;
        current_line_.clear();
        return true;
    }
    return false;
}
*/
