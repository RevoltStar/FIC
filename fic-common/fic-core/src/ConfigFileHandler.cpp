#include <fic/core/ConfigFileHandler.h>

#include <utility>

ConfigFileHandler::ConfigFileHandler(const std::string& filepath,
                                     const std::string& delimiter,
                                     FileHandlerOptions options)
    : FileHandler(filepath, delimiter, std::move(options)) {
    //Загружаем файл в переменную (плохо - может возникнуть ошибка с правами когда не надо)
    //this->FileHandler::loadFile();
    //Создаем конфигурационный файл (плохо - создается много массивов одновременно)
    //this->ConfigFileHandler::loadConfig();
}

//Загружаем конфиг
bool ConfigFileHandler::loadConfig() {
    //Загружаем файл в переменную
    if(!this->FileHandler::loadFile()){
        return false;
    }
    //Очищаем массив
    config_.clear();
    //Обходим все оригинальные строки
    for (std::string& line : this->FileHandler::original_lines_) {

        // Удаляем пробельные символы с обеих сторон
        trim(line);

        const size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            //Игнорируем строки, начинающиеся на '#'
            continue;
        }

        // Пропускаем пустые строки
        if (line.empty()) {
            continue;
        }

        // Разделяем строку на параметр и значение
        const size_t delimiter_pos = line.find(this->delimiter_);
        if (delimiter_pos == std::string::npos) {
            //Строка не имеет вид параметр=значение
            //std::cerr << "Warning: Invalid line format: " << line << std::endl;
            continue;
        }

        std::string parameter = line.substr(0, delimiter_pos);
        std::string value = line.substr(delimiter_pos + 1);
        //std::cout << parameter + "   " + value << std::endl;
        // Удаляем пробельные символы из параметра и значения
        trim(parameter, true);
        trim(value);

        line = parameter + this->delimiter_ + value;
        if (!parameter.empty()) {
            //Проверяем, нет ли такого же ключа. Если есть -> комментируем
            if (config_.find(parameter) != config_.end()) {
                //Комментируем параметр
                line = '#' + line;
            }else{
                config_[parameter] = value;
            }
        }
    }
    return true;
}

//Получить параметр
std::string ConfigFileHandler::getValue(const std::string& parameter) const {
    const auto it = config_.find(parameter);
    return it != config_.end() ? it->second : "";
}

//Установить значение
bool ConfigFileHandler::setValue(const std::string& parameter, const std::string& value) {
    if (parameter.empty()) return false;
    config_[parameter] = value;

    // Ищем строку с параметром
    auto line_it = std::find_if(original_lines_.begin(), original_lines_.end(),
        [this, &parameter](const std::string& line) {
            size_t pos = line.find(this->delimiter_);
            if (pos == std::string::npos) return false;

            std::string param = line.substr(0, pos);
            this->trim(param);
            return param == parameter;
        });

    const std::string new_line = parameter + this->delimiter_ + value;

    if (line_it != original_lines_.end()) {
        *line_it = new_line;
    } else {
        original_lines_.push_back(new_line);
    }

    return true;
}

int ConfigFileHandler::parameterCount(){
    return this->config_.size();
}
/*
bool ConfigFileHandler::saveConfig() {
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
*/
//Параметр существует
bool ConfigFileHandler::isParameterExists(const std::string& parameter) const{
    const auto it = config_.find(parameter);
    return it != config_.end();
}

const std::unordered_map<std::string, std::string>& ConfigFileHandler::entries() const {
    return config_;
}
//Вывести конфигурационный файл
void ConfigFileHandler::printConfig() const {
    std::cout << "Configuration Parameters:" << "\n";
    for (const auto& pair : config_) {
        std::cout << "  '" << pair.first << "':'" << pair.second << "'\n";
    }
}
/*
//Закомментировать все параметры в файле
bool ConfigFileHandler::commentAllParameters() {
    for (auto& line : original_lines_) {
            if (line.empty() || line[0] == '#') continue;

            if (line.find(this->delimiter_) != std::string::npos) {
                line = "#" + line;
            }
        }
        return true;
    }
*/
