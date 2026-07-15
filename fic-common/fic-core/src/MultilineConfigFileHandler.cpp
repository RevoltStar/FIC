#include <fic/core/MultilineConfigFileHandler.h>

#include <utility>
#include <algorithm>

MultilineConfigFileHandler::MultilineConfigFileHandler(const std::string& filepath,
                                                       const std::string& delimiter,
                                                       FileHandlerOptions options)
    : ConfigFileHandler(filepath, delimiter, std::move(options)) {}

bool MultilineConfigFileHandler::loadConfig() {
    if (!this->FileHandler::loadFile()) {
        return false;
    }

    config_.clear();
    std::string current_param;

    for (auto& line : original_lines_) {
        trim(line);

        // Пропускаем комментарии и пустые строки
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Проверяем, начинается ли строка с нового параметра
        const size_t delimiter_pos = line.find(delimiter_);
        if (delimiter_pos != std::string::npos) {
            // Это новый параметр
            current_param = line.substr(0, delimiter_pos);
            trim(current_param, true);

            if (!current_param.empty()) {
                std::string value = line.substr(delimiter_pos + 1);
                trim(value);

                // Проверяем дубликаты
                if (config_.find(current_param) != config_.end()) {
                    line = '#' + line; // Комментируем дубликат
                } else {
                    config_[current_param] = value;
                }
            }
        } else if (!current_param.empty()) {
            // Это продолжение предыдущего параметра
            if (!config_[current_param].empty()) {
                config_[current_param] += "\n" + line;
            } else {
                config_[current_param] = line;
            }
        }
    }

    return true;
}

std::vector<std::string> MultilineConfigFileHandler::getMultilineValue(const std::string& parameter) const {
    const auto it = config_.find(parameter);
    if (it == config_.end()) {
        return {};
    }

    std::vector<std::string> result;
    size_t start = 0;
    size_t end = it->second.find('\n');

    while (end != std::string::npos) {
        result.push_back(it->second.substr(start, end - start));
        start = end + 1;
        end = it->second.find('\n', start);
    }

    result.push_back(it->second.substr(start));
    return result;
}

bool MultilineConfigFileHandler::setMultilineValue(const std::string& parameter, const std::vector<std::string>& values) {
    if (parameter.empty() || values.empty()) {
        return false;
    }

    // Объединяем значения в одну строку с разделителями новой строки
    std::string combined_value;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) combined_value += "\n";
        combined_value += values[i];
    }

    config_[parameter] = combined_value;

    // Обновляем original_lines_
    // Сначала удаляем все существующие строки для этого параметра
    original_lines_.erase(
        std::remove_if(original_lines_.begin(), original_lines_.end(),
            [this, &parameter](const std::string& line) {
                size_t pos = line.find(this->delimiter_);
                if (pos == std::string::npos) return false;

                std::string param = line.substr(0, pos);
                trim(param);
                return param == parameter;
            }),
        original_lines_.end()
    );

    // Добавляем новые строки
    original_lines_.push_back(parameter + delimiter_ + values[0]);
    for (size_t i = 1; i < values.size(); ++i) {
        original_lines_.push_back(values[i]);
    }

    return true;
}

bool MultilineConfigFileHandler::isNewParameter(const std::string& line) const {
    if (line.empty() || line[0] == '#') {
        return false;
    }

    size_t delimiter_pos = line.find(delimiter_);
    if (delimiter_pos == std::string::npos) {
        return false;
    }

    std::string param = line.substr(0, delimiter_pos);
    trim(param);
    return !param.empty();
}
