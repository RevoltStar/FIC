#include "utils/SectionConfigFileHandler.h"
#include <algorithm>
#include <iostream>

SectionConfigFileHandler::SectionConfigFileHandler(const std::string& filepath)
    : FileHandler(filepath, "=") {}

bool SectionConfigFileHandler::loadConfig() {
    if (!FileHandler::loadFile()) {
        return false;
    }

    sections_.clear();
    Section* currentSection = nullptr;

    for (size_t i = 0; i < original_lines_.size(); ++i) {
        std::string line = original_lines_[i];
        trim(line);

        // Пропуск пустых строк и комментариев
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Проверка на заголовок секции
        if (line[0] == '[' && line.back() == ']') {
            std::string sectionName = line.substr(1, line.size() - 2);
            trim(sectionName);

            sections_.push_back({sectionName, {}, i, i});
            currentSection = &sections_.back();
            continue;
        }

        // Парсинг строки параметра, если мы внутри секции
        if (currentSection) {
            std::string parameter, value;
            if (parseParameterLine(line, parameter, value)) {
                currentSection->parameters[parameter] = value;
                currentSection->endLine = i;
            }
        }
    }

    return true;
}

bool SectionConfigFileHandler::parseParameterLine(const std::string& line, std::string& parameter, std::string& value) const {
    size_t delimiter_pos = line.find(delimeter_);
    if (delimiter_pos == std::string::npos) {
        return false;
    }

    parameter = line.substr(0, delimiter_pos);
    value = line.substr(delimiter_pos + 1);

    this->trim(parameter);
    this->trim(value);

    return !parameter.empty();
}

std::string SectionConfigFileHandler::getValue(const std::string& section, const std::string& parameter) const {
    auto it = findSection(section);
    if (it == sections_.end()) {
        return "";
    }

    auto paramIt = it->parameters.find(parameter);
    if (paramIt == it->parameters.end()) {
        return "";
    }

    return paramIt->second;
}

bool SectionConfigFileHandler::setValue(const std::string& section, const std::string& parameter, const std::string& value) {
    if (parameter.empty()) {
        return false;
    }

    auto it = findSection(section);
    if (it == sections_.end()) {
        // Секция не существует, создаем новую
        sections_.push_back({section, {}, 0, 0});
        it = sections_.end() - 1;
    }

    it->parameters[parameter] = value;
    updateOriginalLines();
    return true;
}

std::vector<std::string> SectionConfigFileHandler::getParameters(const std::string& section) const {
    std::vector<std::string> parameters;
    auto it = findSection(section);
    if (it != sections_.end()) {
        for (const auto& param : it->parameters) {
            parameters.push_back(param.first);
        }
    }
    return parameters;
}

std::vector<std::string> SectionConfigFileHandler::getSections() const {
    std::vector<std::string> sectionNames;
    for (const auto& section : sections_) {
        sectionNames.push_back(section.name);
    }
    return sectionNames;
}

bool SectionConfigFileHandler::hasSection(const std::string& section) const {
    return findSection(section) != sections_.end();
}

bool SectionConfigFileHandler::hasParameter(const std::string& section, const std::string& parameter) const {
    auto it = findSection(section);
    if (it == sections_.end()) {
        return false;
    }
    return it->parameters.find(parameter) != it->parameters.end();
}

bool SectionConfigFileHandler::addSection(const std::string& section) {
    if (hasSection(section)) {
        return false;
    }

    sections_.push_back({section, {}, 0, 0});
    updateOriginalLines();
    return true;
}

bool SectionConfigFileHandler::removeSection(const std::string& section) {
    auto it = findSection(section);
    if (it == sections_.end()) {
        return false;
    }

    sections_.erase(it);
    updateOriginalLines();
    return true;
}

bool SectionConfigFileHandler::removeParameter(const std::string& section, const std::string& parameter) {
    auto it = findSection(section);
    if (it == sections_.end()) {
        return false;
    }

    auto paramIt = it->parameters.find(parameter);
    if (paramIt == it->parameters.end()) {
        return false;
    }

    it->parameters.erase(paramIt);
    updateOriginalLines();
    return true;
}

bool SectionConfigFileHandler::saveConfig() {
    updateOriginalLines();
    return FileHandler::saveFile();
}

void SectionConfigFileHandler::printConfig() const {
    for (const auto& section : sections_) {
        std::cout << "[" << section.name << "]\n";
        for (const auto& param : section.parameters) {
            std::cout << param.first << " = " << param.second << "\n";
        }
        std::cout << "\n";
    }
}

bool SectionConfigFileHandler::setValue(const std::string& parameter, const std::string& value) {
    // Реализация по умолчанию - работа с первой секцией
    if (sections_.empty()) {
        return false;
    }
    return setValue(sections_[0].name, parameter, value);
}

std::string SectionConfigFileHandler::getValue(const std::string& parameter) const {
    // Реализация по умолчанию - работа с первой секцией
    if (sections_.empty()) {
        return "";
    }
    return getValue(sections_[0].name, parameter);
}

std::vector<SectionConfigFileHandler::Section>::iterator SectionConfigFileHandler::findSection(const std::string& section) {
    return std::find_if(sections_.begin(), sections_.end(),
        [&section](const Section& s) { return s.name == section; });
}

std::vector<SectionConfigFileHandler::Section>::const_iterator SectionConfigFileHandler::findSection(const std::string& section) const {
    return std::find_if(sections_.begin(), sections_.end(),
        [&section](const Section& s) { return s.name == section; });
}

void SectionConfigFileHandler::updateOriginalLines() {
    original_lines_.clear();

    for (const auto& section : sections_) {
        original_lines_.push_back("[" + section.name + "]");
        for (const auto& param : section.parameters) {
            original_lines_.push_back(param.first + " = " + param.second);
        }
        original_lines_.push_back("");  // Пустая строка между секциями
    }

    // Удаление пустых строк в конце
    while (!original_lines_.empty() && original_lines_.back().empty()) {
        original_lines_.pop_back();
    }
}
