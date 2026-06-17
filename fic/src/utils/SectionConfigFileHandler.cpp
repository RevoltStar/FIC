#include "utils/SectionConfigFileHandler.h"
#include <algorithm>
#include <iostream>

SectionConfigFileHandler::SectionConfigFileHandler(const std::string& filepath)
    : FileHandler(filepath, "=") {}

bool SectionConfigFileHandler::loadConfig() {
    if (!FileHandler::loadFile()) {
        return false;
    }

    rebuildSectionsFromOriginalLines();
    return true;
}

void SectionConfigFileHandler::rebuildSectionsFromOriginalLines() {
    sections_.clear();
    Section* currentSection = nullptr;

    for (size_t i = 0; i < original_lines_.size(); ++i) {
        std::string line = original_lines_[i];
        trim(line);

        // Проверка на заголовок секции
        if (!line.empty() && line[0] == '[' && line.back() == ']') {
            if (currentSection && i > 0) {
                currentSection->endLine = i - 1;
            }

            std::string sectionName = line.substr(1, line.size() - 2);
            trim(sectionName);

            sections_.push_back({sectionName, {}, i, i});
            currentSection = &sections_.back();
            continue;
        }

        if (!currentSection) {
            continue;
        }

        currentSection->endLine = i;

        // Пропуск пустых строк и комментариев
        if (isCommentOrEmpty(line)) {
            continue;
        }

        // Парсинг строки параметра, если мы внутри секции
        std::string parameter, value;
        if (parseParameterLine(line, parameter, value)) {
            currentSection->parameters.push_back({parameter, value, i});
        }
    }
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
    std::string value;
    if (!tryGetValue(section, parameter, value)) {
        return "";
    }

    return value;
}

bool SectionConfigFileHandler::tryGetValue(const std::string& section, const std::string& parameter, std::string& value) const {
    auto it = findSection(section);
    if (it == sections_.end()) {
        return false;
    }

    auto paramIt = findParameter(*it, parameter);
    if (paramIt == it->parameters.end()) {
        return false;
    }

    value = paramIt->value;
    return true;
}

bool SectionConfigFileHandler::setValue(const std::string& section, const std::string& parameter, const std::string& value) {
    if (section.empty() || parameter.empty()) {
        return false;
    }

    auto it = findSection(section);
    if (it == sections_.end()) {
        // Секция не существует, создаем новую
        if (!original_lines_.empty() && !original_lines_.back().empty()) {
            original_lines_.push_back("");
        }
        original_lines_.push_back("[" + section + "]");
        original_lines_.push_back(formatParameterLine(parameter, value));
        rebuildSectionsFromOriginalLines();
        return true;
    }

    auto paramIt = findParameter(*it, parameter);
    if (paramIt != it->parameters.end()) {
        original_lines_[paramIt->line] = formatParameterLine(parameter, value);
        rebuildSectionsFromOriginalLines();
        return true;
    }

    const size_t insertLine = findParameterInsertLine(*it);
    original_lines_.insert(original_lines_.begin() + insertLine, formatParameterLine(parameter, value));
    rebuildSectionsFromOriginalLines();
    return true;
}

std::vector<std::string> SectionConfigFileHandler::getParameters(const std::string& section) const {
    std::vector<std::string> parameters;
    auto it = findSection(section);
    if (it != sections_.end()) {
        for (const auto& param : it->parameters) {
            if (std::find(parameters.begin(), parameters.end(), param.name) == parameters.end()) {
                parameters.push_back(param.name);
            }
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
    return findParameter(*it, parameter) != it->parameters.end();
}

bool SectionConfigFileHandler::addSection(const std::string& section) {
    if (section.empty() || hasSection(section)) {
        return false;
    }

    if (!original_lines_.empty() && !original_lines_.back().empty()) {
        original_lines_.push_back("");
    }
    original_lines_.push_back("[" + section + "]");
    rebuildSectionsFromOriginalLines();
    return true;
}

bool SectionConfigFileHandler::removeSection(const std::string& section) {
    auto it = findSection(section);
    if (it == sections_.end()) {
        return false;
    }

    const size_t startLine = it->startLine;
    size_t endLine = it->endLine;
    if (endLine + 1 < original_lines_.size()) {
        std::string nextLine = original_lines_[endLine + 1];
        trim(nextLine);
        if (nextLine.empty()) {
            ++endLine;
        }
    }

    original_lines_.erase(original_lines_.begin() + startLine, original_lines_.begin() + endLine + 1);
    rebuildSectionsFromOriginalLines();
    return true;
}

bool SectionConfigFileHandler::removeParameter(const std::string& section, const std::string& parameter) {
    auto it = findSection(section);
    if (it == sections_.end()) {
        return false;
    }

    auto paramIt = findParameter(*it, parameter);
    if (paramIt == it->parameters.end()) {
        return false;
    }

    for (auto current = it->parameters.rbegin(); current != it->parameters.rend(); ++current) {
        if (current->name == parameter) {
            original_lines_.erase(original_lines_.begin() + current->line);
        }
    }
    rebuildSectionsFromOriginalLines();
    return true;
}

bool SectionConfigFileHandler::saveConfig() {
    return FileHandler::saveFile();
}

void SectionConfigFileHandler::printConfig() const {
    for (const auto& section : sections_) {
        std::cout << "[" << section.name << "]\n";
        for (const auto& param : section.parameters) {
            std::cout << param.name << " = " << param.value << "\n";
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

std::vector<SectionConfigFileHandler::Parameter>::iterator SectionConfigFileHandler::findParameter(
    Section& section,
    const std::string& parameter
) {
    for (auto it = section.parameters.end(); it != section.parameters.begin();) {
        --it;
        if (it->name == parameter) {
            return it;
        }
    }
    return section.parameters.end();
}

std::vector<SectionConfigFileHandler::Parameter>::const_iterator SectionConfigFileHandler::findParameter(
    const Section& section,
    const std::string& parameter
) const {
    for (auto it = section.parameters.end(); it != section.parameters.begin();) {
        --it;
        if (it->name == parameter) {
            return it;
        }
    }
    return section.parameters.end();
}

std::string SectionConfigFileHandler::formatParameterLine(
    const std::string& parameter,
    const std::string& value
) const {
    return parameter + " = " + value;
}

size_t SectionConfigFileHandler::findParameterInsertLine(const Section& section) const {
    size_t insertLine = section.startLine + 1;
    for (const auto& parameter : section.parameters) {
        insertLine = std::max(insertLine, parameter.line + 1);
    }
    return std::min(insertLine, original_lines_.size());
}

bool SectionConfigFileHandler::isCommentOrEmpty(const std::string& line) const {
    return line.empty() || line[0] == '#' || line[0] == ';';
}
