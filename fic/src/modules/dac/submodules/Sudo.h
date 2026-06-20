#ifndef SUDOEDIT_H
#define SUDOEDIT_H
#include "utils/ConfigFileHandler.h"
#include "modules/dac/DAC.h"
#include <iostream>
#include <string>
#include <fstream>
#include <regex>
#include <nlohmann/json.hpp>

/*/home/MFC.LOCAL/poroshinmi/sudoers-test.txt*/

// ============================================================================
// ПАРАМЕТРЫ SUDOERS
// ============================================================================

class SudoersParam {
public:
    SudoersParam(std::string sectionName, size_t lineNumber)
        : sectionName_(std::move(sectionName)), lineNumber_(lineNumber) {}
    virtual ~SudoersParam() = default;

    virtual std::string getParamString() const = 0;
    virtual std::string getType() const { return sectionName_; }
    size_t getLineNumber() const { return lineNumber_; }

    //Пытаемся сравнить два параметра
    virtual bool equals(const SudoersParam& other) const = 0;
protected:
    std::string sectionName_;
    size_t lineNumber_;

};

// ----------------------------------------------------------------------------
// @includedir / #includedir
// ----------------------------------------------------------------------------
class IncludeDirSudoersParam : public SudoersParam {
public:
    std::string getParamString() const override {
        return sectionName_ + " " + folder;
    }

    bool equals(const SudoersParam& other) const override {
        const auto* rhs = dynamic_cast<const IncludeDirSudoersParam*>(&other);
        return rhs != nullptr && this->getParamString() == rhs->getParamString();
    }

    IncludeDirSudoersParam(std::string sectionName, std::string folder, size_t lineNumber)
        : SudoersParam(std::move(sectionName), lineNumber), folder(std::move(folder)) {}

    const std::string& getFolder() const { return folder; }

private:
    std::string folder;
};

// ----------------------------------------------------------------------------
// Defaults без "=" (env_reset, insults, ...)
// ----------------------------------------------------------------------------
class SingleDefaultsSudoersParam : public SudoersParam {
public:
    std::string getParamString() const override {
        std::string result = sectionName_;
        if (!group.empty()) {
            result += ":" + group;
        }
        if (!scope.empty()) {
            result += scope;
        }
        result += " " + key;
        return result;
    }

    bool equals(const SudoersParam& other) const override {
        const auto* rhs = dynamic_cast<const SingleDefaultsSudoersParam*>(&other);
        return rhs != nullptr && this->getParamString() == rhs->getParamString();
    }

    SingleDefaultsSudoersParam(std::string sectionName, std::string group,
                               std::string scope, std::string key, size_t lineNumber)
        : SudoersParam(std::move(sectionName), lineNumber),
          group(std::move(group)), scope(std::move(scope)), key(std::move(key)) {}

    const std::string& getKey() const { return key; }
    const std::string& getGroup() const { return group; }
    const std::string& getScope() const { return scope; }

private:
    std::string group;   // :groupname
    std::string scope;   // @host, !user, %group
    std::string key;
};

// ----------------------------------------------------------------------------
// Defaults с "=" (secure_path="/usr/bin", timestamp_timeout=5, ...)
// ----------------------------------------------------------------------------
class KeyValueDefaultsSudoersParam : public SudoersParam {
public:
    std::string getParamString() const override {
        std::string result = sectionName_;
        if (!group.empty()) {
            result += ":" + group;
        }
        if (!scope.empty()) {
            result += scope;
        }
        result += " " + key + operator_ + value;
        return result;
    }

    bool equals(const SudoersParam& other) const override {
        const auto* rhs = dynamic_cast<const KeyValueDefaultsSudoersParam*>(&other);
        return rhs != nullptr && this->getParamString() == rhs->getParamString();
    }

    KeyValueDefaultsSudoersParam(std::string sectionName, std::string group,
                                 std::string scope, std::string key,
                                 std::string op, std::string value, size_t lineNumber)
        : SudoersParam(std::move(sectionName), lineNumber),
          group(std::move(group)), scope(std::move(scope)),
          key(std::move(key)), operator_(std::move(op)), value(std::move(value)) {}

    const std::string& getKey() const { return key; }
    const std::string& getValue() const { return value; }
    const std::string& getGroup() const { return group; }
    const std::string& getScope() const { return scope; }
    const std::string& getOperator() const { return operator_; }

private:
    std::string group;
    std::string scope;
    std::string key;
    std::string operator_;  // =, +=, -=
    std::string value;
};

// ----------------------------------------------------------------------------
// Defaults со списком значений (env_keep += "FOO", "BAR")
// ----------------------------------------------------------------------------
class ListDefaultsSudoersParam : public SudoersParam {
public:
    std::string getParamString() const override {
        std::string result = sectionName_;
        if (!group.empty()) {
            result += ":" + group;
        }
        if (!scope.empty()) {
            result += scope;
        }
        result += " " + key + operator_;
        for (size_t i = 0; i < values.size(); ++i) {
            if (i > 0) result += ", ";
            result += values[i];
        }
        return result;
    }

    bool equals(const SudoersParam& other) const override {
        const auto* rhs = dynamic_cast<const ListDefaultsSudoersParam*>(&other);
        return rhs != nullptr && this->getParamString() == rhs->getParamString();
    }

    ListDefaultsSudoersParam(std::string sectionName, std::string group,
                             std::string scope, std::string key,
                             std::string op, std::vector<std::string> vals,
                             size_t lineNumber)
        : SudoersParam(std::move(sectionName), lineNumber),
          group(std::move(group)), scope(std::move(scope)),
          key(std::move(key)), operator_(std::move(op)), values(std::move(vals)) {}

    const std::string& getKey() const { return key; }
    const std::vector<std::string>& getValues() const { return values; }
    const std::string& getGroup() const { return group; }
    const std::string& getScope() const { return scope; }
    const std::string& getOperator() const { return operator_; }

    // Проверка наличия значения в списке
    bool hasValue(const std::string& val) const {
        return std::find(values.begin(), values.end(), val) != values.end();
    }

private:
    std::string group;
    std::string scope;
    std::string key;
    std::string operator_;  // +=, -=
    std::vector<std::string> values;
};

// ----------------------------------------------------------------------------
// Алиасы (User_Alias, Host_Alias, Runas_Alias, Cmnd_Alias)
// ----------------------------------------------------------------------------
class AliasSudoersParam : public SudoersParam {
public:
    std::string getParamString() const override {
        return sectionName_ + " " + aliasName + " = " +
               join(aliasValues, ", ");
    }

    bool equals(const SudoersParam& other) const override {
        const auto* rhs = dynamic_cast<const AliasSudoersParam*>(&other);
        return rhs != nullptr && this->getParamString() == rhs->getParamString();
    }

    AliasSudoersParam(std::string sectionName, std::string aliasName,
                      std::vector<std::string> aliasValues, size_t lineNumber)
        : SudoersParam(std::move(sectionName), lineNumber),
          aliasName(std::move(aliasName)), aliasValues(std::move(aliasValues)) {}

    const std::string& getAliasName() const { return aliasName; }
    const std::vector<std::string>& getAliasValues() const { return aliasValues; }

    bool hasValue(const std::string& val) const {
        return std::find(aliasValues.begin(), aliasValues.end(), val) != aliasValues.end();
    }

private:
    std::string aliasName;
    std::vector<std::string> aliasValues;

    static std::string join(const std::vector<std::string>& arr, const std::string& delim) {
        std::string result;
        for (size_t i = 0; i < arr.size(); ++i) {
            if (i > 0) result += delim;
            result += arr[i];
        }
        return result;
    }
};

// ----------------------------------------------------------------------------
// Теги команд (NOPASSWD, NOEXEC, SETENV, PASSWD, EXEC, NOSETENV)
// ----------------------------------------------------------------------------
struct CommandTag {
    enum Type { NONE, NOPASSWD, NOEXEC, SETENV, PASSWD, EXEC, NOSETENV };
    Type type = NONE;
    std::string custom;  // для CUSTOM tags

    static Type fromString(const std::string& s) {
        if (s == "NOPASSWD") return NOPASSWD;
        if (s == "NOEXEC") return NOEXEC;
        if (s == "SETENV") return SETENV;
        if (s == "PASSWD") return PASSWD;
        if (s == "EXEC") return EXEC;
        if (s == "NOSETENV") return NOSETENV;
        return NONE;
    }

    std::string toString() const {
        switch (type) {
            case NOPASSWD: return "NOPASSWD";
            case NOEXEC: return "NOEXEC";
            case SETENV: return "SETENV";
            case PASSWD: return "PASSWD";
            case EXEC: return "EXEC";
            case NOSETENV: return "NOSETENV";
            default: return custom;
        }
    }
};

// ----------------------------------------------------------------------------
// ОТДЕЛЬНОЕ ПРАВИЛО ПРИВИЛЕГИИ (развёрнутое)
// Один пользователь + одна команда = один объект
// ----------------------------------------------------------------------------
class PrivilegeSudoersParam : public SudoersParam {
public:
    std::string getParamString() const override {
        std::string result = user + " " + host + " = ";

        if (!runasUsers.empty() || !runasGroups.empty()) {
            result += "(";
            if (!runasUsers.empty()) {
                result += runasUsers;
                if (!runasGroups.empty()) {
                    result += " : " + runasGroups;
                }
            } else if (!runasGroups.empty()) {
                result += ":" + runasGroups;
            }
            result += ") ";
        }

        // Добавляем теги
        for (const auto& tag : tags) {
            result += tag.toString() + ": ";
        }

        result += command;
        if (negated) {
            result = "!" + result;
        }

        return result;
    }

    bool equals(const SudoersParam& other) const override {
        const auto* rhs = dynamic_cast<const PrivilegeSudoersParam*>(&other);
        return rhs != nullptr && this->getParamString() == rhs->getParamString();
    }

    PrivilegeSudoersParam(std::string user, std::string host,
                         std::string runasUsers, std::string runasGroups,
                         std::string command, std::vector<CommandTag> tags,
                         bool negated, size_t lineNumber)
        : SudoersParam("Privilege", lineNumber),
          user(std::move(user)), host(std::move(host)),
          runasUsers(std::move(runasUsers)), runasGroups(std::move(runasGroups)),
          command(std::move(command)), tags(std::move(tags)), negated(negated) {}

    // Геттеры для валидации
    const std::string& getUser() const { return user; }
    const std::string& getHost() const { return host; }
    const std::string& getRunasUsers() const { return runasUsers; }
    const std::string& getRunasGroups() const { return runasGroups; }
    const std::string& getCommand() const { return command; }
    const std::vector<CommandTag>& getTags() const { return tags; }
    bool isNegated() const { return negated; }

    // Проверка тега
    bool hasTag(CommandTag::Type tagType) const {
        for (const auto& tag : tags) {
            if (tag.type == tagType) return true;
        }
        return false;
    }

    // Проверка NOPASSWD
    bool isNoPasswd() const { return hasTag(CommandTag::NOPASSWD); }

private:
    std::string user;           // Один пользователь/группа/алиас
    std::string host;           // Один хост
    std::string runasUsers;     // Runas users (может быть списком)
    std::string runasGroups;    // Runas groups (может быть списком)
    std::string command;        // Одна команда
    std::vector<CommandTag> tags;
    bool negated = false;
};

// ============================================================================
// ОСНОВНОЙ КЛАСС ПАРСЕРА
// ============================================================================

class SudoersConfigFileHandler : public FileHandler {
public:
    SudoersConfigFileHandler(const std::string& filePath = "/etc/sudoers")
        : FileHandler(filePath) {}

    bool setValue(const std::string& parameter, const std::string& value) override {
        return false;
    }

    bool setValue(const SudoersParam& parameter, const std::string& value) {
        if (const auto* expected = dynamic_cast<const KeyValueDefaultsSudoersParam*>(&parameter)) {
            for (size_t i = config_.size(); i > 0; --i) {
                auto* current = dynamic_cast<KeyValueDefaultsSudoersParam*>(config_[i - 1].get());
                if (current != nullptr && isSameDefaultsParameter(*current, *expected)) {
                    const size_t lineNumber = current->getLineNumber();
                    if (lineNumber == 0 || lineNumber > original_lines_.size()) {
                        return false;
                    }

                    original_lines_[lineNumber - 1] = buildDefaultsLine(*expected, value);
                    config_[i - 1] = std::make_unique<KeyValueDefaultsSudoersParam>(
                        expected->getType(),
                        expected->getGroup(),
                        expected->getScope(),
                        expected->getKey(),
                        expected->getOperator(),
                        value,
                        lineNumber);
                    return true;
                }
            }

            original_lines_.push_back(buildDefaultsLine(*expected, value));
            config_.push_back(std::make_unique<KeyValueDefaultsSudoersParam>(
                expected->getType(),
                expected->getGroup(),
                expected->getScope(),
                expected->getKey(),
                expected->getOperator(),
                value,
                original_lines_.size()));
            return true;
        }

        if (const auto* expected = dynamic_cast<const SingleDefaultsSudoersParam*>(&parameter)) {
            if (value == "ENABLE") {
                for (size_t i = config_.size(); i > 0; --i) {
                    auto* current = dynamic_cast<SingleDefaultsSudoersParam*>(config_[i - 1].get());
                    if (current != nullptr && isSameDefaultsParameter(*current, *expected)) {
                        return true;
                    }
                }

                original_lines_.push_back(buildDefaultsLine(*expected));
                config_.push_back(std::make_unique<SingleDefaultsSudoersParam>(
                    expected->getType(),
                    expected->getGroup(),
                    expected->getScope(),
                    expected->getKey(),
                    original_lines_.size()));
                return true;
            }

            if (value == "DISABLE") {
                std::vector<size_t> lineNumbersToErase;

                for (size_t i = config_.size(); i > 0; --i) {
                    auto* current = dynamic_cast<SingleDefaultsSudoersParam*>(config_[i - 1].get());
                    if (current != nullptr && isSameDefaultsParameter(*current, *expected)) {
                        const size_t lineNumber = current->getLineNumber();
                        if (lineNumber > 0 && lineNumber <= original_lines_.size()) {
                            lineNumbersToErase.push_back(lineNumber - 1);
                        }
                        config_.erase(config_.begin() + (i - 1));
                    }
                }

                for (size_t lineIndex : lineNumbersToErase) {
                    original_lines_.erase(original_lines_.begin() + lineIndex);
                }

                return true;
            }
        }

        return false;
    }

    std::string getValue(const SudoersParam& parameter) const {
        if (const auto* expected = dynamic_cast<const KeyValueDefaultsSudoersParam*>(&parameter)) {
            for (size_t i = this->config_.size(); i > 0; --i) {
                auto* current = dynamic_cast<const KeyValueDefaultsSudoersParam*>(this->config_[i - 1].get());
                if (current != nullptr && isSameDefaultsParameter(*current, *expected)) {
                    return current->getValue();
                }
            }
            return "";
        }

        if (const auto* expected = dynamic_cast<const SingleDefaultsSudoersParam*>(&parameter)) {
            for (size_t i = this->config_.size(); i > 0; --i) {
                auto* current = dynamic_cast<const SingleDefaultsSudoersParam*>(this->config_[i - 1].get());
                if (current != nullptr && isSameDefaultsParameter(*current, *expected)) {
                    return "ENABLE";
                }
            }
            return "DISABLE";
        }

        return "";
    }

    // ------------------------------------------------------------------------
    // ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
    // ------------------------------------------------------------------------

    static std::string trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\n\r");
        return str.substr(start, end - start + 1);
    }

    static bool isComment(const std::string& line) {
        std::string trimmed = trim(line);
        return trimmed.empty() || trimmed[0] == '#';
    }

    // Удалить комментарий в конце строки (с учётом кавычек)
    static std::string removeCommentEnd(const std::string& input) {
        bool in_single = false;
        bool in_double = false;
        bool escaped = false;

        for (size_t i = 0; i < input.size(); ++i) {
            char c = input[i];

            if (escaped) {
                escaped = false;
                continue;
            }

            if (c == '\\') {
                escaped = true;
                continue;
            }

            if (c == '"' && !in_single) {
                in_double = !in_double;
                continue;
            }

            if (c == '\'' && !in_double) {
                in_single = !in_single;
                continue;
            }

            if (c == '#' && !in_single && !in_double) {
                return input.substr(0, i);
            }
        }
        return input;
    }

    // Разделить строку по разделителю (с учётом кавычек)
    static std::vector<std::string> split(const std::string& str, char delimiter = ',') {
        std::vector<std::string> result;
        std::string token;
        bool in_single = false;
        bool in_double = false;
        bool escaped = false;

        for (char c : str) {
            if (escaped) {
                token += c;
                escaped = false;
                continue;
            }

            if (c == '\\') {
                token += c;
                escaped = true;
                continue;
            }

            if (c == '"' && !in_single) {
                in_double = !in_double;
                token += c;
                continue;
            }

            if (c == '\'' && !in_double) {
                in_single = !in_single;
                token += c;
                continue;
            }

            if (c == delimiter && !in_single && !in_double) {
                std::string trimmed = trim(token);
                if (!trimmed.empty()) {
                    result.push_back(trimmed);
                }
                token.clear();
            } else {
                token += c;
            }
        }

        std::string trimmed = trim(token);
        if (!trimmed.empty()) {
            result.push_back(trimmed);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // ОБРАБОТКА МНОГОСТРОЧНЫХ ПРАВИЛ
    // ------------------------------------------------------------------------

    void handleLineContinuation() {
        std::string accumulatedLine;
        bool inMultiLine = false;
        std::vector<std::string> processedLines;

        for (size_t i = 0; i < original_lines_.size(); ++i) {
            std::string line = original_lines_[i];
            std::string trimmedLine = trim(line);

            // Пропускаем полные комментарии (но не inline)
            if (trimmedLine.empty() || (trimmedLine[0] == '#' && !inMultiLine)) {
                if (inMultiLine) {
                    std::cerr << "Warning: Comment inside multi-line rule at line "
                              << (i + 1) << std::endl;
                }
                processedLines.push_back(line);
                continue;
            }

            // Удаляем inline-комментарии
            trimmedLine = trim(removeCommentEnd(line));

            if (!trimmedLine.empty() && trimmedLine.back() == '\\') {
                // Продолжение на следующей строке
                trimmedLine.pop_back();
                trimmedLine = trim(trimmedLine);
                if (!accumulatedLine.empty()) {
                    accumulatedLine += " ";
                }
                accumulatedLine += trimmedLine;
                inMultiLine = true;
            } else if (inMultiLine) {
                // Конец многострочной записи
                if (!accumulatedLine.empty()) {
                    accumulatedLine += " ";
                }
                accumulatedLine += trimmedLine;
                processedLines.push_back(accumulatedLine);
                accumulatedLine.clear();
                inMultiLine = false;
            } else {
                // Обычная строка
                processedLines.push_back(trimmedLine);
            }
        }

        // Обработка случая, когда файл заканчивается многострочной записью
        if (inMultiLine && !accumulatedLine.empty()) {
            processedLines.push_back(accumulatedLine);
        }

        original_lines_ = processedLines;
    }

    // ------------------------------------------------------------------------
    // ПАРСИНГ СТРОКИ DEFAULTS
    // ------------------------------------------------------------------------

    void parseDefaultsLine(const std::string& line, size_t lineNumber) {
        std::string rest = line.substr(8); // "Defaults".length() = 8
        rest = trim(rest);

        // Проверяем наличие группы (Defaults:group)
        std::string group;
        if (!rest.empty() && rest[0] == ':') {
            size_t spacePos = rest.find(' ');
            if (spacePos == std::string::npos) {
                std::cerr << "Error: Syntax error in Defaults at line "
                          << lineNumber << ": " << line << std::endl;
                return;
            }
            group = rest.substr(1, spacePos - 1);
            rest = trim(rest.substr(spacePos + 1));
        }

        // Проверяем наличие скоупа (@host, !user, %group)
        std::string scope;
        if (!rest.empty() && (rest[0] == '@' || rest[0] == '!' || rest[0] == '%')) {
            size_t spacePos = rest.find(' ');
            if (spacePos != std::string::npos) {
                scope = rest.substr(0, spacePos);
                rest = trim(rest.substr(spacePos + 1));
            } else {
                scope = rest;
                rest = "";
            }
        }

        if (rest.empty()) {
            std::cerr << "Error: Empty Defaults at line " << lineNumber << std::endl;
            return;
        }

        // ИСПРАВЛЕНИЕ: Сначала разделяем по запятым (с учётом кавычек)
        std::vector<std::string> params = splitDefaultsParams(rest);

        // Каждый параметр обрабатываем отдельно
        for (const auto& param : params) {
            parseSingleDefaultParam(param, group, scope, lineNumber);
        }
    }

    // ------------------------------------------------------------------------
    // РАЗДЕЛЕНИЕ СПИСКА ПАРАМЕТРОВ DEFAULTS (с учётом кавычек)
    // ------------------------------------------------------------------------

    std::vector<std::string> splitDefaultsParams(const std::string& str) {
        std::vector<std::string> result;
        std::string token;
        bool in_single = false;
        bool in_double = false;
        bool escaped = false;

        for (char c : str) {
            if (escaped) {
                token += c;
                escaped = false;
                continue;
            }

            if (c == '\\') {
                token += c;
                escaped = true;
                continue;
            }

            if (c == '"' && !in_single) {
                in_double = !in_double;
                token += c;
                continue;
            }

            if (c == '\'' && !in_double) {
                in_single = !in_single;
                token += c;
                continue;
            }

            if (c == ',' && !in_single && !in_double) {
                std::string trimmed = trim(token);
                if (!trimmed.empty()) {
                    result.push_back(trimmed);
                }
                token.clear();
            } else {
                token += c;
            }
        }

        std::string trimmed = trim(token);
        if (!trimmed.empty()) {
            result.push_back(trimmed);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // ПАРСИНГ ОДНОГО ПАРАМЕТРА DEFAULTS
    // ------------------------------------------------------------------------

    void parseSingleDefaultParam(const std::string& param, const std::string& group,
                                const std::string& scope, size_t lineNumber) {
        // Ищем оператор (+=, -=, =)
        size_t opPos = std::string::npos;
        std::string op;

        if ((opPos = param.find("+=")) != std::string::npos) {
            op = "+=";
        } else if ((opPos = param.find("-=")) != std::string::npos) {
            op = "-=";
        } else if ((opPos = param.find('=')) != std::string::npos) {
            op = "=";
        }

        if (opPos == std::string::npos) {
            // Параметр без значения (env_reset, insults, ...)
            config_.push_back(std::make_unique<SingleDefaultsSudoersParam>(
                "Defaults", group, scope, param, lineNumber));
            return;
        }

        // Разделяем ключ и значение
        std::string key = trim(param.substr(0, opPos));
        std::string valuePart = trim(param.substr(opPos + op.length()));

        // Проверяем, является ли значение списком (для +=/-=)
        if (op == "+=" || op == "-=") {
            parseDefaultsValue(key, valuePart, group, scope, op, lineNumber);
        } else {
            // Для простого = создаём один параметр
            config_.push_back(std::make_unique<KeyValueDefaultsSudoersParam>(
                "Defaults", group, scope, key, op, valuePart, lineNumber));
        }
    }

    // ------------------------------------------------------------------------
    // ПАРСИНГ ЗНАЧЕНИЙ DEFAULTS (с поддержкой списков для +=/-=)
    // ------------------------------------------------------------------------

    void parseDefaultsValue(const std::string& key, const std::string& valuePart,
                           const std::string& group, const std::string& scope,
                           const std::string& op, size_t lineNumber) {
        // Разделяем по запятым (с учётом кавычек)
        std::vector<std::string> values = split(valuePart, ',');

        // Если значений несколько — создаём ListDefaultsSudoersParam
        if (values.size() > 1) {
            config_.push_back(std::make_unique<ListDefaultsSudoersParam>(
                "Defaults", group, scope, key, op, values, lineNumber));
        } else if (!values.empty()) {
            // Одно значение — KeyValueDefaultsSudoersParam
            config_.push_back(std::make_unique<KeyValueDefaultsSudoersParam>(
                "Defaults", group, scope, key, op, values[0], lineNumber));
        }
    }

    // ------------------------------------------------------------------------
    // ПАРСИНГ АЛИАСОВ
    // ------------------------------------------------------------------------

    void parseAliasLine(const std::string& line, size_t lineNumber) {
        size_t firstSpace = line.find(' ');
        if (firstSpace == std::string::npos) {
            std::cerr << "Error: Syntax error in alias at line "
                      << lineNumber << ": " << line << std::endl;
            return;
        }

        std::string type = line.substr(0, firstSpace);
        std::string rest = trim(line.substr(firstSpace + 1));

        size_t eqPos = rest.find('=');
        if (eqPos == std::string::npos) {
            std::cerr << "Error: No '=' in alias at line "
                      << lineNumber << ": " << line << std::endl;
            return;
        }

        std::string name = trim(rest.substr(0, eqPos));
        std::string valuesStr = trim(rest.substr(eqPos + 1));

        // Разбиваем значения алиаса на отдельные элементы
        std::vector<std::string> values = split(valuesStr, ',');

        config_.push_back(std::make_unique<AliasSudoersParam>(
            type, name, values, lineNumber));
    }

    // ------------------------------------------------------------------------
    // ПАРСИНГ ТЕГОВ КОМАНД (NOPASSWD:, NOEXEC:, ...)
    // ------------------------------------------------------------------------

    std::pair<std::vector<CommandTag>, std::string> parseCommandTags(const std::string& str) {
        std::vector<CommandTag> tags;
        std::string remaining = trim(str);

        while (!remaining.empty()) {
            size_t colonPos = remaining.find(':');
            if (colonPos == std::string::npos) {
                break;
            }

            std::string tagStr = trim(remaining.substr(0, colonPos));
            CommandTag::Type tagType = CommandTag::fromString(tagStr);

            if (tagType != CommandTag::NONE) {
                tags.push_back({tagType, ""});
                remaining = trim(remaining.substr(colonPos + 1));
            } else {
                break;
            }
        }

        return {tags, remaining};
    }

    // ------------------------------------------------------------------------
    // РАЗВЁРТКА ПРАВИЛ ПРИВИЛЕГИЙ (CARTESIAN PRODUCT)
    // ------------------------------------------------------------------------

    void parsePrivilegeLine(const std::string& line, size_t lineNumber) {
        // Разделяем на пользователя и остаток
        size_t firstSpace = line.find(' ');
        if (firstSpace == std::string::npos) {
            std::cerr << "Error: Syntax error in privilege rule at line "
                      << lineNumber << ": " << line << std::endl;
            return;
        }

        std::string userSpec = trim(line.substr(0, firstSpace));
        std::string rest = trim(line.substr(firstSpace + 1));

        // Находим '=' для разделения хостов и правил
        size_t eqPos = rest.find('=');
        if (eqPos == std::string::npos) {
            std::cerr << "Error: No '=' in privilege rule at line "
                      << lineNumber << ": " << line << std::endl;
            return;
        }

        std::string hostSpec = trim(rest.substr(0, eqPos));
        rest = trim(rest.substr(eqPos + 1));

        // Обрабатываем часть runas (если есть)
        std::string runasUsers, runasGroups;
        if (!rest.empty() && rest[0] == '(') {
            size_t closingParen = rest.find(')');
            if (closingParen == std::string::npos) {
                std::cerr << "Error: Unmatched '(' in privilege rule at line "
                          << lineNumber << ": " << line << std::endl;
                return;
            }
            std::string runasSpec = rest.substr(1, closingParen - 1);
            rest = trim(rest.substr(closingParen + 1));

            size_t colonPos = runasSpec.find(':');
            if (colonPos == std::string::npos) {
                runasUsers = trim(runasSpec);
            } else {
                runasUsers = trim(runasSpec.substr(0, colonPos));
                runasGroups = trim(runasSpec.substr(colonPos + 1));
            }
        }

        // Разбираем команды (с тегами)
        std::string commandSpec = trim(rest);

        // --------------------------------------------------------------------
        // РАЗВЁРТКА: cartesian product пользователей × команд
        // --------------------------------------------------------------------

        std::vector<std::string> users = split(userSpec, ',');
        std::vector<std::string> hosts = split(hostSpec, ',');

        // ИСПРАВЛЕНИЕ: ParsedCommand вместо std::string
        std::vector<ParsedCommand> commands = splitCommands(commandSpec);

        // Создаём отдельное правило для каждой комбинации
        for (const auto& user : users) {
            for (const auto& host : hosts) {
                for (const auto& cmd : commands) {
                    config_.push_back(std::make_unique<PrivilegeSudoersParam>(
                        trim(user),
                        trim(host),
                        trim(runasUsers),
                        trim(runasGroups),
                        cmd.command,    // ← теперь это поле структуры ParsedCommand
                        cmd.tags,       // ← теперь это поле структуры ParsedCommand
                        cmd.negated,    // ← теперь это поле структуры ParsedCommand
                        lineNumber
                    ));
                }
            }
        }
    }

    // Структура для разобранной команды с тегами
    struct ParsedCommand {
        std::string command;
        std::vector<CommandTag> tags;
        bool negated = false;
    };

    // Разбор команд с учётом тегов и отрицаний
    std::vector<ParsedCommand> splitCommands(const std::string& str) {
        std::vector<ParsedCommand> result;
        std::vector<std::string> parts = split(str, ',');

        for (const auto& part : parts) {
            std::string cmd = trim(part);
            if (cmd.empty()) continue;

            ParsedCommand parsed;

            // Проверяем отрицание
            if (!cmd.empty() && cmd[0] == '!') {
                parsed.negated = true;
                cmd = trim(cmd.substr(1));
            }

            // Разбираем теги
            auto [tags, remaining] = parseCommandTags(cmd);
            parsed.tags = tags;
            parsed.command = trim(remaining);

            result.push_back(parsed);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // ОСНОВНОЙ МЕТОД ЗАГРУЗКИ
    // ------------------------------------------------------------------------

    bool loadConfig() override {
        if (!loadFile()) {
            return false;
        }
        config_.clear();

        // Обрабатываем продолжения строк
        handleLineContinuation();

        for (size_t i = 0; i < original_lines_.size(); ++i) {
            const auto& line = original_lines_[i];
            size_t lineNumber = i + 1;

            // Пропускаем полные комментарии
            if (isComment(line)) {
                std::string trimmed = trim(line);
                // Обработка #includedir в комментариях
                if (trimmed.find("#includedir") == 0) {
                    std::string dir = trim(trimmed.substr(11));
                    config_.push_back(std::make_unique<IncludeDirSudoersParam>(
                        "#includedir", dir, lineNumber));
                }
                continue;
            }

            // Определяем тип строки и парсим
            if (line.find("Defaults") == 0) {
                parseDefaultsLine(line, lineNumber);
            } else if (line.find("User_Alias") == 0 ||
                       line.find("Host_Alias") == 0 ||
                       line.find("Runas_Alias") == 0 ||
                       line.find("Cmnd_Alias") == 0) {
                parseAliasLine(line, lineNumber);
            } else if (line.find("@includedir") == 0) {
                std::string dir = trim(line.substr(11));
                config_.push_back(std::make_unique<IncludeDirSudoersParam>(
                    "@includedir", dir, lineNumber));
            } else {
                // Правило привилегий
                parsePrivilegeLine(line, lineNumber);
            }
        }

        return true;
    }

    void printConfig() const override {
        for (const auto& param : config_) {
            std::cout << param->getParamString() << std::endl;
        }
    }

    // ------------------------------------------------------------------------
    // МЕТОДЫ ВАЛИДАЦИИ (ДЛЯ БЕЛОГО/ЧЁРНОГО СПИСКА)
    // ------------------------------------------------------------------------

    // Проверка: имеет ли пользователь доступ к команде
    bool hasCommandAccess(const std::string& user, const std::string& command) const {
        for (const auto& param : config_) {
            if (auto* privilege = dynamic_cast<const PrivilegeSudoersParam*>(param.get())) {
                if (matchUser(privilege->getUser(), user)) {
                    if (matchCommand(privilege->getCommand(), command)) {
                        if (!privilege->isNegated()) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    // Проверка: содержится ли переменная в env_keep
    bool hasEnvKeepVariable(const std::string& varName) const {
        for (const auto& param : config_) {
            if (auto* listDefaults = dynamic_cast<const ListDefaultsSudoersParam*>(param.get())) {
                if (listDefaults->getKey() == "env_keep" &&
                    listDefaults->getOperator() == "+=") {
                    if (listDefaults->hasValue(varName) ||
                        listDefaults->hasValue("\"" + varName + "\"") ||
                        listDefaults->hasValue("'" + varName + "'")) {
                        return true;
                    }
                }
            }
            // Также проверяем KeyValueDefaults (если значение одно)
            if (auto* kvDefaults = dynamic_cast<const KeyValueDefaultsSudoersParam*>(param.get())) {
                if (kvDefaults->getKey() == "env_keep") {
                    std::string val = kvDefaults->getValue();
                    if (val == varName || val == "\"" + varName + "\"" ||
                        val == "'" + varName + "'") {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // Проверка: является ли пользователь членом группы в правилах
    bool isUserInGroup(const std::string& user, const std::string& group) const {
        std::string groupSpec = "%" + group;
        for (const auto& param : config_) {
            if (auto* privilege = dynamic_cast<const PrivilegeSudoersParam*>(param.get())) {
                if (privilege->getUser() == groupSpec) {
                    // Группа указана в правиле — нужно проверить алиасы
                    // Для полной проверки нужно разрешать алиасы
                    return true; // Упрощённая проверка
                }
            }
        }
        return false;
    }

    // Получить все правила для пользователя
    std::vector<const PrivilegeSudoersParam*> getUserRules(const std::string& user) const {
        std::vector<const PrivilegeSudoersParam*> rules;
        for (const auto& param : config_) {
            if (auto* privilege = dynamic_cast<const PrivilegeSudoersParam*>(param.get())) {
                if (matchUser(privilege->getUser(), user)) {
                    rules.push_back(privilege);
                }
            }
        }
        return rules;
    }

    // Получить все Defaults параметры
    std::vector<const SudoersParam*> getDefaultsParams() const {
        std::vector<const SudoersParam*> result;
        for (const auto& param : config_) {
            if (param->getType() == "Defaults") {
                result.push_back(param.get());
            }
        }
        return result;
    }

    // Проверка timestamp_timeout
    bool checkTimestampTimeout(int maxTimeout) const {
        for (const auto& param : config_) {
            if (auto* defaults = dynamic_cast<const KeyValueDefaultsSudoersParam*>(param.get())) {
                if (defaults->getKey() == "timestamp_timeout") {
                    try {
                        int timeout = std::stoi(defaults->getValue());
                        return timeout <= maxTimeout;
                    } catch (...) {
                        return false;
                    }
                }
            }
        }
        return true; // Параметр не найден, используется значение по умолчанию
    }

    // Получить алиас по имени
    const AliasSudoersParam* getAlias(const std::string& name) const {
        for (const auto& param : config_) {
            if (auto* alias = dynamic_cast<const AliasSudoersParam*>(param.get())) {
                if (alias->getAliasName() == name) {
                    return alias;
                }
            }
        }
        return nullptr;
    }

private:
    std::vector<std::unique_ptr<SudoersParam>> config_;

    bool isSameDefaultsParameter(const KeyValueDefaultsSudoersParam& current,
                                 const KeyValueDefaultsSudoersParam& expected) const {
        return current.getType() == expected.getType() &&
               current.getGroup() == expected.getGroup() &&
               current.getScope() == expected.getScope() &&
               current.getKey() == expected.getKey() &&
               current.getOperator() == expected.getOperator();
    }

    bool isSameDefaultsParameter(const SingleDefaultsSudoersParam& current,
                                 const SingleDefaultsSudoersParam& expected) const {
        return current.getType() == expected.getType() &&
               current.getGroup() == expected.getGroup() &&
               current.getScope() == expected.getScope() &&
               current.getKey() == expected.getKey();
    }

    std::string buildDefaultsLine(const KeyValueDefaultsSudoersParam& parameter,
                                  const std::string& value) const {
        KeyValueDefaultsSudoersParam updated(
            parameter.getType(),
            parameter.getGroup(),
            parameter.getScope(),
            parameter.getKey(),
            parameter.getOperator(),
            value,
            0);
        return updated.getParamString();
    }

    std::string buildDefaultsLine(const SingleDefaultsSudoersParam& parameter) const {
        SingleDefaultsSudoersParam updated(
            parameter.getType(),
            parameter.getGroup(),
            parameter.getScope(),
            parameter.getKey(),
            0);
        return updated.getParamString();
    }

    // Проверка соответствия пользователя (с учётом %, +, ALL)
    bool matchUser(const std::string& ruleUser, const std::string& queryUser) const {
        if (ruleUser == "ALL") return true;
        if (ruleUser == queryUser) return true;
        if (ruleUser == "%" + queryUser) return true;  // группа
        if (ruleUser == "+" + queryUser) return true;  // netgroup
        return false;
    }

    // Проверка соответствия команды (с учётом wildcards)
    bool matchCommand(const std::string& ruleCmd, const std::string& queryCmd) const {
        if (ruleCmd == "ALL") return true;
        if (ruleCmd == queryCmd) return true;

        // Простая поддержка wildcards
        if (ruleCmd.find('*') != std::string::npos) {
            // Преобразуем wildcard в regex
            std::string pattern = ruleCmd;
            pattern = std::regex_replace(pattern, std::regex("\\."), "\\.");
            pattern = std::regex_replace(pattern, std::regex("\\*"), ".*");
            try {
                std::regex re(pattern);
                return std::regex_match(queryCmd, re);
            } catch (...) {
                return false;
            }
        }

        return false;
    }
};


//Для безопасного редактирования sudo
class Sudo : public DAC
{
protected:
    const static std::string sudoersPath;

    /*Здесь храним распарсенный /etc/sudoers*/
    static std::unique_ptr<SudoersConfigFileHandler> sudoConfig;

    //Соответствие какого параметра проверяем?
    std::unique_ptr<SudoersParam> sudoParameter;
public:
    Sudo();
    bool apply () override;
    virtual ~Sudo();
};

#endif // SUDOEDIT_H
