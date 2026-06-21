#include <fic/policy/PolicyTypeValue.h>

#include <algorithm>
#include <cctype>
#include <iostream>
#include <stdexcept>

PolicyTypeValue::PolicyTypeValue() {
}

std::string PolicyTypeValue::getDefaultValue() {
    return this->defaultValue;
}

/*
IntPolicyTypeValue::IntPolicyTypeValue(int _min, int _max)
    : PolicyTypeValue() {
    if (_min >= _max){
        throw std::invalid_argument("MAX должен быть больше MIN");
    }
    min = _min;
    max = _max;
    this->defaultValue = _min;
}
*/
IntPolicyTypeValue::IntPolicyTypeValue(int _min, int _max, int _defaultValue)
    : PolicyTypeValue() {
    if (_min >= _max){
        throw std::invalid_argument("MAX должен быть больше MIN");
    }
    if(_defaultValue > _max || _defaultValue < _min){
        throw std::invalid_argument("DEFAULT VALUE должен находиться в диапазоне [MIN;MAX]");
    }
    min = _min;
    max = _max;
    this->defaultValue = std::to_string(_defaultValue);
}

PolicyEditorSpec IntPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;
    spec.editor = "spinbox";
    spec.min = this->min;
    spec.max = this->max;
    return spec;
}

bool IntPolicyTypeValue::validate(const std::string& value) {
    if (value.empty()) {
        std::cerr << "Ошибка: пустая строка\n";
        return false;
    }

    try {
        int num = std::stoi(value);

        if (num < this->min || num > this->max) {
            std::cerr << "Ошибка: значение " << num
                      << " вне допустимого диапазона ["
                      << this->min << ", " << this->max << "]\n";
            return false;
        }

        return true;
    }
    catch (const std::invalid_argument&) {
        std::cerr << "Ошибка: '" << value << "' не является числом\n";
        return false;
    }
    catch (const std::out_of_range&) {
        std::cerr << "Ошибка: число '" << value
                  << "' выходит за пределы диапазона int\n";
        return false;
    }
}

std::string IntPolicyTypeValue::getPolicyRestrictionInfo() {
    return LocalizationManager::getLang("[utils:policytypevalue][type:intpolicytypevalue]") + 
        " [" +
        std::to_string(this->min) +
        ";"
        +
        std::to_string(this->max) +
        "]";
}

std::string IntPolicyTypeValue::postProcessingValue(const std::string& value) {
    return value;
}

std::string IntPolicyTypeValue::reverse_postProcessingValue(const std::string& value) {
    return value;
}

PossibleListPolicyTypeValue::PossibleListPolicyTypeValue(const std::vector<std::string>& _possibleList)
    : PolicyTypeValue() {
    if(_possibleList.size() == 0){
        throw std::invalid_argument("Массив не должен быть пустым");
    }
    this->possibleList = _possibleList;
    this->defaultValue = _possibleList[0];
}

bool PossibleListPolicyTypeValue::validate(const std::string& value) {
    bool is_valid = std::find(this->possibleList.begin(), this->possibleList.end(), value) != this->possibleList.end();
    if (!is_valid) {
        return false;
    }

    return true;
}

PolicyEditorSpec PossibleListPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;
    spec.editor = "combobox";
    spec.possibleValues = this->possibleList;
    return spec;
}

std::string PossibleListPolicyTypeValue::getPolicyRestrictionInfo() {
    std::string strConcat = "";
    for(int i = 0; i < this->possibleList.size();i++){
        strConcat += this->possibleList[i] + "\n";
    }
    return
        LocalizationManager::getLang("[utils:policytypevalue][type:possiblelistpolicytypevalue]") +
        "\n" +
        strConcat;
}

std::string PossibleListPolicyTypeValue::postProcessingValue(const std::string& value) {
    return value;
}

std::string PossibleListPolicyTypeValue::reverse_postProcessingValue(const std::string& value) {
    return value;
}

/*
EnableDisablePolicyTypeValue::EnableDisablePolicyTypeValue()
    : PossibleListPolicyTypeValue({"ENABLE", "DISABLE"}) {
    this->defaultValue = "DISABLE";
}

bool EnableDisablePolicyTypeValue::validate(const std::string& value) {
    return this->PossibleListPolicyTypeValue::validate(value);
}

std::string EnableDisablePolicyTypeValue::postProcessingValue(const std::string& value) {
    return this->PossibleListPolicyTypeValue::postProcessingValue(value);
}

std::string EnableDisablePolicyTypeValue::reverse_postProcessingValue(const std::string& value) {
    return this->PossibleListPolicyTypeValue::reverse_postProcessingValue(value);
}
*/

FixedPolicyTypeValue::FixedPolicyTypeValue(){
    this->defaultValue = "[FIXED_VALUE]";
}

PolicyEditorSpec FixedPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;
    spec.editor = "label";
    return spec;
}

bool FixedPolicyTypeValue::validate(const std::string& value) {
    return true;
}

std::string FixedPolicyTypeValue::postProcessingValue(const std::string& value) {
    return value;
}

std::string FixedPolicyTypeValue::reverse_postProcessingValue(const std::string& value) {
    return value;
}

std::string FixedPolicyTypeValue::getPolicyRestrictionInfo() {
    return LocalizationManager::getLang("[utils:policytypevalue][type:fixedpolicytypevalue]");
}

/*
MultiLineTextPolicyTypeValue::MultiLineTextPolicyTypeValue(std::string _delimiterFrom, std::string _delimiterTo)
    : PolicyTypeValue() {
    this->defaultValue = "[ЗНАЧЕНИЕ ПО УМОЛЧАНИЮ]";
    this->delimiterFrom = _delimiterFrom;
    this->delimiterTo = _delimiterTo;
}
*/
MultiLineTextPolicyTypeValue::MultiLineTextPolicyTypeValue(std::string _delimiterFrom, std::string _delimiterTo, std::string _defaultValue)
    : PolicyTypeValue() {
    this->defaultValue = _defaultValue;
    this->delimiterFrom = _delimiterFrom;
    this->delimiterTo = _delimiterTo;
}

PolicyEditorSpec MultiLineTextPolicyTypeValue::getEditorSpec() const {
    PolicyEditorSpec spec;
    spec.editor = "textedit";
    spec.textDelimiter = this->delimiterTo;
    return spec;
}

bool MultiLineTextPolicyTypeValue::validate(const std::string& value) {
    return true;
}

std::string MultiLineTextPolicyTypeValue::postProcessingValue(const std::string& value) {
    try {
        if (value.empty()) {
            throw std::invalid_argument("Input string is empty");
        }

        if (delimiterFrom.empty()) {
            throw std::runtime_error("Delimiter is not set");
        }

        std::vector<std::string> items;
        size_t start = 0;
        size_t end = value.find(delimiterFrom);

        if (end == std::string::npos && !value.empty()) {
            return json({value}).dump();
        }

        while (end != std::string::npos) {
            if (start == end) {
                items.emplace_back("");
            } else {
                items.push_back(value.substr(start, end - start));
            }
            start = end + delimiterFrom.length();
            end = value.find(delimiterFrom, start);
        }

        if (start < value.length()) {
            items.push_back(value.substr(start));
        } else if (start == value.length()) {
            items.emplace_back("");
        }

        if (items.empty()) {
            throw std::runtime_error("Resulting array is empty");
        }

        return json(items).dump();

    } catch (const std::exception& e) {
        std::cerr << "Ошибка при постобработке параметра: " << e.what() << std::endl;
        return "";
    } catch (...) {
        std::cerr << "Unknown error in postprocessing" << std::endl;
        return "";
    }
}

std::string MultiLineTextPolicyTypeValue::reverse_postProcessingValue(const std::string& value) {
    try {
        auto j = json::parse(value);

        if (!j.is_array()) {
            throw std::runtime_error("Ожидался JSON-массив");
        }

        std::vector<std::string> items;
        for (const auto& item : j) {
            items.push_back(item.get<std::string>());
        }

        std::string result;
        for (size_t i = 0; i < items.size(); ++i) {
            if (i != 0) {
                result += delimiterTo;
            }
            result += items[i];
        }

        return result;
    } catch (const json::parse_error& e) {
        throw std::runtime_error("Ошибка парсинга JSON: " + std::string(e.what()));
    } catch (const json::type_error& e) {
        throw std::runtime_error("Некорректный тип данных в JSON: " + std::string(e.what()));
    }
}

std::string MultiLineTextPolicyTypeValue::getPolicyRestrictionInfo() {
    return LocalizationManager::getLang("[utils:policytypevalue][type:multilinepolicytypevalue]");
}

std::vector<std::string> MultiLineTextPolicyTypeValue::split_paths(const std::string& str, const char delimiter) {
    std::vector<std::string> paths;
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::string::npos) {
        std::string path = str.substr(start, end - start);
        path.erase(path.begin(), std::find_if(path.begin(), path.end(), [](int ch) { return !std::isspace(ch); }));
        path.erase(std::find_if(path.rbegin(), path.rend(), [](int ch) { return !std::isspace(ch); }).base(), path.end());

        if (!path.empty()) {
            paths.push_back(path);
        }
        start = end + 1;
        end = str.find(delimiter, start);
    }

    std::string last_path = str.substr(start);
    last_path.erase(last_path.begin(), std::find_if(last_path.begin(), last_path.end(), [](int ch) { return !std::isspace(ch); }));
    last_path.erase(std::find_if(last_path.rbegin(), last_path.rend(), [](int ch) { return !std::isspace(ch); }).base(), last_path.end());

    if (!last_path.empty()) {
        paths.push_back(last_path);
    }

    return paths;
}
