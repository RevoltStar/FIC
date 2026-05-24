#include "utils/ModuleConfigFileHandler.h"
#include <sys/stat.h>
#include <fstream>
#include <string>
#include <iostream>
const std::string ModuleConfigFileHandler::moduleFolderPath = "/opt/fic/config";

ModuleConfigFileHandler::ModuleConfigFileHandler(const std::string& module)
    :FileHandler(moduleFolderPath + "/" + module + ".conf", ":"){
    //Загружаем файл в переменную
    //this->FileHandler::loadFile();
    //Создаем конфигурационный файл
    //this->ModuleConfigFileHandler::loadConfig();
}

//Извлечение подстроки
std::string ModuleConfigFileHandler::section(std::string& str, const std::string& sep, int start, int end) {
  if (sep.empty()) {
    return str;
  }
  std::vector<std::string> sections;
  size_t start_pos = 0;
  size_t end_pos = str.find(sep);

  while (end_pos != std::string::npos) {
    sections.push_back(str.substr(start_pos, end_pos - start_pos));
    start_pos = end_pos + sep.length();
    end_pos = str.find(sep, start_pos);
  }

  sections.push_back(str.substr(start_pos));

  if (start < 0 || start >= sections.size()) {
    return "";
  }

  if (end == -1) {
    end = sections.size() - 1;
  }

  if (end < start || end >= sections.size()) {
    return "";
  }

  std::string result;
  for (int i = start; i <= end; ++i) {
    result += sections[i];
    if (i < end) {
      result += sep;
    }
  }

  return result;
}

//Иницализируем переменную config
bool ModuleConfigFileHandler::loadConfig() {
    if(!this->FileHandler::loadFile()){
        return false;
    }
    config_.clear();
    //Обходим файл
    for (std::string& line : this->FileHandler::original_lines_) {
        // Удаляем комментарии (строки, начинающиеся с #)
        const size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line.resize(comment_pos);
        }

        // Удаляем пробельные символы с обеих сторон
        trim(line);

        // Пропускаем пустые строки
        if (line.empty()) {
            continue;
        }

        //Название настройки
        auto elemName = this->section(line, ":", 0, 0);
        //Настройка включена?
        auto isEnable = this->section(line,":", 1, 1);
        //Значение параметра
        auto value = this->section(line,":", 2);

        // Удаляем пробельные символы из параметра и значения
        trim(elemName);
        trim(isEnable);
        trim(value);

        if(elemName.empty() || isEnable.empty()){
            continue;
        }
        this->config_[elemName] = ModuleConfig{isEnable, value};
    }
    return true;
}

bool ModuleConfigFileHandler::isParameterExists(const std::string& parameter){
    const auto it = config_.find(parameter);
    return it != config_.end();
}

//Получить параметр
std::string ModuleConfigFileHandler::getValue(const std::string& parameter) const{
    const auto it = config_.find(parameter);
    return it != config_.end() ? it->second.value : "";
}

//Дать активность параметра
std::string ModuleConfigFileHandler::getIsEnable(const std::string& parameter){
    const auto it = config_.find(parameter);
    return it != config_.end() ? it->second.isEnable : "";
}

//Установить значение
bool ModuleConfigFileHandler::setValue(const std::string& parameter, const std::string& newValue) {
    const auto it = config_.find(parameter);
    if(it == config_.end()){
        ModuleConfig newParam = {"DISABLE", newValue};
        config_[parameter] = newParam;
        return true;
    }
    ModuleConfig mf = it->second;
    if(mf.value == newValue){
        std::cout << "Новое значение не отличается от старого." << "\n";
        return true;
    }

    mf.value = newValue;
    it->second = mf;
    return true;
}

//Сохранить значение модуля
//todo потом переделать.
bool ModuleConfigFileHandler::saveConfig(){
    std::ofstream file(filepath_, std::ios::trunc | std::ios::out);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file for writing: " << filepath_ << std::endl;
        return false;
    }

    for (auto it : this->config_) {
        //it->first - ключ
        //it->second - значение
        //Конфиг (parameter:isEnable:value)

        file << it.first << ":" <<it.second.isEnable << ":" << it.second.value << '\n';
    }

    file.close();
    return true;
}

bool ModuleConfigFileHandler::enableParam(const std::string& parameter){
    const auto it = config_.find(parameter);
    if(it == config_.end()){
        return false;
    }
    ModuleConfig mf = it->second;
    if(mf.isEnable == "ENABLE"){
        std::cout << "Новое значение не отличается от старого. [ENABLE->ENABLE]" << "\n";
        return true;
    }

    mf.isEnable = "ENABLE";
    it->second = mf;
    return true;
}
bool ModuleConfigFileHandler::disableParam(const std::string& parameter){
    const auto it = config_.find(parameter);
    if(it == config_.end()){
        return false;
    }
    ModuleConfig mf = it->second;
    if(mf.isEnable  == "DISABLE"){
        std::cout << "Новое значение не отличается от старого. [DISABLE->DISABLE]" << "\n";
        return true;
    }

    mf.isEnable= "DISABLE";
    it->second = mf;
    return true;
}

//Вывести конфигурационный файл
void ModuleConfigFileHandler::printConfig() const{
    std::cout << "Политики модуля:" << "\n";
    for (const auto& pair : config_) {
        std::cout << "ПАРАМЕТР: '" << pair.first << "' ЗНАЧЕНИЕ:'" << pair.second.value << "' АКТИВНО?:'" << pair.second.isEnable << "'\n";
    }
}
