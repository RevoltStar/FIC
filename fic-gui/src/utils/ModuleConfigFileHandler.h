#ifndef MODULECONFIGFILEHANDLER_H
#define MODULECONFIGFILEHANDLER_H
#include "FileHandler.h"
#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>

//Значение параметра
struct ModuleConfig{
    std::string isEnable;
    std::string value;
};

class ModuleConfigFileHandler : public FileHandler {
private:
    const static std::string moduleFolderPath;
public:
    ModuleConfigFileHandler(const std::string& module);

    bool loadConfig() override;

    //Дать значение параметра
    std::string getValue(const std::string& parameter) const;
    //Дать активность параметра
    std::string getIsEnable(const std::string& parameter);

    //Изменить значение параметра модуля
    bool setValue(const std::string& parameter, const std::string& value) override;

    //Вывести весь конфиг
    void printConfig() const override;

    //Сохранить конфиг
    bool saveConfig();

    bool enableParam(const std::string& parameter);
    bool disableParam(const std::string& parameter);

    bool isParameterExists(const std::string& parameter);
private:
    std::string section(std::string& str, const std::string& sep, int start, int end = -1);
    //Конфиг (parameter:type:isEnable:value)
    std::unordered_map<std::string, ModuleConfig> config_;
};

#endif // MODULECONFIGFILEHANDLER_H
