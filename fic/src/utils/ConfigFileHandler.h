#ifndef CONFIGFILEHANDLER_H
#define CONFIGFILEHANDLER_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <algorithm>
#include "FileHandler.h"

//Класс для работы с конфигурационными файлами вида
//ключ1<разделитель>значение1
//ключ2<разделитель>значение2
class ConfigFileHandler : public FileHandler {
private:

public:
    //delimeter может принимать одно из следующих специальных значений
    ConfigFileHandler(const std::string& filepath, const std::string& delimeter = "=");
    //Загружаем конфигурационный файл
    bool loadConfig() override;

    //Загружаем конфигурационный файл (если не указали путь и разделитель раньше)
    bool loadConfig(const std::string& filepath, const std::string& delimeter = "=");

    //Получить параметр
    std::string getValue(const std::string& parameter) const override;

    //Установить значение
    bool setValue(const std::string& parameter, const std::string& value="") override;

    //Сохранить конфигурационный файл
    //bool saveConfig();

    //Вывести конфигурационный файл
    void printConfig() const override;

    //Закомментировать все параметры в файле
    /*bool commentAllParameters() override;*/

    //Пока не нужна
    bool isEmptyConfig();

    //Количество параметров
    int parameterCount();

    bool isParameterExists(const std::string& parameter) const;
    const std::unordered_map<std::string, std::string>& entries() const;
protected:
    //Конфиг
    std::unordered_map<std::string, std::string> config_;
};


#endif // CONFIGFILEHANDLER_H
