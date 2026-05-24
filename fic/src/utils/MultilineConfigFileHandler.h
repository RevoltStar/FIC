// MultilineConfigFileHandler.h
#ifndef MULTILINECONFIGFILEHANDLER_H
#define MULTILINECONFIGFILEHANDLER_H

#include "ConfigFileHandler.h"
#include <vector>

class MultilineConfigFileHandler : public ConfigFileHandler {
public:
    MultilineConfigFileHandler(const std::string& filepath, const std::string& delimeter = "=");

    // Загружаем конфигурационный файл с поддержкой многострочных значений
    bool loadConfig() override;

    // Получить параметр как многострочное значение
    std::vector<std::string> getMultilineValue(const std::string& parameter) const;

    // Установить многострочное значение
    bool setMultilineValue(const std::string& parameter, const std::vector<std::string>& values);

private:
    // Проверяет, является ли строка началом нового параметра
    bool isNewParameter(const std::string& line) const;
};

#endif // MULTILINECONFIGFILEHANDLER_H
