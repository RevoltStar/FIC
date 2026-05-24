#ifndef SINGLELINEFILEHANDLER_H
#define SINGLELINEFILEHANDLER_H

#include "FileHandler.h"

//Класс для работы с конфигурационным файлом, в котором параметр - первая строка
class SingleLineFileHandler : public FileHandler {
public:
    SingleLineFileHandler(const std::string& filepath);

    // Загружаем конфигурационный файл
    bool loadConfig() override;

    // Получить параметр (в данном случае всю строку)
    std::string getValue(const std::string& parameter = "") const override;

    // Установить значение (заменить всю строку)
    bool setValue(const std::string& parameter, const std::string& value) override;

    //Сохранить изменения
    bool saveConfig();

    // Вывести конфигурационный файл
    void printConfig() const override;

    // Закомментировать все параметры в файле (в данном случае закомментировать строку)
    bool commentAllParameters() override;

protected:
    std::string current_line_;  // Текущая строка с данными
    int data_line_index_;       // Индекс строки с полезными данными в original_lines_
};

#endif // SINGLELINEFILEHANDLER_H
