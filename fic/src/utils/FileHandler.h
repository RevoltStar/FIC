#ifndef FILEHANDLER_H
#define FILEHANDLER_H

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <unordered_map>
#include <algorithm>

class FileHandler {
public:
    FileHandler(const std::string& filepath, const std::string& delimeter = "=");

    //Загрузить файл
    bool loadFile();

    //Загружаем конфигурационный файл
    virtual bool loadConfig() ;
    //Получить параметр
    virtual std::string getValue(const std::string& parameter) const;

    //Установить значение
    //true - значение установлено успешно
    //false - значение установить не удалось
    virtual bool setValue(const std::string& parameter, const std::string& value) = 0;

    //Вывести конфигурационный файл
    virtual void printConfig() const;

    //Сохранить файл
    bool saveFile();
    //Закомментировать все параметры в файле
    /*virtual bool commentAllParameters();*/

    virtual ~FileHandler() = default;
protected:
    //Преобразуем несколько пробельных символов в один
    std::string collapseSpaces(const std::string& input);

    //Убрать пробельные символы
    void trim(std::string& str, bool needMid = false) const;
    //Разделитель
    std::string delimeter_;
    //Путь к файлу
    std::string filepath_;
    // Сохраняем оригинальные строки из файла
    std::vector<std::string> original_lines_;
};
#endif // FILEHANDLER_H
