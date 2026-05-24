#ifndef SECTIONCONFIGFILEHANDLER_H
#define SECTIONCONFIGFILEHANDLER_H

#include "FileHandler.h"
#include <unordered_map>
#include <vector>

class SectionConfigFileHandler : public FileHandler {
public:
    SectionConfigFileHandler(const std::string& filepath);

    // Загрузка конфигурации из файла
    bool loadConfig() override;

    // Получение значения параметра из указанной секции
    std::string getValue(const std::string& section, const std::string& parameter) const;

    // Установка значения параметра в указанной секции
    bool setValue(const std::string& section, const std::string& parameter, const std::string& value = "");

    // Получение списка параметров в секции
    std::vector<std::string> getParameters(const std::string& section) const;

    // Получение списка всех секций
    std::vector<std::string> getSections() const;

    // Проверка существования секции
    bool hasSection(const std::string& section) const;

    // Проверка существования параметра в секции
    bool hasParameter(const std::string& section, const std::string& parameter) const;

    // Добавление новой секции
    bool addSection(const std::string& section);

    // Удаление секции
    bool removeSection(const std::string& section);

    // Удаление параметра из секции
    bool removeParameter(const std::string& section, const std::string& parameter);

    // Сохранение конфигурации в файл
    bool saveConfig();

    // Вывод конфигурации
    void printConfig() const override;

    // Реализация абстрактных методов FileHandler
    bool setValue(const std::string& parameter, const std::string& value) override;
    std::string getValue(const std::string& parameter) const override;

private:
    // Структура для хранения данных секции
    struct Section {
        std::string name;
        std::unordered_map<std::string, std::string> parameters;
        size_t startLine;  // Номер строки начала секции
        size_t endLine;    // Номер строки конца секции
    };

    // Поиск секции по имени
    std::vector<Section>::iterator findSection(const std::string& section);
    std::vector<Section>::const_iterator findSection(const std::string& section) const;

    // Парсинг строки параметра
    bool parseParameterLine(const std::string& line, std::string& parameter, std::string& value) const;

    // Обновление оригинальных строк файла
    void updateOriginalLines();

    // Данные конфигурации
    std::vector<Section> sections_;
};

#endif // SECTIONCONFIGFILEHANDLER_H
