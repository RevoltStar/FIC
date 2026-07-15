#ifndef SECTIONCONFIGFILEHANDLER_H
#define SECTIONCONFIGFILEHANDLER_H

#include <fic/core/FileHandler.h>
#include <vector>

class SectionConfigFileHandler : public FileHandler {
public:
    SectionConfigFileHandler(const std::string& filepath,
                             FileHandlerOptions options = {});

    // Загрузка конфигурации из файла
    bool loadConfig() override;

    // Получение значения параметра из указанной секции
    std::string getValue(const std::string& section, const std::string& parameter) const;

    // Получение значения с явным признаком существования параметра
    bool tryGetValue(const std::string& section, const std::string& parameter, std::string& value) const;

    // Установка значения параметра в указанной секции
    bool setValue(const std::string& section, const std::string& parameter, const std::string& value);

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
    struct Parameter {
        std::string name;
        std::string value;
        size_t line;
    };

    // Структура для хранения данных секции
    struct Section {
        std::string name;
        std::vector<Parameter> parameters;
        size_t startLine;  // Номер строки начала секции
        size_t endLine;    // Номер строки конца секции
    };

    // Поиск секции по имени
    std::vector<Section>::iterator findSection(const std::string& section);
    std::vector<Section>::const_iterator findSection(const std::string& section) const;
    std::vector<Parameter>::iterator findParameter(Section& section, const std::string& parameter);
    std::vector<Parameter>::const_iterator findParameter(const Section& section, const std::string& parameter) const;

    // Парсинг строки параметра
    bool parseParameterLine(const std::string& line, std::string& parameter, std::string& value) const;

    // Перестроение индекса секций по текущим строкам файла
    void rebuildSectionsFromOriginalLines();
    std::string formatParameterLine(const std::string& parameter, const std::string& value) const;
    size_t findParameterInsertLine(const Section& section) const;
    bool isCommentOrEmpty(const std::string& line) const;

    // Данные конфигурации
    std::vector<Section> sections_;
};

#endif // SECTIONCONFIGFILEHANDLER_H
