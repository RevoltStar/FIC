#ifndef FILEHANDLER_H
#define FILEHANDLER_H

#include <fic/core/fs/AtomicFileWriter.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <unordered_map>
#include <algorithm>


/*
Базовый класс для работы с файлами
*/
struct FileHandlerOptions {
    AtomicWriteOptions writeOptions;
};

class FileHandler {
public:
    FileHandler(const std::string& filepath,
                const std::string& delimiter = "=",
                FileHandlerOptions options = {});

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

    // Optimistic save: replaces the file only when it still matches the
    // target state captured by the last load (see loadSnapshot()). Protects
    // shared configuration files against concurrent external modification
    // between load and save (TOCTOU). Returns RefusedChanged without writing
    // anything when the file changed, Failed when the write failed without
    // installing anything, Installed on success. When installedState is
    // provided and the file was installed, it receives the exact state FIC
    // published through rename (identity, metadata, content) — the
    // compensation anchor for later conditional restores.
    enum class FileSaveResult {
        Installed,
        RefusedChanged,
        Failed
    };
    FileSaveResult saveFileIfUnchanged(
        std::string& error,
        std::optional<AtomicTargetState>* installedState = nullptr);

    // Target state (identity, metadata, content) captured by the last load,
    // when the concrete handler captures it; empty otherwise.
    const std::optional<AtomicTargetState>& loadSnapshot() const {
        return loadSnapshot_;
    }
    //Закомментировать все параметры в файле
    /*virtual bool commentAllParameters();*/

    virtual ~FileHandler() = default;
protected:
    //Преобразуем несколько пробельных символов в один
    std::string collapseSpaces(const std::string& input);

    //Убрать пробельные символы
    void trim(std::string& str, bool needMid = false) const;
    //Разделитель
    std::string delimiter_;
    //Путь к файлу
    std::string filepath_;
    //Политика создания и безопасной записи файла
    FileHandlerOptions options_;
    // Optimistic snapshot of the target captured by the concrete handler at
    // load time; used by saveFileIfUnchanged().
    std::optional<AtomicTargetState> loadSnapshot_;
    // Сохраняем оригинальные строки из файла
    std::vector<std::string> original_lines_;
};
#endif // FILEHANDLER_H
