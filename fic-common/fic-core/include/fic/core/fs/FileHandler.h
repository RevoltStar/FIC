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

    enum class FileSaveResult {
        Installed,
        RefusedChanged,
        Failed
    };

    // Structured save outcome (see saveFileIfUnchanged()).
    struct FileSaveOutcome {
        FileSaveResult result = FileSaveResult::Failed;
        // True when the replacement DID happen (rename succeeded), even when
        // a later durability step (directory fsync) failed and result is
        // Failed. Callers must never treat installed==true as "file
        // unchanged": the system may already carry the new content.
        bool installed = false;
        // True when the write was refused by the optimistic precondition
        // before anything was installed (nothing was replaced).
        bool preconditionFailed = false;
        // Present only when installed == true: the exact target state FIC
        // published through rename — the compensation anchor for conditional
        // restores. Available even when a post-rename durability step failed.
        std::optional<AtomicTargetState> installedTargetState;
    };

    // Optimistic save: replaces the file only when it still matches the
    // target state captured by the last load (see loadSnapshot()). Protects
    // shared configuration files against concurrent external modification
    // between load and save (TOCTOU). Returns RefusedChanged without writing
    // anything when the file changed, Failed when the write failed — the
    // structured outcome distinguishes a pre-install failure (installed ==
    // false, nothing was replaced) from a post-rename durability failure
    // (installed == true, the target already carries the new content and
    // installedTargetState holds the exact installed state).
    FileSaveOutcome saveFileIfUnchanged(std::string& error);

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
