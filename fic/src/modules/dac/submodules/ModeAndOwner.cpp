#include "modules/dac/submodules/ModeAndOwner.h"
ModeAndOwner::ModeAndOwner()
    :DAC()
{
    this->submoduleName = "Mode_and_Owner";
}

//Проверить и исправить права и владельца
bool ModeAndOwner::apply() {
    this->log("Запуск функции Mode_And_Owner::apply", logLevel::TRACE);
    int total = 0, success = 0, failed = 0, fixed = 0;
    for (auto& [filename, expected_stats] : this->ModeAndOwner::expected) {
        //Сколько параметров всего
        total++;
        //Полный путь для утилиты
        std::string full_path = filename;
        //Список ошибок при проверке
        std::vector<std::string> errors;

        //Текущие настройки файла
        //expected_stats->ожидаемые параметры
        FileStats current_stats = FileStats(full_path);

        if (!current_stats.exists) {
            this->log("Файл" + full_path + " не найден", logLevel::DEBUG);
            //Если файла нет, то считаем что все хорошо
            success++;
            continue;
        }

        this->log("Проверка файла " + full_path, logLevel::INFO);

        // Определяем какую группу использовать (проверяем существует ли указанная)
        if (!current_stats.group_exists(expected_stats._group)) {
            this->log("   Группа '" + expected_stats._group + "' не существует, будет использована 'root'" , logLevel::DEBUG);
            //Меняем на root, если нет указанной
            expected_stats.change_group_to_root();
        }

        // Проверка владельца/группы
        if(!current_stats.check_owner_group(expected_stats)){
            //Если владелец/группа не совпадают с ожиданием
            if(current_stats.change_owner_group(full_path, expected_stats._owner, expected_stats._group)){
                //Если получилось поменять на эталон
                fixed++;
                this->log("  Владелец для файла " + filename + " был исправлен [" + current_stats._owner + ":" + current_stats._group
                          + " → " + expected_stats._owner + ":" + expected_stats._group
                          + "]... Исправлено", logLevel::DEBUG);
            }else{
                //Если не получилось поменять на эталон
                errors.push_back("Владелец/группа не изменён");
                this->log("  Владелец для файла " + filename + " не был исправлен [" + current_stats._owner + ":" + current_stats._group
                          + " → " + expected_stats._owner + ":" + expected_stats._group
                          + "]... ОШИБКА", logLevel::ERROR);
            }
        }else{
            this->log("Владелец/группа: ОК для " + filename, logLevel::DEBUG);
        }

        //Проверка прав доступа
        if(!current_stats.check_permission(expected_stats)){
            if(current_stats.change_permissions(full_path, expected_stats._permissions)){
                fixed++;
                this->log("  Права для файла " + filename + " были исправлены [" + current_stats.permToString()
                          + " → " + expected_stats.permToString() + "]... Исправлено", logLevel::DEBUG);
            }else{
                errors.push_back("Права не изменены");
                this->log("  Права для файла " + filename + " исправлены не были [" + current_stats.permToString()
                          + " → " + expected_stats.permToString() + "]... ОШИБКА", logLevel::ERROR);
            }
        }else{
            //Права ОК
            this->log("   Права: ОК (" + expected_stats.permToString() + ")", logLevel::DEBUG);
        }

        // Итог по файлу
        if (!errors.empty()) {
            if (errors.size() == 2) {
                this->log("  ИТОГ: Полностью не соответствует требованиям ("
                          + errors[0] + "; " + errors[1] + ")", logLevel::ERROR);
            } else {
                this->log("  ИТОГ: Частично соответствует требованиям (" + errors[0] + ")", logLevel::ERROR);
            }
            failed++;
        } else {
            if (current_stats._owner != expected_stats._owner ||
                current_stats._group != expected_stats._group ||
                current_stats._permissions != expected_stats._permissions) {
                this->log("  ИТОГ: Полностью исправлено", logLevel::INFO);
            } else {
                this->log("  ИТОГ: Соответствует требованиям", logLevel::INFO);
            }
            success++;
        }
    }


    // Итоговая статистика
    this->log("РЕЗУЛЬТАТ:", logLevel::DEBUG);
    this->log("Всего проверено файлов: " + std::to_string(total), logLevel::DEBUG);
    this->log("Соответствуют требованиям: " + std::to_string(success), logLevel::DEBUG);
    this->log("Исправлено параметров: " + std::to_string(fixed), logLevel::DEBUG);
    this->log("Проблемных файлов: " + std::to_string(failed), logLevel::DEBUG);

    if (failed == 0) {
        if (fixed == 0) {
            this->log("Отклонений не обнаружено", logLevel::INFO);
            return true;
        } else {
            this->notify("Были обнаружены отклонения от эталона при применении политики " +
                               this->policyName + " ,однако они все были успешно исправлены", notifyLevel::WARN);
            this->log("Все обнаруженные отклонения исправлены", logLevel::INFO);
            return true;
        }
    } else {
        this->notify("Были обнаружены отклонения от эталона при применении политики " +
                           this->policyName + " ,и некоторые (" + std::to_string(failed) + ") исправлены не были", notifyLevel::ERROR);
        this->log("ВНИМАНИЕ: Не все отклонения удалось исправить (Проблемных файлов: " +  std::to_string(failed) + ")", logLevel::ERROR);
        return false;
    }
    return false;
}


