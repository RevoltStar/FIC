#ifndef NOTIFY_USER_H
#define NOTIFY_USER_H
#include <iostream>
#include <unordered_map>
#include <errno.h>
#include <string.h>
#include <string>

//Уровень лога
enum class notifyLevel{
    NoNotify = 0, //Не уведомлять пользователя
    INFO  = 1, //Информационное сообщение.
    WARN  = 2, //Предупреждение. Ситуации, не мешающие в данный момент корректному выполнению программы,
               //но которые могут проявиться в будущем
               //В частности, отклонения от эталона, которое было исправлено
    ERROR = 3, //Ошибка, которая мешает корректной работе программы.
               //Ошибки чтения/записи. -> ERROR всегда приводит к блокировке
               //В частности, когда отклонения от эталонов не удалось исправить
    FATAL = 4  //Критическая ошибка из-за которой приложение не может продолжить работу
               //Например, нехватка ОЗУ, повреждение ФС, повреждение файлов конфигурации
               //Ошибки в коде -> FATAL всегда приводит к блокировке
};

const std::unordered_map<notifyLevel, std::string> notifyUserStrings = {
    {notifyLevel::INFO, "INFO"},
    {notifyLevel::WARN, "WARNING"},
    {notifyLevel::ERROR, "ERROR"},
    {notifyLevel::FATAL, "FATAL"},
    {notifyLevel::NoNotify, "NoNotify"}
};

//Создание уведомления для пользователя
class NotifyUser{
    static const notifyLevel currNotifyLevel;
    static std::string enumToString(notifyLevel level) {
        return notifyUserStrings.at(level);
    }
public:
    static bool notify_user(const std::string& filename, const std::string& content, const notifyLevel& notifyLev);
};

#endif // NOTIFY_USER_H
