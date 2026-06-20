#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <functional>
#include <unistd.h>
#include <mutex>
#include <fic/core/SystemBootInfo.h>

enum class logLevel {
    NoLog = 0, // Не логгируем
    TRACE = 1, // Трассировка. Значения переменных. Вход/выходы из цикла.
    DEBUG = 2, // Отладочные сообщения. Вход в функции, выход из функций.
    INFO  = 3,
    WARN  = 4, // Предупреждения. В данный момент не влияет на корректную работу программы, но может стать проблемой в будущем. Например, не соответствие параметров эталону.
    ERROR = 5, // Ошибки
    FATAL = 6  // Фатальные ошибке препятсвующие работе программы.
};

class Logger {
private:
    static std::string get_boot_id();
    static std::string get_file_path(const std::string& type);
    static void ensure_directory_exists(const std::string& path);
    static logLevel get_configured_log_level();

public:
    static std::string get_current_time();
    static std::string level_to_string(logLevel level);
    static logLevel string_to_level(const std::string& levelStr);

    /*using GuiCallback = std::function<void(const std::string&, logLevel, const std::string&)>;*/

    /*static void setGuiCallback(GuiCallback callback);*/
    static bool log(const std::string& message, logLevel logLev, const std::string& type = "unclassified");
};

#endif // LOGGER_H
