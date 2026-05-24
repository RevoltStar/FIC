#include "Logger.h"
#include "ModuleConfigFileHandler.h"

#include <algorithm>
#include <cctype>

namespace {
std::string normalize_level_string(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }), value.end());

    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });

    return value;
}
}

std::string Logger::get_boot_id() {
    return SystemBootInfo::get_boot_id();
}

std::string Logger::get_file_path(const std::string& type) {
    std::string boot_id = get_boot_id();
    pid_t process_id = getpid();
    std::string base_dir = "/opt/fic/log/" + boot_id + "/" + type;
    return base_dir + "/" + type + "_" + std::to_string(process_id) + ".txt";
}

void Logger::ensure_directory_exists(const std::string& path) {
    std::filesystem::create_directories(path);
}

std::string Logger::get_current_time() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::stringstream ss;

    std::tm tm;
    localtime_r(&time, &tm);

    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
    ss << buffer;
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    std::strftime(buffer, sizeof(buffer), "%z", &tm);
    ss << " " << buffer;

    return ss.str();
}

std::string Logger::level_to_string(logLevel level) {
    switch(level) {
        case logLevel::TRACE: return "TRACE";
        case logLevel::DEBUG: return "DEBUG";
        case logLevel::INFO:  return "INFO";
        case logLevel::WARN:  return "WARN";
        case logLevel::ERROR: return "ERROR";
        case logLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

logLevel Logger::string_to_level(const std::string& levelStr) {
    const std::string normalized = normalize_level_string(levelStr);

    if (normalized == "NOLOG") {
        return logLevel::NoLog;
    }
    if (normalized == "TRACE") {
        return logLevel::TRACE;
    }
    if (normalized == "DEBUG") {
        return logLevel::DEBUG;
    }
    if (normalized == "INFO") {
        return logLevel::INFO;
    }
    if (normalized == "WARN") {
        return logLevel::WARN;
    }
    if (normalized == "ERROR") {
        return logLevel::ERROR;
    }
    if (normalized == "FATAL") {
        return logLevel::FATAL;
    }

    return logLevel::ERROR;
}

logLevel Logger::get_configured_log_level() {
    ModuleConfigFileHandler globalConfig("GLOBAL");
    if (!globalConfig.loadConfig()) {
        return logLevel::ERROR;
    }

    if (!globalConfig.isParameterExists("log_level")) {
        return logLevel::ERROR;
    }

    if (globalConfig.getIsEnable("log_level") != "ENABLE") {
        return logLevel::ERROR;
    }

    const std::string configuredLevel = globalConfig.getValue("log_level");
    if (configuredLevel.empty()) {
        return logLevel::ERROR;
    }

    return string_to_level(configuredLevel);
}

/*
void Logger::setGuiCallback(GuiCallback callback) {
    static GuiCallback storedCallback = nullptr;
    storedCallback = callback;

    static GuiCallback* guiCallbackPtr = &storedCallback;
    (void)guiCallbackPtr;
}
*/
bool Logger::log(const std::string& message, logLevel logLev, const std::string& type) {
    /*static GuiCallback guiCallback = nullptr;*/

    /*
    if (guiCallback) {
        try {
            guiCallback(message, logLev, type);
        } catch (const std::exception& e) {
            std::cerr << "GUI callback error: " << e.what() << std::endl;
        }
    }
    */
    if (logLev == logLevel::NoLog) {
        return true;
    }

    if (message.empty()) {
        return true;
    }

    const logLevel configuredLevel = get_configured_log_level();
    if (configuredLevel == logLevel::NoLog) {
        return true;
    }

    if (logLev < configuredLevel) {
        return true;
    }

    static std::mutex log_mutex;
    std::lock_guard<std::mutex> lock(log_mutex);

    try {
        std::string file_path = get_file_path(type);
        std::string dir_path = std::filesystem::path(file_path).parent_path();
        ensure_directory_exists(dir_path);

        std::ofstream log_file(file_path, std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "Failed to open log file: " << file_path << std::endl;
            return false;
        }

        std::stringstream log_entry;
        log_entry << "[" << get_current_time() << "] "
                  << "[" << level_to_string(logLev) << "] "
                  << message;

        if (true) {
            std::cout << log_entry.str() << std::endl;
        }

        log_file << log_entry.str() << std::endl;
        log_file.close();

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Logging error: " << e.what() << std::endl;
        return false;
    }
}
