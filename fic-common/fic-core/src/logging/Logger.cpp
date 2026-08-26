#include <fic/core/logging/Logger.h>
#include <fic/core/config/PolicyConfig.h>
#include <fic/core/runtime/FicRuntimePaths.h>

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

class Logger::ScopedCaptureState {
public:
    ScopedCaptureState(std::size_t recordLimit, std::size_t byteLimit)
        : maxRecords(recordLimit), maxBytes(byteLimit) {}

    void append(const LogRecord& record) {
        const std::size_t recordBytes = record.timestamp.size() + record.type.size() +
            record.message.size() + 32;
        if (records.size() >= maxRecords || recordBytes > maxBytes - capturedBytes) {
            truncated = true;
            return;
        }

        records.push_back(record);
        capturedBytes += recordBytes;
    }

    std::vector<LogRecord> records;
    ScopedCaptureState* previous = nullptr;
    std::size_t maxRecords;
    std::size_t maxBytes;
    std::size_t capturedBytes = 0;
    bool truncated = false;
    bool active = false;
};

thread_local Logger::ScopedCaptureState* Logger::activeCapture = nullptr;

Logger::ScopedCapture::ScopedCapture(std::size_t maxRecords, std::size_t maxBytes)
    : state(std::make_unique<ScopedCaptureState>(maxRecords, maxBytes)) {
    state->previous = Logger::activeCapture;
    state->active = true;
    Logger::activeCapture = state.get();
}

Logger::ScopedCapture::~ScopedCapture() {
    if (state != nullptr && state->active) {
        Logger::activeCapture = state->previous;
        state->active = false;
    }
}

LogCaptureResult Logger::ScopedCapture::finish() {
    if (state == nullptr) {
        return {};
    }

    if (state->active) {
        Logger::activeCapture = state->previous;
        state->active = false;
    }

    return {std::move(state->records), state->truncated};
}

std::string Logger::get_boot_id() {
    return SystemBootInfo::get_boot_id();
}

std::string Logger::get_file_path(const std::string& type) {
    std::string boot_id = get_boot_id();
    pid_t process_id = getpid();
    const std::filesystem::path baseDir =
        fic::core::FicRuntimePaths::get().logDir / boot_id / type;
    return (baseDir / (type + "_" + std::to_string(process_id) + ".txt")).string();
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
    const std::optional<std::string> configuredLevel =
        PolicyConfig::getEnabledValue("AUDIT", "log_level");
    if (!configuredLevel.has_value() || configuredLevel.value().empty()) {
        return logLevel::ERROR;
    }

    return string_to_level(configuredLevel.value());
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

    const LogRecord record{get_current_time(), logLev, type, message};
    if (activeCapture != nullptr) {
        try {
            activeCapture->append(record);
        } catch (...) {
            // Diagnostic capture must not prevent the primary log write.
        }
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
        log_entry << "[" << record.timestamp << "] "
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
