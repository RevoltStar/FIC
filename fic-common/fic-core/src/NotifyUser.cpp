#include <fic/core/NotifyUser.h>
#include <fic/core/FicRuntimePaths.h>

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

const notifyLevel NotifyUser::currNotifyLevel = notifyLevel::NoNotify;

namespace {
std::atomic<unsigned long> notifyCounter{0};

std::string sanitize_filename(std::string value)
{
    if (value.empty()) {
        return "fic";
    }

    for (char& ch : value) {
        const bool safe =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' || ch == '-' || ch == '.';

        if (!safe) {
            ch = '_';
        }
    }

    return value;
}

std::string escape_value(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size());

    for (char ch : value) {
        switch (ch) {
        case '\\':
            escaped += "\\\\";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            break;
        default:
            escaped += ch;
            break;
        }
    }

    return escaped;
}
} // namespace

bool NotifyUser::notify_user(const std::string& filename, const std::string& content, const notifyLevel& notifyLev)
{
    if (notifyLev == notifyLevel::NoNotify || content.empty()) {
        return true;
    }

    const std::string notifyUserString = NotifyUser::enumToString(notifyLev);
    const std::filesystem::path notifyDir = fic::core::FicRuntimePaths::get().notifyDir;

    try {
        std::filesystem::create_directories(notifyDir);
        chmod(notifyDir.c_str(), 02750);
    } catch (const std::exception& e) {
        std::cerr << "Failed to create notify directory " << notifyDir << ": " << e.what() << std::endl;
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    const unsigned long counter = ++notifyCounter;
    const std::string timestampString = std::to_string(timestamp);
    const std::string safeFilename = sanitize_filename(filename);

    std::stringstream baseName;
    baseName << safeFilename
             << "_" << timestampString
             << "_" << getpid()
             << "_" << counter;

    const std::string finalPath = (notifyDir / (baseName.str() + ".notify")).string();
    const std::string tempPath = (notifyDir / ("." + baseName.str() + ".tmp")).string();

    std::ofstream notify_file(tempPath, std::ios::out | std::ios::trunc);
    if (!notify_file.is_open()) {
        std::cerr << "Failed to create notify file: " << tempPath << std::endl;
        return false;
    }

    notify_file << "timestamp=" << timestampString << "\n"
                << "level=" << notifyUserString << "\n"
                << "source=" << safeFilename << "\n"
                << "message=" << escape_value(content) << "\n";

    notify_file.close();
    chmod(tempPath.c_str(), 0640);

    try {
        std::filesystem::rename(tempPath, finalPath);
    } catch (const std::exception& e) {
        std::filesystem::remove(tempPath);
        std::cerr << "Failed to publish notify file: " << e.what() << std::endl;
        return false;
    }

    chmod(finalPath.c_str(), 0640);
    return true;
}
