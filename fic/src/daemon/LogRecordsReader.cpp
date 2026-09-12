#include "daemon/LogRecordsReader.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <fic/ipc/FicIpcClient.h>

namespace fic::daemon {
namespace {

using json = nlohmann::json;
constexpr int CURSOR_VERSION = 2;
constexpr std::size_t MAX_STORED_CURSORS = 64U;

struct CursorPosition {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t offset = 0;
};

struct CursorState {
    int version = CURSOR_VERSION;
    std::string bootId;
    std::map<std::string, CursorPosition> positions;
};

struct LogFile {
    std::string relativePath;
    std::string category;
    std::filesystem::path absolutePath;
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t size = 0;
};

class ScopedFd {
public:
    explicit ScopedFd(int descriptor = -1) : descriptor_(descriptor) {}
    ~ScopedFd() {
        if (descriptor_ >= 0) ::close(descriptor_);
    }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    int get() const { return descriptor_; }
    int release() {
        const int descriptor = descriptor_;
        descriptor_ = -1;
        return descriptor;
    }

private:
    int descriptor_;
};

struct FileCloser {
    void operator()(FILE* stream) const {
        if (stream != nullptr) ::fclose(stream);
    }
};

std::uint64_t mix64(std::uint64_t value) {
    value ^= value >> 30U;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27U;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31U);
}

std::uint64_t cursorNonce(const void* instance) {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return mix64(static_cast<std::uint64_t>(now) ^
                 (static_cast<std::uint64_t>(::getpid()) << 32U) ^
                 static_cast<std::uint64_t>(
                     reinterpret_cast<std::uintptr_t>(instance)));
}

void appendHex(std::string& output, std::uint64_t value) {
    static constexpr char digits[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4) {
        output.push_back(digits[(value >> shift) & 0x0fU]);
    }
}

bool validCursorToken(const std::string& cursor) {
    if (cursor.size() != MAX_LOG_CURSOR_BYTES ||
        cursor[0] != '2' || cursor[1] != '.') {
        return false;
    }
    return std::all_of(cursor.begin() + 2, cursor.end(), [](unsigned char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

bool enumerateLogFiles(
    const std::filesystem::path& bootDirectory,
    std::vector<LogFile>& files,
    json& categories,
    std::string& error)
{
    try {
        std::vector<std::filesystem::path> categoryDirectories;
        for (const auto& entry : std::filesystem::directory_iterator(
                 bootDirectory)) {
            if (entry.is_directory()) categoryDirectories.push_back(entry.path());
        }
        std::sort(categoryDirectories.begin(), categoryDirectories.end());
        for (const auto& categoryDirectory : categoryDirectories) {
            const std::string category = categoryDirectory.filename().string();
            categories.push_back(category);
            std::vector<std::filesystem::path> paths;
            for (const auto& entry : std::filesystem::directory_iterator(
                     categoryDirectory)) {
                if (entry.path().extension() == ".txt") {
                    paths.push_back(entry.path());
                }
            }
            std::sort(paths.begin(), paths.end());
            for (const auto& path : paths) {
                files.push_back({
                    std::filesystem::relative(path, bootDirectory).generic_string(),
                    category,
                    path,
                    0,
                    0,
                    0
                });
            }
        }
    } catch (const std::filesystem::filesystem_error& exception) {
        error = "failed to enumerate logs: " + std::string(exception.what());
        return false;
    }
    return true;
}

bool snapshotLogFile(LogFile& file, std::string& error) {
    ScopedFd descriptor(::open(
        file.absolutePath.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (descriptor.get() < 0) {
        error = "failed to open log file " + file.relativePath + ": " +
            std::strerror(errno);
        return false;
    }
    struct stat status {};
    if (::fstat(descriptor.get(), &status) != 0) {
        error = "failed to stat log file " + file.relativePath + ": " +
            std::strerror(errno);
        return false;
    }
    if (!S_ISREG(status.st_mode)) {
        error = "log path is not a regular file: " + file.relativePath;
        return false;
    }
    file.device = static_cast<std::uint64_t>(status.st_dev);
    file.inode = static_cast<std::uint64_t>(status.st_ino);
    file.size = static_cast<std::uint64_t>(status.st_size);
    return true;
}

json reloadRequiredResponse(const std::string& bootId, const json& categories) {
    return {
        {"ok", true},
        {"message", "log cursor is stale; full reload required"},
        {"boot_id", bootId},
        {"categories", categories},
        {"records", json::array()},
        {"has_more", false},
        {"reload_required", true}
    };
}

} // namespace

struct LogRecordsReader::Impl {
    struct StoredCursor {
        CursorState state;
        std::list<std::string>::iterator age;
    };

    Impl() : nonce(cursorNonce(this)) {}

    bool load(const std::string& token, CursorState& state) {
        std::lock_guard<std::mutex> lock(mutex);
        const auto found = cursors.find(token);
        if (found == cursors.end()) return false;
        age.splice(age.end(), age, found->second.age);
        state = found->second.state;
        return true;
    }

    std::string store(CursorState state) {
        std::lock_guard<std::mutex> lock(mutex);
        std::string token;
        do {
            token = "2.";
            appendHex(token, nonce);
            appendHex(token, ++counter);
        } while (cursors.find(token) != cursors.end());

        age.push_back(token);
        cursors.emplace(token, StoredCursor{std::move(state), std::prev(age.end())});
        while (cursors.size() > MAX_STORED_CURSORS) {
            cursors.erase(age.front());
            age.pop_front();
        }
        return token;
    }

    std::mutex mutex;
    std::uint64_t nonce;
    std::uint64_t counter = 0;
    std::list<std::string> age;
    std::map<std::string, StoredCursor> cursors;
};

LogRecordsReader::LogRecordsReader() : impl_(std::make_unique<Impl>()) {}
LogRecordsReader::~LogRecordsReader() = default;

json LogRecordsReader::read(
    const std::filesystem::path& logDirectory,
    const std::string& bootId,
    const std::string& cursor,
    int limit)
{
    json categories = json::array();
    json records = json::array();
    CursorState previousState;
    bool cursorExpired = false;
    if (!cursor.empty()) {
        if (!validCursorToken(cursor)) {
            return fic::ipc::make_error_response("invalid log cursor");
        }
        if (!impl_->load(cursor, previousState)) {
            cursorExpired = true;
        } else if (previousState.version != CURSOR_VERSION ||
                   previousState.bootId != bootId) {
            return fic::ipc::make_error_response(
                "invalid or mismatched log cursor");
        }
    } else {
        previousState.bootId = bootId;
    }

    const std::filesystem::path bootDirectory = logDirectory / bootId;
    if (!std::filesystem::exists(bootDirectory) ||
        !std::filesystem::is_directory(bootDirectory)) {
        if (cursorExpired || !previousState.positions.empty()) {
            return reloadRequiredResponse(bootId, categories);
        }
        return {
            {"ok", true},
            {"message", "logs loaded"},
            {"boot_id", bootId},
            {"categories", categories},
            {"records", records},
            {"has_more", false},
            {"reload_required", false},
            {"next_cursor", impl_->store(CursorState{
                CURSOR_VERSION, bootId, {}})}
        };
    }

    std::vector<LogFile> files;
    std::string error;
    if (!enumerateLogFiles(bootDirectory, files, categories, error)) {
        return fic::ipc::make_error_response(error);
    }
    if (cursorExpired) {
        return reloadRequiredResponse(bootId, categories);
    }

    std::map<std::string, LogFile*> currentFiles;
    for (auto& file : files) {
        if (!snapshotLogFile(file, error)) {
            return fic::ipc::make_error_response(error);
        }
        currentFiles.emplace(file.relativePath, &file);
    }

    for (const auto& [path, position] : previousState.positions) {
        const auto current = currentFiles.find(path);
        if (current == currentFiles.end() ||
            current->second->device != position.device ||
            current->second->inode != position.inode ||
            current->second->size < position.offset) {
            return reloadRequiredResponse(bootId, categories);
        }
    }

    CursorState nextState;
    nextState.bootId = bootId;
    for (const auto& file : files) {
        const auto previous = previousState.positions.find(file.relativePath);
        nextState.positions[file.relativePath] = {
            file.device,
            file.inode,
            previous == previousState.positions.end()
                ? 0U
                : previous->second.offset
        };
    }

    std::size_t responseBytes = 0;
    bool hasMore = false;
    for (auto& file : files) {
        CursorPosition& position = nextState.positions.at(file.relativePath);
        ScopedFd descriptor(::open(
            file.absolutePath.c_str(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (descriptor.get() < 0) {
            return fic::ipc::make_error_response(
                "failed to open log file " + file.relativePath + ": " +
                std::strerror(errno));
        }
        struct stat status {};
        if (::fstat(descriptor.get(), &status) != 0) {
            return fic::ipc::make_error_response(
                "failed to stat log file " + file.relativePath + ": " +
                std::strerror(errno));
        }
        if (!S_ISREG(status.st_mode)) {
            return fic::ipc::make_error_response(
                "log path is not a regular file: " + file.relativePath);
        }
        const std::uint64_t device = static_cast<std::uint64_t>(status.st_dev);
        const std::uint64_t inode = static_cast<std::uint64_t>(status.st_ino);
        const std::uint64_t size = static_cast<std::uint64_t>(status.st_size);
        if (device != file.device || inode != file.inode ||
            size < position.offset) {
            return reloadRequiredResponse(bootId, categories);
        }
        if (::lseek(descriptor.get(), static_cast<off_t>(position.offset),
                    SEEK_SET) < 0) {
            return fic::ipc::make_error_response(
                "failed to seek log file: " + file.relativePath);
        }
        const int streamDescriptor = descriptor.release();
        FILE* raw = ::fdopen(streamDescriptor, "r");
        if (raw == nullptr) {
            ::close(streamDescriptor);
            return fic::ipc::make_error_response(
                "failed to read log file: " + file.relativePath);
        }
        std::unique_ptr<FILE, FileCloser> stream(raw);
        char* buffer = nullptr;
        std::size_t capacity = 0;
        std::uint64_t streamOffset = position.offset;
        while (true) {
            const ssize_t bytes = ::getline(&buffer, &capacity, stream.get());
            if (bytes < 0) break;
            streamOffset += static_cast<std::uint64_t>(bytes);
            if (bytes == 0 || buffer[bytes - 1] != '\n') {
                break;
            }
            std::string line(buffer, static_cast<std::size_t>(bytes - 1));
            if (line.empty()) {
                position.offset = streamOffset;
                continue;
            }
            const std::size_t originalBytes = line.size();
            const bool lineTruncated = line.size() > MAX_LOG_LINE_BYTES;
            if (lineTruncated) line.resize(MAX_LOG_LINE_BYTES);
            json item = {
                {"category", file.category},
                {"source_file", file.absolutePath.string()},
                {"line", line},
                {"byte_size", originalBytes},
                {"line_truncated", lineTruncated}
            };
            const std::size_t itemBytes = item.dump().size();
            if (records.size() >= static_cast<std::size_t>(limit) ||
                responseBytes + itemBytes > MAX_LOG_PAGE_BYTES) {
                hasMore = true;
                break;
            }
            responseBytes += itemBytes;
            records.push_back(std::move(item));
            position.offset = streamOffset;
        }
        const bool readFailed = ::ferror(stream.get()) != 0;
        std::free(buffer);
        if (readFailed) {
            return fic::ipc::make_error_response(
                "failed to read log file: " + file.relativePath);
        }
        if (hasMore) break;
    }

    return {
        {"ok", true},
        {"message", "logs loaded"},
        {"boot_id", bootId},
        {"categories", categories},
        {"records", std::move(records)},
        {"has_more", hasMore},
        {"reload_required", false},
        {"next_cursor", impl_->store(std::move(nextState))}
    };
}

} // namespace fic::daemon
