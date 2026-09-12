#include "daemon/LogRecordsReader.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <fic/ipc/FicIpcClient.h>

namespace fic::daemon {
namespace {

using json = nlohmann::json;
constexpr int CURSOR_VERSION = 1;
constexpr std::size_t MAX_CURSOR_BYTES = 64U * 1024U;

struct CursorPosition {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t offset = 0;
};

struct OpenLogFile {
    std::string relativePath;
    std::string category;
    std::filesystem::path absolutePath;
    CursorPosition identity;
    int descriptor = -1;

    OpenLogFile() = default;
    OpenLogFile(const OpenLogFile&) = delete;
    OpenLogFile& operator=(const OpenLogFile&) = delete;
    OpenLogFile(OpenLogFile&& other) noexcept
        : relativePath(std::move(other.relativePath)),
          category(std::move(other.category)),
          absolutePath(std::move(other.absolutePath)),
          identity(other.identity), descriptor(other.descriptor) {
        other.descriptor = -1;
    }
    OpenLogFile& operator=(OpenLogFile&& other) noexcept {
        if (this != &other) {
            if (descriptor >= 0) ::close(descriptor);
            relativePath = std::move(other.relativePath);
            category = std::move(other.category);
            absolutePath = std::move(other.absolutePath);
            identity = other.identity;
            descriptor = other.descriptor;
            other.descriptor = -1;
        }
        return *this;
    }
    ~OpenLogFile() {
        if (descriptor >= 0) ::close(descriptor);
    }
};

struct FileCloser {
    void operator()(FILE* stream) const {
        if (stream != nullptr) ::fclose(stream);
    }
};

std::string base64UrlEncode(const std::string& input) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((input.size() * 4U + 2U) / 3U);
    std::uint32_t accumulator = 0;
    int bits = 0;
    for (const unsigned char byte : input) {
        accumulator = (accumulator << 8U) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            output.push_back(alphabet[(accumulator >> bits) & 0x3fU]);
        }
    }
    if (bits > 0) {
        output.push_back(alphabet[(accumulator << (6 - bits)) & 0x3fU]);
    }
    return output;
}

bool base64UrlDecode(const std::string& input, std::string& output) {
    if (input.size() > MAX_CURSOR_BYTES || input.size() % 4U == 1U) {
        return false;
    }
    auto value = [](unsigned char ch) -> int {
        if (ch >= 'A' && ch <= 'Z') return ch - 'A';
        if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
        if (ch >= '0' && ch <= '9') return ch - '0' + 52;
        if (ch == '-') return 62;
        if (ch == '_') return 63;
        return -1;
    };
    output.clear();
    output.reserve(input.size() * 3U / 4U);
    std::uint32_t accumulator = 0;
    int bits = 0;
    for (const unsigned char ch : input) {
        const int decoded = value(ch);
        if (decoded < 0) return false;
        accumulator = (accumulator << 6U) | static_cast<unsigned>(decoded);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<char>((accumulator >> bits) & 0xffU));
        }
    }
    return true;
}

bool safeRelativeLogPath(const std::string& text) {
    const std::filesystem::path path(text);
    if (text.empty() || path.is_absolute() || path.extension() != ".txt" ||
        path.lexically_normal().generic_string() != text) {
        return false;
    }
    for (const auto& component : path) {
        if (component == ".." || component == ".") return false;
    }
    return std::distance(path.begin(), path.end()) == 2;
}

bool decodeCursor(
    const std::string& encoded,
    const std::string& bootId,
    std::map<std::string, CursorPosition>& positions,
    std::string& error)
{
    positions.clear();
    if (encoded.empty()) return true;
    std::string decoded;
    if (!base64UrlDecode(encoded, decoded)) {
        error = "invalid log cursor encoding";
        return false;
    }
    try {
        const json value = json::parse(decoded);
        if (!value.is_object() || value.value("version", 0) != CURSOR_VERSION ||
            value.value("boot_id", "") != bootId ||
            !value.contains("files") || !value["files"].is_array()) {
            error = "invalid or mismatched log cursor";
            return false;
        }
        for (const auto& file : value["files"]) {
            if (!file.is_object() || !file.contains("path") ||
                !file["path"].is_string() || !file.contains("st_dev") ||
                !file["st_dev"].is_number_unsigned() ||
                !file.contains("st_ino") ||
                !file["st_ino"].is_number_unsigned() ||
                !file.contains("offset") ||
                !file["offset"].is_number_unsigned()) {
                error = "invalid log cursor file position";
                return false;
            }
            const std::string path = file["path"].get<std::string>();
            if (!safeRelativeLogPath(path) ||
                !positions.emplace(path, CursorPosition{
                    file["st_dev"].get<std::uint64_t>(),
                    file["st_ino"].get<std::uint64_t>(),
                    file["offset"].get<std::uint64_t>()}).second) {
                error = "invalid log cursor file path";
                return false;
            }
        }
    } catch (const std::exception&) {
        error = "invalid log cursor payload";
        return false;
    }
    return true;
}

std::string encodeCursor(
    const std::string& bootId,
    const std::map<std::string, CursorPosition>& positions)
{
    json files = json::array();
    for (const auto& [path, position] : positions) {
        files.push_back({
            {"path", path},
            {"st_dev", position.device},
            {"st_ino", position.inode},
            {"offset", position.offset}
        });
    }
    return base64UrlEncode(json{
        {"version", CURSOR_VERSION},
        {"boot_id", bootId},
        {"files", std::move(files)}
    }.dump());
}

bool openLogFiles(
    const std::filesystem::path& bootDirectory,
    std::vector<OpenLogFile>& files,
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
            const std::string category =
                categoryDirectory.filename().string();
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
                const int descriptor = ::open(
                    path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
                if (descriptor < 0) continue;
                struct stat status {};
                if (::fstat(descriptor, &status) != 0 ||
                    !S_ISREG(status.st_mode)) {
                    ::close(descriptor);
                    continue;
                }
                OpenLogFile file;
                file.relativePath = std::filesystem::relative(
                    path, bootDirectory).generic_string();
                file.category = category;
                file.absolutePath = path;
                file.identity = {
                    static_cast<std::uint64_t>(status.st_dev),
                    static_cast<std::uint64_t>(status.st_ino),
                    static_cast<std::uint64_t>(status.st_size)};
                file.descriptor = descriptor;
                files.push_back(std::move(file));
            }
        }
    } catch (const std::filesystem::filesystem_error& exception) {
        error = "failed to enumerate logs: " + std::string(exception.what());
        return false;
    }
    return true;
}

json reloadRequiredResponse(
    const std::string& bootId,
    const json& categories)
{
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

json readLogRecords(
    const std::filesystem::path& logDirectory,
    const std::string& bootId,
    const std::string& cursor,
    int limit)
{
    json categories = json::array();
    json records = json::array();
    std::map<std::string, CursorPosition> previous;
    std::string error;
    if (!decodeCursor(cursor, bootId, previous, error)) {
        return fic::ipc::make_error_response(error);
    }
    const std::filesystem::path bootDirectory = logDirectory / bootId;
    if (!std::filesystem::exists(bootDirectory) ||
        !std::filesystem::is_directory(bootDirectory)) {
        if (!previous.empty()) {
            return reloadRequiredResponse(bootId, categories);
        }
        return {{"ok", true}, {"message", "logs loaded"},
                {"boot_id", bootId}, {"categories", categories},
                {"records", records}, {"has_more", false},
                {"reload_required", false},
                {"next_cursor", encodeCursor(bootId, {})}};
    }

    std::vector<OpenLogFile> files;
    if (!openLogFiles(bootDirectory, files, categories, error)) {
        return fic::ipc::make_error_response(error);
    }
    std::map<std::string, OpenLogFile*> currentFiles;
    for (auto& file : files) currentFiles[file.relativePath] = &file;

    for (const auto& [path, position] : previous) {
        const auto current = currentFiles.find(path);
        if (current == currentFiles.end() ||
            current->second->identity.device != position.device ||
            current->second->identity.inode != position.inode ||
            current->second->identity.offset < position.offset) {
            return reloadRequiredResponse(bootId, categories);
        }
    }

    std::map<std::string, CursorPosition> next;
    for (const auto& file : files) {
        const auto previousPosition = previous.find(file.relativePath);
        next[file.relativePath] = {
            file.identity.device,
            file.identity.inode,
            previousPosition == previous.end() ? 0U
                                               : previousPosition->second.offset};
    }

    std::size_t responseBytes = 0;
    bool hasMore = false;
    for (auto& file : files) {
        CursorPosition& position = next.at(file.relativePath);
        if (::lseek(file.descriptor, static_cast<off_t>(position.offset),
                    SEEK_SET) < 0) {
            return fic::ipc::make_error_response(
                "failed to seek log file: " + file.relativePath);
        }
        const int duplicate = ::dup(file.descriptor);
        if (duplicate < 0) {
            return fic::ipc::make_error_response(
                "failed to read log file: " + file.relativePath);
        }
        FILE* raw = ::fdopen(duplicate, "r");
        if (raw == nullptr) {
            ::close(duplicate);
            return fic::ipc::make_error_response(
                "failed to read log file: " + file.relativePath);
        }
        std::unique_ptr<FILE, FileCloser> stream(raw);
        char* buffer = nullptr;
        std::size_t capacity = 0;
        while (true) {
            const ssize_t bytes = ::getline(&buffer, &capacity, stream.get());
            if (bytes < 0) break;
            std::string line(buffer, static_cast<std::size_t>(bytes));
            if (!line.empty() && line.back() == '\n') line.pop_back();
            const off_t lineEnd = ::ftello(stream.get());
            const std::uint64_t nextOffset = lineEnd >= 0
                ? static_cast<std::uint64_t>(lineEnd)
                : position.offset + static_cast<std::uint64_t>(bytes);
            if (line.empty()) {
                position.offset = nextOffset;
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
            position.offset = nextOffset;
        }
        std::free(buffer);
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
        {"next_cursor", encodeCursor(bootId, next)}
    };
}

} // namespace fic::daemon
