#include "daemon/LogRecordsReader.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

#include <fic/ipc/FicIpcClient.h>

namespace {
using json = nlohmann::json;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void appendLine(const std::filesystem::path& path, const std::string& line) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::app);
    stream << line << '\n';
}

void appendText(const std::filesystem::path& path, const std::string& text) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::app);
    stream << text;
}

class ScopedFileLimit {
public:
    explicit ScopedFileLimit(rlim_t softLimit) {
        require(::getrlimit(RLIMIT_NOFILE, &original_) == 0,
                "failed to read RLIMIT_NOFILE");
        struct rlimit lowered = original_;
        lowered.rlim_cur = std::min(original_.rlim_cur, softLimit);
        require(::setrlimit(RLIMIT_NOFILE, &lowered) == 0,
                "failed to lower RLIMIT_NOFILE");
    }

    ~ScopedFileLimit() {
        ::setrlimit(RLIMIT_NOFILE, &original_);
    }

private:
    struct rlimit original_ {};
};

std::vector<std::string> lines(const json& response) {
    std::vector<std::string> result;
    for (const auto& record : response.at("records")) {
        result.push_back(record.at("line").get<std::string>());
    }
    return result;
}

std::string cursor(const json& response) {
    return response.at("next_cursor").get<std::string>();
}
} // namespace

int main() {
    namespace fs = std::filesystem;
    fic::daemon::LogRecordsReader reader;
    const fs::path root = fs::temp_directory_path() /
        ("fic-log-cursor-test-" + std::to_string(::getpid()));
    const std::string bootId = "boot-test";
    const fs::path boot = root / bootId;
    const fs::path daemon = boot / "daemon" / "fic.txt";
    const fs::path audit = boot / "audit" / "audit.txt";

    appendLine(daemon, "daemon-old");
    json response = reader.read(root, bootId, "", 500);
    require(response.value("ok", false) &&
                lines(response) == std::vector<std::string>{"daemon-old"},
            "initial daemon record was not read");
    std::string next = cursor(response);
    require(!next.empty() && next.find(bootId) == std::string::npos,
            "cursor is not opaque to the client");

    json malformed = reader.read(root, bootId, "not+curs!", 500);
    require(!malformed.value("ok", true), "malformed cursor was accepted");
    fs::create_directories(root / "other-boot");
    json mismatched = reader.read(
        root, "other-boot", next, 500);
    require(!mismatched.value("ok", true),
            "cursor from another boot was accepted");
    fic::daemon::LogRecordsReader restartedReader;
    json expired = restartedReader.read(root, bootId, next, 500);
    require(expired.value("reload_required", false),
            "unknown well-formed cursor did not request a full reload");

    appendLine(audit, "audit-new");
    response = reader.read(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{"audit-new"},
            "new earlier audit file repeated an old daemon record");
    next = cursor(response);

    appendLine(daemon, "daemon-new");
    response = reader.read(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{"daemon-new"},
            "daemon append did not return exactly the new record");
    next = cursor(response);

    const fs::path daemonSecond = boot / "daemon" / "second.txt";
    const fs::path auditSecond = boot / "audit" / "second.txt";
    appendLine(daemonSecond, "daemon-second-old");
    appendLine(auditSecond, "audit-second-old");
    response = reader.read(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{
                "audit-second-old", "daemon-second-old"},
            "new log files were not read from their own beginnings");
    next = cursor(response);

    appendLine(auditSecond, "audit-second-new");
    appendLine(daemonSecond, "daemon-second-new");
    response = reader.read(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{
                "audit-second-new", "daemon-second-new"},
            "multiple files did not preserve independent offsets");

    const fs::path pagedRoot = root / "paged";
    const std::string pagedBootId = "paged-boot";
    const fs::path paged = pagedRoot / pagedBootId / "daemon" / "fic.txt";
    appendLine(paged, "page-one");
    appendLine(paged, "page-two");
    json firstPage = reader.read(
        pagedRoot, pagedBootId, "", 1);
    require(firstPage.value("has_more", false) &&
                lines(firstPage) == std::vector<std::string>{"page-one"},
            "record limit pagination changed");
    json secondPage = reader.read(
        pagedRoot, pagedBootId, cursor(firstPage), 1);
    require(!secondPage.value("has_more", true) &&
                lines(secondPage) == std::vector<std::string>{"page-two"},
            "cursor pagination repeated or skipped a record");

    const fs::path boundedRoot = root / "bounded";
    const std::string boundedBootId = "bounded-boot";
    const fs::path bounded =
        boundedRoot / boundedBootId / "daemon" / "fic.txt";
    const std::string oversizedLine(
        fic::daemon::MAX_LOG_LINE_BYTES + 100U, 'x');
    for (int index = 0; index < 60; ++index) {
        appendLine(bounded, oversizedLine);
    }
    json boundedPage = reader.read(
        boundedRoot, boundedBootId, "", 500);
    require(boundedPage.value("has_more", false) &&
                boundedPage.at("records").size() < 60,
            "page byte limit was not preserved");
    const auto& boundedRecord = boundedPage.at("records").front();
    require(boundedRecord.value("line_truncated", false) &&
                boundedRecord.at("line").get<std::string>().size() ==
                    fic::daemon::MAX_LOG_LINE_BYTES &&
                boundedRecord.at("byte_size").get<std::size_t>() ==
                    oversizedLine.size(),
            "line byte limit metadata changed");

    std::ofstream(paged, std::ios::trunc) << "short\n";
    json truncated = reader.read(
        pagedRoot, pagedBootId, cursor(secondPage), 500);
    require(truncated.value("reload_required", false) &&
                truncated.at("records").empty(),
            "truncated file did not invalidate its cursor");

    const fs::path inodeRoot = root / "inode";
    const std::string inodeBootId = "inode-boot";
    const fs::path inodeFile =
        inodeRoot / inodeBootId / "daemon" / "fic.txt";
    appendLine(inodeFile, "before-replacement");
    json beforeReplacement = reader.read(
        inodeRoot, inodeBootId, "", 500);
    fs::rename(inodeFile, inodeFile.string() + ".old");
    appendLine(inodeFile, "after-replacement");
    json replaced = reader.read(
        inodeRoot, inodeBootId, cursor(beforeReplacement), 500);
    require(replaced.value("reload_required", false) &&
                replaced.at("records").empty(),
            "inode replacement did not invalidate its cursor");

    const fs::path partialRoot = root / "partial";
    const std::string partialBootId = "partial-boot";
    const fs::path partialFile =
        partialRoot / partialBootId / "daemon" / "fic.txt";
    appendText(partialFile, "partial");
    json partial = reader.read(partialRoot, partialBootId, "", 500);
    require(partial.value("ok", false) && partial.at("records").empty(),
            "unfinished final log line was emitted");
    const std::string partialCursor = cursor(partial);
    appendText(partialFile, "-complete\nnext\n");
    json completed = reader.read(
        partialRoot, partialBootId, partialCursor, 500);
    require(lines(completed) == std::vector<std::string>{
                "partial-complete", "next"},
            "unfinished line offset advanced before newline completion");
    json afterCompleted = reader.read(
        partialRoot, partialBootId, cursor(completed), 500);
    require(afterCompleted.at("records").empty(),
            "completed lines were returned more than once");

    const fs::path manyRoot = root / "many";
    const std::string manyBootId = "many-boot";
    const fs::path manyDirectory = manyRoot / manyBootId / "daemon";
    constexpr int manyFileCount = 1100;
    for (int index = 0; index < manyFileCount; ++index) {
        std::ostringstream name;
        name << "file-" << std::setw(4) << std::setfill('0') << index
             << ".txt";
        appendLine(manyDirectory / name.str(), "record-" + std::to_string(index));
    }
    std::set<std::string> manyLines;
    std::string manyCursor;
    bool manyHasMore = false;
    int pageCount = 0;
    {
        ScopedFileLimit fileLimit(32);
        do {
            json page = reader.read(
                manyRoot, manyBootId, manyCursor,
                fic::daemon::MAX_LOG_RECORDS_PER_PAGE);
            require(page.value("ok", false),
                    "many-file page could not be read under low RLIMIT_NOFILE");
            manyCursor = cursor(page);
            require(manyCursor.size() <= fic::daemon::MAX_LOG_CURSOR_BYTES,
                    "opaque cursor grew with the number of log files");
            const json request = {
                {"api_version", fic::ipc::API_VERSION},
                {"command", "log_records"},
                {"boot_id", manyBootId},
                {"cursor", manyCursor},
                {"limit", fic::daemon::MAX_LOG_RECORDS_PER_PAGE}
            };
            require(request.dump().size() <= fic::ipc::MAX_REQUEST_BYTES,
                    "cursor made the next IPC request too large");
            for (const auto& line : lines(page)) manyLines.insert(line);
            manyHasMore = page.value("has_more", false);
            require(++pageCount <= 4, "many-file pagination did not terminate");
        } while (manyHasMore);
    }
    require(manyLines.size() == manyFileCount,
            "log files were skipped under low RLIMIT_NOFILE");

    const fs::path openErrorRoot = root / "open-error";
    const std::string openErrorBootId = "open-error-boot";
    const fs::path openErrorDirectory =
        openErrorRoot / openErrorBootId / "daemon";
    appendLine(openErrorDirectory / "target.log", "not-enumerated");
    fs::create_symlink("target.log", openErrorDirectory / "unreadable.txt");
    json openError = reader.read(openErrorRoot, openErrorBootId, "", 500);
    require(!openError.value("ok", true) &&
                openError.value("message", "").find("failed to open log file") !=
                    std::string::npos,
            "log open error was silently ignored");

    fs::remove_all(root);
    return 0;
}
