#include "daemon/LogRecordsReader.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

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
    const fs::path root = fs::temp_directory_path() /
        ("fic-log-cursor-test-" + std::to_string(::getpid()));
    const std::string bootId = "boot-test";
    const fs::path boot = root / bootId;
    const fs::path daemon = boot / "daemon" / "fic.txt";
    const fs::path audit = boot / "audit" / "audit.txt";

    appendLine(daemon, "daemon-old");
    json response = fic::daemon::readLogRecords(root, bootId, "", 500);
    require(response.value("ok", false) &&
                lines(response) == std::vector<std::string>{"daemon-old"},
            "initial daemon record was not read");
    std::string next = cursor(response);
    require(!next.empty() && next.find(bootId) == std::string::npos,
            "cursor is not opaque to the client");

    json malformed = fic::daemon::readLogRecords(root, bootId, "not+curs!", 500);
    require(!malformed.value("ok", true), "malformed cursor was accepted");
    fs::create_directories(root / "other-boot");
    json mismatched = fic::daemon::readLogRecords(
        root, "other-boot", next, 500);
    require(!mismatched.value("ok", true),
            "cursor from another boot was accepted");

    appendLine(audit, "audit-new");
    response = fic::daemon::readLogRecords(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{"audit-new"},
            "new earlier audit file repeated an old daemon record");
    next = cursor(response);

    appendLine(daemon, "daemon-new");
    response = fic::daemon::readLogRecords(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{"daemon-new"},
            "daemon append did not return exactly the new record");
    next = cursor(response);

    const fs::path daemonSecond = boot / "daemon" / "second.txt";
    const fs::path auditSecond = boot / "audit" / "second.txt";
    appendLine(daemonSecond, "daemon-second-old");
    appendLine(auditSecond, "audit-second-old");
    response = fic::daemon::readLogRecords(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{
                "audit-second-old", "daemon-second-old"},
            "new log files were not read from their own beginnings");
    next = cursor(response);

    appendLine(auditSecond, "audit-second-new");
    appendLine(daemonSecond, "daemon-second-new");
    response = fic::daemon::readLogRecords(root, bootId, next, 500);
    require(lines(response) == std::vector<std::string>{
                "audit-second-new", "daemon-second-new"},
            "multiple files did not preserve independent offsets");

    const fs::path pagedRoot = root / "paged";
    const std::string pagedBootId = "paged-boot";
    const fs::path paged = pagedRoot / pagedBootId / "daemon" / "fic.txt";
    appendLine(paged, "page-one");
    appendLine(paged, "page-two");
    json firstPage = fic::daemon::readLogRecords(
        pagedRoot, pagedBootId, "", 1);
    require(firstPage.value("has_more", false) &&
                lines(firstPage) == std::vector<std::string>{"page-one"},
            "record limit pagination changed");
    json secondPage = fic::daemon::readLogRecords(
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
    json boundedPage = fic::daemon::readLogRecords(
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
    json truncated = fic::daemon::readLogRecords(
        pagedRoot, pagedBootId, cursor(secondPage), 500);
    require(truncated.value("reload_required", false) &&
                truncated.at("records").empty(),
            "truncated file did not invalidate its cursor");

    const fs::path inodeRoot = root / "inode";
    const std::string inodeBootId = "inode-boot";
    const fs::path inodeFile =
        inodeRoot / inodeBootId / "daemon" / "fic.txt";
    appendLine(inodeFile, "before-replacement");
    json beforeReplacement = fic::daemon::readLogRecords(
        inodeRoot, inodeBootId, "", 500);
    fs::rename(inodeFile, inodeFile.string() + ".old");
    appendLine(inodeFile, "after-replacement");
    json replaced = fic::daemon::readLogRecords(
        inodeRoot, inodeBootId, cursor(beforeReplacement), 500);
    require(replaced.value("reload_required", false) &&
                replaced.at("records").empty(),
            "inode replacement did not invalidate its cursor");

    fs::remove_all(root);
    return 0;
}
