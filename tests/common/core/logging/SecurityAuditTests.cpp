#include <fic/core/logging/SecurityAudit.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

#include <nlohmann/json.hpp>

namespace {

using json = nlohmann::json;
namespace audit = fic::core::security_audit;

std::filesystem::path temporaryPath() {
    return std::filesystem::temp_directory_path() /
        ("fic-security-audit-" + std::to_string(::getpid()) + ".jsonl");
}

void testJsonLineAndStringLimit() {
    const std::filesystem::path path = temporaryPath();
    std::filesystem::remove(path);

    std::string malicious =
        "x result=ok peer=uid:0 gid:0 pid:1 command=device_delete "
        "message=\"fake\"\r\n\tquote=\" slash=\\ ";
    malicious.append("\0\x1b", 2);
    malicious += u8"Привет 日本語 😀";
    audit::PeerCredentials peer;
    peer.available = true;
    peer.uid = 1200;
    peer.gid = 1300;
    peer.pid = 1400;
    const json event = audit::makeIpcEvent(
        "test-component", peer, "real-command", {{"value", malicious}},
        false, "real failure", "2026-09-08T00:00:00Z");

    std::string error;
    assert(audit::appendJsonLine(path, event, error));
    assert(error.empty());

    std::ifstream stream(path, std::ios::binary);
    std::string line;
    assert(std::getline(stream, line));
    assert(!std::getline(stream, error));
    assert(std::count(line.begin(), line.end(), '\n') == 0);
    assert(std::count(line.begin(), line.end(), '\r') == 0);
    const json parsed = json::parse(line);
    assert(parsed["request"]["value"] == malicious);
    assert(parsed["peer"]["uid"] == 1200);
    assert(parsed["result"]["ok"] == false);
    assert(parsed["command"] == "real-command");

    const std::string longAscii(audit::MAX_STRING_BYTES + 100U, 'A');
    const json truncated = audit::makeEvent(
        "test-component", {{"event", "limit"}, {"value", longAscii}},
        "2026-09-08T00:00:00Z");
    assert(truncated["value"].get<std::string>().size() == audit::MAX_STRING_BYTES);
    assert(truncated["value"].get<std::string>().find("...[truncated]") !=
           std::string::npos);
    assert(truncated["truncated_fields"] == json::array({"/value"}));
    assert(audit::serializeJsonLine(truncated).size() <= audit::MAX_RECORD_BYTES);

    std::string longUtf8;
    while (longUtf8.size() <= audit::MAX_STRING_BYTES + 10U) {
        longUtf8 += u8"日";
    }
    const json utf8Event = audit::makeEvent(
        "test-component", {{"event", "utf8_limit"}, {"value", longUtf8}},
        "2026-09-08T00:00:00Z");
    assert(json::parse(audit::serializeJsonLine(utf8Event)) == utf8Event);

    json oversizedValues = json::array();
    for (int index = 0; index < 100; ++index) {
        oversizedValues.push_back(std::string(audit::MAX_STRING_BYTES, '\x01'));
    }
    const json fallback = audit::makeEvent(
        "test-component", {{"event", "oversized"}, {"values", oversizedValues}},
        "2026-09-08T00:00:00Z");
    assert(fallback["record_truncated"] == true);
    assert(fallback["event"] == "oversized");
    assert(audit::serializeJsonLine(fallback).size() <= audit::MAX_RECORD_BYTES);

    std::filesystem::remove(path);
}

} // namespace

int main() {
    testJsonLineAndStringLimit();
    return 0;
}
