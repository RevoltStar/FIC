#include "daemon/AdminAudit.h"

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

int main() {
    using nlohmann::json;
    namespace audit = fic::core::security_audit;

    std::string malicious =
        "x result=ok peer=uid:0 gid:0 pid:1 command=device_delete "
        "message=\"fake\"\r\n\t\\ ";
    malicious.append("\0\x1b", 2);
    malicious += u8"Привет 😀";
    const json request = {
        {"command", "apply_module"},
        {"module", malicious},
        {"device_id", 42},
        {"password", "must-not-be-audited"}
    };
    const json response = {{"ok", false}, {"message", "real failure"}};
    audit::PeerCredentials peer;
    peer.available = true;
    peer.uid = 1001;
    peer.gid = 1002;
    peer.pid = 1003;

    const json event = make_admin_ipc_audit_event(
        peer, request, response, "2026-09-08T00:00:00Z");
    const std::filesystem::path path = std::filesystem::temp_directory_path() /
        ("fic-admin-audit-" + std::to_string(::getpid()) + ".jsonl");
    std::filesystem::remove(path);
    std::string error;
    assert(audit::appendJsonLine(path, event, error));

    std::ifstream stream(path, std::ios::binary);
    std::string line;
    assert(std::getline(stream, line));
    std::string secondLine;
    assert(!std::getline(stream, secondLine));
    assert(std::count(line.begin(), line.end(), '\n') == 0);
    assert(std::count(line.begin(), line.end(), '\r') == 0);

    const json parsed = json::parse(line);
    assert(parsed["component"] == "fic");
    assert(parsed["command"] == "apply_module");
    assert(parsed["request"]["module"] == malicious);
    assert(parsed["request"]["device_id"].is_number_integer());
    assert(parsed["request"]["device_id"] == 42);
    assert(!parsed["request"].contains("password"));
    assert(parsed["peer"]["available"] == true);
    assert(parsed["peer"]["uid"] == 1001);
    assert(parsed["peer"]["gid"] == 1002);
    assert(parsed["peer"]["pid"] == 1003);
    assert(parsed["result"]["ok"] == false);
    assert(parsed["result"]["message"] == "real failure");
    assert(!parsed.contains("message"));
    assert(!parsed.contains("gid"));
    assert(!parsed.contains("pid"));

    audit::PeerCredentials unavailablePeer;
    unavailablePeer.error = "credentials\r\n\"unavailable\"";
    const json unavailableEvent = make_admin_ipc_audit_event(
        unavailablePeer, request, response, "2026-09-08T00:00:00Z");
    assert(unavailableEvent["peer"]["available"] == false);
    assert(unavailableEvent["peer"]["error"] == unavailablePeer.error);
    assert(!unavailableEvent["peer"].contains("uid"));

    json longRequest = request;
    longRequest["module"] = std::string(audit::MAX_STRING_BYTES + 100U, 'M');
    const json truncated = make_admin_ipc_audit_event(
        peer, longRequest, response, "2026-09-08T00:00:00Z");
    assert(truncated["request"]["module"].get<std::string>().size() ==
           audit::MAX_STRING_BYTES);
    assert(std::find(truncated["truncated_fields"].begin(),
                     truncated["truncated_fields"].end(),
                     "/request/module") != truncated["truncated_fields"].end());
    assert(audit::serializeJsonLine(truncated).size() <= audit::MAX_RECORD_BYTES);

    std::filesystem::remove(path);
    return 0;
}
