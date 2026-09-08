#include "daemon/DeviceAudit.h"

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
    using namespace fic::device_control;

    std::string malicious =
        "x result=ok peer=uid:0 gid:0 pid:1 command=device_delete "
        "message=\"fake\"\r\n\t\\ ";
    malicious.append("\0\x1b", 2);
    malicious += u8"Привет 😀";
    const json request = {
        {"command", "device_update_control_level"},
        {"device_id", 73},
        {"parent_id", 12},
        {"control_level", malicious},
        {"ignore_hierarchy", true},
        {"block_usb_storage", false},
        {"env", {{"SECRET", "must-not-be-audited"}}}
    };
    const json response = {{"ok", false}, {"message", "invalid control level"}};
    audit::PeerCredentials peer;
    peer.available = true;
    peer.uid = 2001;
    peer.gid = 2002;
    peer.pid = 2003;

    assert(is_mutating_device_command(device_audit_command(request)));
    const json event = make_device_ipc_audit_event(
        peer, request, response, "2026-09-08T00:00:00Z");
    const std::filesystem::path path = std::filesystem::temp_directory_path() /
        ("fic-device-audit-" + std::to_string(::getpid()) + ".jsonl");
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
    assert(parsed["component"] == "fic-dick");
    assert(parsed["command"] == "device_update_control_level");
    assert(parsed["request"]["control_level"] == malicious);
    assert(parsed["request"]["device_id"].is_number_integer());
    assert(parsed["request"]["device_id"] == 73);
    assert(parsed["request"]["parent_id"] == 12);
    assert(parsed["request"]["ignore_hierarchy"].is_boolean());
    assert(parsed["request"]["ignore_hierarchy"] == true);
    assert(parsed["request"]["block_usb_storage"].is_boolean());
    assert(parsed["request"]["block_usb_storage"] == false);
    assert(!parsed["request"].contains("env"));
    assert(parsed["peer"]["available"] == true);
    assert(parsed["peer"]["uid"] == 2001);
    assert(parsed["peer"]["gid"] == 2002);
    assert(parsed["peer"]["pid"] == 2003);
    assert(parsed["result"]["ok"] == false);
    assert(parsed["result"]["message"] == "invalid control level");
    assert(!parsed.contains("message"));
    assert(!parsed.contains("gid"));
    assert(!parsed.contains("pid"));

    json longRequest = request;
    longRequest["control_level"] =
        std::string(audit::MAX_STRING_BYTES + 100U, 'C');
    const json truncated = make_device_ipc_audit_event(
        peer, longRequest, response, "2026-09-08T00:00:00Z");
    assert(truncated["request"]["control_level"].get<std::string>().size() ==
           audit::MAX_STRING_BYTES);
    assert(std::find(truncated["truncated_fields"].begin(),
                     truncated["truncated_fields"].end(),
                     "/request/control_level") !=
           truncated["truncated_fields"].end());
    assert(audit::serializeJsonLine(truncated).size() <= audit::MAX_RECORD_BYTES);

    std::filesystem::remove(path);
    return 0;
}
