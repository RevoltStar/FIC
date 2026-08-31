#include <fic/ipc/FicIpcClient.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>

int main() {
    fic::ipc::json request;
    std::string error;

    const std::string currentVersionRequest = fic::ipc::json{
        {"api_version", fic::ipc::API_VERSION},
        {"command", "status"}
    }.dump();
    assert(fic::ipc::parse_request_json(
        currentVersionRequest, request, error));
    assert(!fic::ipc::parse_request_json(
        R"({"command":"status"})", request, error));
    assert(error.find("api_version") != std::string::npos);
    const std::string unsupportedVersionRequest = fic::ipc::json{
        {"api_version", fic::ipc::API_VERSION + 1},
        {"command", "status"}
    }.dump();
    assert(!fic::ipc::parse_request_json(
        unsupportedVersionRequest, request, error));
    assert(error.find("unsupported") != std::string::npos);
    assert(!fic::ipc::parse_request_json("[]", request, error));
    assert(!fic::ipc::parse_request_json(R"({"command":7})", request, error));

    std::string deep = "{\"api_version\":" +
        std::to_string(fic::ipc::API_VERSION) +
        ",\"command\":\"status\",\"value\":";
    for (std::size_t index = 0; index < fic::ipc::MAX_JSON_DEPTH + 2U; ++index) {
        deep += '[';
    }
    deep += '0';
    for (std::size_t index = 0; index < fic::ipc::MAX_JSON_DEPTH + 2U; ++index) {
        deep += ']';
    }
    deep += '}';
    assert(!fic::ipc::parse_request_json(deep, request, error));

    request = {{"command", "shutdown"}, {"unexpected", true}};
    assert(!fic::ipc::request_has_only_fields(request, {"command"}, error));

    fic::ipc::json oversized = {
        {"command", "echo"},
        {"padding", std::string(fic::ipc::MAX_REQUEST_BYTES, 'x')}
    };
    const auto response = fic::ipc::Client("/tmp/does-not-need-to-exist.sock")
        .request(oversized);
    assert(!response.value("ok", true));
    assert(response.value("message", "").find("65536-byte") != std::string::npos);
    return 0;
}
