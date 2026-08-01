#include <fic/ipc/FicAdminSocket.h>
#include <fic/ipc/FicIpcClient.h>

#include <arpa/inet.h>

#include <atomic>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
using json = nlohmann::json;
using namespace std::chrono_literals;

int connectRaw(const std::filesystem::path& socketPath) {
    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const std::string path = socketPath.string();
    assert(path.size() < sizeof(address.sun_path));
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
    const socklen_t length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1U);
    assert(::connect(fd, reinterpret_cast<sockaddr*>(&address), length) == 0);
    return fd;
}

json receiveRawResponse(int fd) {
    constexpr std::uint32_t magic = 0x46494332U;
    std::vector<char> frame(16U + fic::ipc::RESPONSE_CHUNK_BYTES);
    std::string response;
    std::size_t expected = 0;
    do {
        const ssize_t received = ::recv(fd, frame.data(), frame.size(), 0);
        assert(received >= 16);
        std::uint32_t words[4]{};
        std::memcpy(words, frame.data(), 16U);
        assert(ntohl(words[0]) == magic);
        const std::size_t total = ntohl(words[1]);
        const std::size_t offset = ntohl(words[2]);
        const std::size_t chunk = ntohl(words[3]);
        assert(static_cast<std::size_t>(received) == 16U + chunk);
        assert(offset == response.size());
        if (expected == 0) {
            expected = total;
        }
        assert(total == expected);
        response.append(frame.data() + 16U, chunk);
    } while (response.size() < expected);
    return json::parse(response);
}
} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-ipc-transport-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    const fs::path socketPath = root / "runtime/admin.sock";

    auto socketResult = fic::ipc::create_admin_server_socket({
        socketPath,
        fic::ipc::AdminSocketSecurityProfile::Development,
        32,
        "IPC transport test socket"
    });
    if (socketResult.fileDescriptor < 0) {
        std::cerr << socketResult.error << '\n';
        fs::remove_all(root);
        if (socketResult.error.find("Operation not permitted") != std::string::npos) {
            return 77;
        }
    }
    assert(socketResult.fileDescriptor >= 0);

    fic::ipc::AdminSocketTransport transport(socketResult.fileDescriptor);
    std::atomic_bool stop{false};
    std::atomic_int handled{0};
    std::thread server([&] {
        while (!stop.load()) {
            std::string error;
            const bool ok = transport.pollOnce(10,
                [&](int, const std::string& requestText) {
                    ++handled;
                    const json request = json::parse(requestText);
                    if (request.value("command", "") == "large") {
                        return json{{"ok", true}, {"message", "large"},
                                    {"api_version", fic::ipc::API_VERSION},
                                    {"data", std::string(900U * 1024U, 'x')}}.dump();
                    }
                    if (request.value("command", "") == "unversioned-response") {
                        return json{{"ok", true}, {"message", "old daemon"}}.dump();
                    }
                    return fic::ipc::make_ok_response("echo").dump();
                },
                error);
            assert(ok);
        }
    });

    fic::ipc::Client client(socketPath.string(), 3s);
    json response = client.request({{"command", "status"}});
    assert(response.value("ok", false));

    response = client.request({{"command", "large"}});
    assert(response.value("ok", false));
    assert(response.at("data").get_ref<const std::string&>().size() == 900U * 1024U);

    response = client.request({{"command", "unversioned-response"}});
    assert(!response.value("ok", true));
    assert(response.value("message", "").find("IPC API version") != std::string::npos);

    json exactRequest{{"api_version", fic::ipc::API_VERSION},
                      {"command", "echo"}, {"padding", ""}};
    const std::size_t emptySize = exactRequest.dump().size();
    exactRequest["padding"] = std::string(fic::ipc::MAX_REQUEST_BYTES - emptySize, 'p');
    assert(exactRequest.dump().size() == fic::ipc::MAX_REQUEST_BYTES);
    response = client.request(exactRequest);
    assert(response.value("ok", false));

    exactRequest["padding"] = exactRequest["padding"].get<std::string>() + "p";
    response = client.request(exactRequest);
    assert(!response.value("ok", true));
    assert(response.value("message", "").find("65536-byte") != std::string::npos);

    const int idleFd = connectRaw(socketPath);
    const auto responsiveStart = std::chrono::steady_clock::now();
    response = client.request({{"command", "status"}});
    const auto responsiveElapsed = std::chrono::steady_clock::now() - responsiveStart;
    assert(response.value("ok", false));
    assert(responsiveElapsed < 1s);
    std::this_thread::sleep_for(2200ms);
    timeval idleReceiveTimeout{};
    idleReceiveTimeout.tv_sec = 1;
    assert(::setsockopt(idleFd, SOL_SOCKET, SO_RCVTIMEO,
                        &idleReceiveTimeout, sizeof(idleReceiveTimeout)) == 0);
    char idleByte = '\0';
    assert(::recv(idleFd, &idleByte, 1, 0) == 0);

    const int nonReadingFd = connectRaw(socketPath);
    const std::string largeRequest =
        json{{"api_version", 1}, {"command", "large"}}.dump();
    assert(::send(nonReadingFd, largeRequest.data(), largeRequest.size(), 0) ==
           static_cast<ssize_t>(largeRequest.size()));
    std::this_thread::sleep_for(50ms);
    response = client.request({{"command", "status"}});
    assert(response.value("ok", false));

    const int oversizedFd = connectRaw(socketPath);
    const std::string oversized(fic::ipc::MAX_REQUEST_BYTES + 1U, 'x');
    assert(::send(oversizedFd, oversized.data(), oversized.size(), 0) ==
           static_cast<ssize_t>(oversized.size()));
    response = receiveRawResponse(oversizedFd);
    assert(!response.value("ok", true));
    assert(response.value("message", "").find("65536-byte") != std::string::npos);

    json parsed;
    std::string parseError;
    assert(!fic::ipc::parse_request_json("[]", parsed, parseError));
    assert(!fic::ipc::parse_request_json("{\"command\":7}", parsed, parseError));
    std::string deep = "{\"command\":\"x\",\"v\":";
    for (std::size_t i = 0; i < fic::ipc::MAX_JSON_DEPTH + 2U; ++i) {
        deep += '[';
    }
    deep += '0';
    for (std::size_t i = 0; i < fic::ipc::MAX_JSON_DEPTH + 2U; ++i) {
        deep += ']';
    }
    deep += '}';
    assert(!fic::ipc::parse_request_json(deep, parsed, parseError));

    ::close(oversizedFd);
    ::close(nonReadingFd);
    ::close(idleFd);
    stop = true;
    server.join();
    assert(handled.load() >= 6);

    ::close(socketResult.fileDescriptor);
    fs::remove_all(root);
    return 0;
}
