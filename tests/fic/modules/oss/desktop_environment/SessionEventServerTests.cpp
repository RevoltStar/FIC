#include "session/SessionEventServer.h"

#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

int listener(std::string& path) {
    char directory[] = "/tmp/fic-session-event-test-XXXXXX";
    require(::mkdtemp(directory) != nullptr, "mkdtemp failed");
    path = std::string(directory) + "/events.sock";
    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    require(fd >= 0, "socket failed");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
    const int bindResult =
        ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    const int bindError = errno;
    require(bindResult == 0,
            "bind failed: " + std::string(std::strerror(bindError)));
    require(::listen(fd, 8) == 0, "listen failed");
    return fd;
}

int connectClient(const std::string& path) {
    const int client = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    require(client >= 0, "client socket failed");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
    require(::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0,
            "connect failed");
    return client;
}

nlohmann::json readResponse(int client) {
    char response[1024];
    const ssize_t count = ::recv(client, response, sizeof(response), 0);
    require(count > 0, "missing ACK");
    return nlohmann::json::parse(response, response + count);
}

nlohmann::json exchange(int serverFd, const std::string& path,
                        SessionEventServer& server, const nlohmann::json& request) {
    const int client = connectClient(path);
    const std::string text = request.dump();
    require(::send(client, text.data(), text.size(), 0) >= 0, "send failed");
    std::string error;
    require(server.pollOnce(0, error), error);
    const nlohmann::json response = readResponse(client);
    ::close(client);
    return response;
}
}

int main() {
    std::string path;
    const int fd = listener(path);
    int reconciliations = 0;
    SessionEventServer server(fd,
        [](uid_t uid, const std::string& id, ClassifiedGraphicalSession& out,
           std::string& error) {
            if (uid != ::getuid() || (id != "7" && id != "9")) {
                error = "uid/session mismatch";
                return false;
            }
            out.session.id = id;
            out.session.uid = uid;
            out.desktop = DesktopEnvironmentKind::Kde;
            return true;
        },
        [&](const ClassifiedGraphicalSession&) { ++reconciliations; });

    require(!exchange(fd, path, server, {{"event", "admin"}, {"session_id", "7"}})
                 .value("ok", true), "admin command reached event endpoint");
    require(!exchange(fd, path, server,
                      {{"event", "session_ready"}, {"session_id", "7"},
                       {"desktop", "KDE"}}).value("ok", true),
            "desktop supplied by agent was accepted");
    require(!exchange(fd, path, server,
                      {{"event", "session_ready"}, {"session_id", "8"}})
                 .value("ok", true), "uid/session mismatch was accepted");
    require(!exchange(fd, path, server,
                      {{"event", "session_ready"}, {"session_id", "../7"}})
                 .value("ok", true), "unsafe session id was accepted");
    const int delayedClient = connectClient(path);
    const std::string delayedPayload = nlohmann::json{
        {"event", "session_ready"}, {"session_id", "7"}}.dump();
    bool delayedSendSucceeded = false;
    std::thread delayedSender([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        delayedSendSucceeded = ::send(
            delayedClient, delayedPayload.data(), delayedPayload.size(), 0) >= 0;
    });
    std::string error;
    require(server.pollOnce(0, error), error);
    delayedSender.join();
    require(delayedSendSucceeded, "delayed session event send failed");
    require(readResponse(delayedClient).value("ok", false),
            "connect-before-send event was falsely rejected");
    ::close(delayedClient);
    require(server.pendingCount() == 1,
            "connect-before-send event was not scheduled exactly once");
    require(reconciliations == 0, "ACK incorrectly waited for reconciliation");
    server.processOne();
    require(reconciliations == 1, "scheduled reconciliation was not run");

    const int silentClient = connectClient(path);
    const auto timeoutStart = std::chrono::steady_clock::now();
    require(server.pollOnce(0, error), error);
    const auto timeoutElapsed = std::chrono::steady_clock::now() - timeoutStart;
    require(!readResponse(silentClient).value("ok", true),
            "silent connection timeout was acknowledged as accepted");
    char closedProbe = 0;
    require(::recv(silentClient, &closedProbe, sizeof(closedProbe), 0) == 0,
            "silent connection was not closed after payload timeout");
    ::close(silentClient);
    require(timeoutElapsed < std::chrono::seconds(3),
            "silent connection timeout was not bounded");

    const int closedClient = connectClient(path);
    ::close(closedClient);
    const auto closedStart = std::chrono::steady_clock::now();
    require(server.pollOnce(0, error), error);
    require(std::chrono::steady_clock::now() - closedStart <
                std::chrono::seconds(1),
            "peer close without payload waited for the full timeout");
    require(server.pendingCount() == 0,
            "peer close without payload scheduled reconciliation");

    require(exchange(fd, path, server,
                     {{"event", "session_ready"}, {"session_id", "9"}})
                .value("ok", false),
            "valid event after payload timeout was rejected");
    require(exchange(fd, path, server,
                     {{"event", "session_ready"}, {"session_id", "9"}})
                .value("ok", false), "duplicate event was not acknowledged");
    require(server.pendingCount() == 1, "duplicate event was not coalesced");
    server.processOne();
    require(reconciliations == 2,
            "post-timeout event was not reconciled exactly once");

    ::close(fd);
    ::unlink(path.c_str());
    ::rmdir(path.substr(0, path.find_last_of('/')).c_str());
    return 0;
}
