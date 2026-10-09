#include "incident/IncidentAccessClient.h"
#include "FicIpcWire.h"
#include <fic/ipc/FicReadinessStatus.h>

#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>

#include <cstdlib>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
void require(bool value, const std::string& detail) {
    if (!value) throw std::runtime_error("strict incident IPC regression: " + detail);
}

class Fixture {
public:
    Fixture() {
        char pattern[] = "/tmp/fic-access-ipc-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) throw std::runtime_error("mkdtemp failed");
        directory_ = created;
        path_ = (directory_ / "socket").string();
        server_ = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (server_ < 0) throw std::runtime_error("socket failed");
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, path_.c_str(), sizeof(address.sun_path) - 1);
        if (::bind(server_, reinterpret_cast<sockaddr*>(&address),
                   sizeof(address)) != 0 || ::listen(server_, 2) != 0) {
            throw std::runtime_error("socket bind/listen failed");
        }
    }
    ~Fixture() {
        if (server_ >= 0) ::close(server_);
        std::filesystem::remove_all(directory_);
    }
    const std::string& path() const { return path_; }
    bool hasPendingConnection() const {
        pollfd descriptor{server_, POLLIN, 0};
        return ::poll(&descriptor, 1, 0) > 0 &&
            (descriptor.revents & POLLIN) != 0;
    }
    std::thread answer(const std::string& response) {
        return std::thread([this, response] {
            const int client = ::accept(server_, nullptr, nullptr);
            if (client < 0) return;
            char request[1024];
            if (::recv(client, request, sizeof(request), 0) > 0) {
                const auto frame = fic::ipc::wire::responseFrame(
                    response, 0, response.size());
                (void)::send(client, frame.data(), frame.size(),
                             MSG_NOSIGNAL);
            }
            ::close(client);
        });
    }
    std::thread hold() {
        return std::thread([this] {
            const int client = ::accept(server_, nullptr, nullptr);
            if (client < 0) return;
            char request[1024];
            (void)::recv(client, request, sizeof(request), 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(2200));
            ::close(client);
        });
    }
private:
    std::filesystem::path directory_;
    std::string path_;
    int server_ = -1;
};

std::string response(bool allowed) {
    fic::ipc::AccessGateStatus status;
    status.state = "READY"; status.modeProven = true;
    status.severity = allowed ? "UNLOCKED" : "HARD";
    status.stateProven = true; status.provenance = "PROVEN";
    status.loginAllowed = allowed;
    return fic::ipc::serializeAccessGateStatus(status).dump();
}
}

int main() {
    using fic::incident::IncidentAccessClient;
    Fixture fixture;
    ::setenv("FIC_SOCKET_PATH", fixture.path().c_str(), 1);
    (void)IncidentAccessClient::query();
    require(!fixture.hasPendingConnection(),
            "production client followed FIC_SOCKET_PATH");
    {
        auto server = fixture.answer(response(true));
        const auto reply = IncidentAccessClient::queryAtPathForTests(
            fixture.path(), ::geteuid());
        server.join();
        require(reply.allowed, "allow: " + reply.diagnostic);
    }
    {
        auto server = fixture.answer(response(false));
        const auto reply = IncidentAccessClient::queryAtPathForTests(
            fixture.path(), ::geteuid());
        server.join();
        require(!reply.allowed, "deny: " + reply.diagnostic);
    }
    {
        auto server = fixture.answer(R"({"ok":true,"api_version":1})");
        const auto reply = IncidentAccessClient::queryAtPathForTests(
            fixture.path(), ::geteuid());
        server.join();
        require(!reply.allowed, "malformed: " + reply.diagnostic);
    }
    {
        auto wrongVersion = nlohmann::json::parse(response(true));
        wrongVersion["api_version"] = 2;
        auto server = fixture.answer(wrongVersion.dump());
        const auto reply = IncidentAccessClient::queryAtPathForTests(
            fixture.path(), ::geteuid());
        server.join();
        require(!reply.allowed, "version: " + reply.diagnostic);
    }
    {
        auto inconsistent = nlohmann::json::parse(response(true));
        inconsistent["daemon_state"] = "APPLYING";
        auto server = fixture.answer(inconsistent.dump());
        const auto reply = IncidentAccessClient::queryAtPathForTests(
            fixture.path(), ::geteuid());
        server.join();
        require(!reply.allowed, "inconsistent: " + reply.diagnostic);
    }
    {
        auto server = fixture.hold();
        const auto started = std::chrono::steady_clock::now();
        const auto reply = IncidentAccessClient::queryAtPathForTests(
            fixture.path(), ::geteuid());
        const auto elapsed = std::chrono::steady_clock::now() - started;
        server.join();
        require(!reply.allowed && elapsed < std::chrono::seconds(4),
                "deadline: " + reply.diagnostic);
    }
    {
        // Peer rejection happens immediately after connect, before any send.
        auto server = fixture.answer(response(true));
        const auto reply = IncidentAccessClient::queryAtPathForTests(
            fixture.path(), ::geteuid() + 1);
        server.join();
        require(!reply.allowed, "peer: " + reply.diagnostic);
    }
    ::unsetenv("FIC_SOCKET_PATH");
}
