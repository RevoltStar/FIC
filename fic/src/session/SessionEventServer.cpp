#include "session/SessionEventServer.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <nlohmann/json.hpp>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
bool writeAck(int fd, bool ok, const std::string& message)
{
    const std::string text = nlohmann::json{{"ok", ok}, {"message", message}}.dump();
    return ::send(fd, text.data(), text.size(), MSG_NOSIGNAL) >= 0;
}
}

SessionEventServer::SessionEventServer(
    int serverFd, Validator validator, Reconciler reconciler)
    : serverFd_(serverFd), validator_(std::move(validator)),
      reconciler_(std::move(reconciler))
{
}

bool SessionEventServer::pollOnce(int timeoutMilliseconds, std::string& error)
{
    pollfd descriptor{serverFd_, POLLIN, 0};
    const int ready = ::poll(&descriptor, 1, timeoutMilliseconds);
    if (ready < 0) {
        if (errno == EINTR) return true;
        error = "session-event poll failed: " + std::string(std::strerror(errno));
        return false;
    }
    if (ready == 0) return true;

    const int client = ::accept4(serverFd_, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client < 0) {
        if (errno == EAGAIN || errno == EINTR) return true;
        error = "session-event accept failed: " + std::string(std::strerror(errno));
        return false;
    }

    struct ucred peer {};
    socklen_t peerLength = sizeof(peer);
    if (::getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peerLength) != 0) {
        writeAck(client, false, "peer credentials unavailable");
        ::close(client);
        return true;
    }

    char buffer[MaxRequestBytes + 1];
    const ssize_t count = ::recv(client, buffer, sizeof(buffer), MSG_TRUNC);
    if (count <= 0 || static_cast<std::size_t>(count) > MaxRequestBytes) {
        writeAck(client, false, "invalid session event size");
        ::close(client);
        return true;
    }

    try {
        const auto request = nlohmann::json::parse(buffer, buffer + count);
        if (!request.is_object() || request.size() != 2 ||
            request.value("event", "") != "session_ready" ||
            !request.contains("session_id") || !request["session_id"].is_string()) {
            writeAck(client, false, "unsupported or malformed session event");
            ::close(client);
            return true;
        }
        const std::string sessionId = request["session_id"].get<std::string>();
        const bool validSessionId = !sessionId.empty() && sessionId.size() <= 128 &&
            std::all_of(sessionId.begin(), sessionId.end(), [](unsigned char value) {
                return std::isalnum(value) != 0 || value == '_' || value == '-';
            });
        ClassifiedGraphicalSession session;
        std::string validationError;
        if (!validSessionId ||
            !validator_(peer.uid, sessionId, session, validationError)) {
            writeAck(client, false, validationError.empty()
                ? "invalid session identity" : validationError);
            ::close(client);
            return true;
        }

        const auto now = std::chrono::steady_clock::now();
        const std::string key = std::to_string(peer.uid) + ":" + sessionId;
        for (auto item = pendingOrRecent_.begin(); item != pendingOrRecent_.end();) {
            if (pendingKeys_.find(item->first) == pendingKeys_.end() &&
                now - item->second >= std::chrono::seconds(5)) {
                item = pendingOrRecent_.erase(item);
            } else {
                ++item;
            }
        }
        const auto existing = pendingOrRecent_.find(key);
        if (existing != pendingOrRecent_.end() &&
            now - existing->second < std::chrono::seconds(5)) {
            writeAck(client, true, "session event coalesced");
        } else if (pending_.size() >= MaxPending) {
            writeAck(client, false, "session event queue is full");
        } else {
            pendingOrRecent_[key] = now;
            pendingKeys_.insert(key);
            pending_.push_back(std::move(session));
            writeAck(client, true, "session reconciliation scheduled");
        }
    } catch (const std::exception&) {
        writeAck(client, false, "malformed session event");
    }
    ::close(client);
    return true;
}

void SessionEventServer::processOne()
{
    if (pending_.empty()) return;
    ClassifiedGraphicalSession session = std::move(pending_.front());
    pending_.pop_front();
    const std::string key = std::to_string(session.session.uid) + ":" +
        session.session.id;
    pendingKeys_.erase(key);
    pendingOrRecent_[key] = std::chrono::steady_clock::now();
    reconciler_(session);
}
