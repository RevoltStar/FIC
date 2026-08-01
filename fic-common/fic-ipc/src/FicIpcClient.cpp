#include <fic/ipc/FicIpcClient.h>

#include "FicIpcWire.h"

#include <algorithm>
#include <chrono>
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace fic::ipc {
namespace {
using Clock = std::chrono::steady_clock;

class ScopedFd {
public:
    explicit ScopedFd(int fd) : fd_(fd) {}
    ~ScopedFd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    int get() const { return fd_; }

private:
    int fd_;
};

bool waitFor(int fd,
             short events,
             Clock::time_point deadline,
             std::string& error) {
    while (true) {
        const auto now = Clock::now();
        if (now >= deadline) {
            error = "IPC deadline exceeded";
            return false;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        const int timeout = static_cast<int>(std::min<long long>(
            std::max<long long>(remaining.count(), 1), INT_MAX));
        pollfd descriptor{fd, events, 0};
        const int ready = ::poll(&descriptor, 1, timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = std::strerror(errno);
            return false;
        }
        if (ready == 0) {
            continue;
        }
        if ((descriptor.revents & POLLNVAL) != 0) {
            error = "invalid socket descriptor";
            return false;
        }
        if ((descriptor.revents & events) != 0) {
            return true;
        }
        if ((descriptor.revents & (POLLERR | POLLHUP)) != 0) {
            error = "daemon closed the IPC connection";
            return false;
        }
    }
}

bool connectWithDeadline(int fd,
                         const std::string& socketPath,
                         Clock::time_point deadline,
                         std::string& error) {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(address.sun_path)) {
        error = "socket path is too long: " + socketPath;
        return false;
    }
    std::strncpy(address.sun_path, socketPath.c_str(), sizeof(address.sun_path) - 1);
    const socklen_t addressLength = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + socketPath.size() + 1U);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), addressLength) == 0) {
        return true;
    }
    if (errno != EINPROGRESS && errno != EAGAIN) {
        error = std::strerror(errno);
        return false;
    }
    if (!waitFor(fd, POLLOUT, deadline, error)) {
        return false;
    }

    int socketError = 0;
    socklen_t errorLength = sizeof(socketError);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) != 0) {
        error = std::strerror(errno);
        return false;
    }
    if (socketError != 0) {
        error = std::strerror(socketError);
        return false;
    }
    return true;
}

bool sendPacket(int fd,
                const std::string& packet,
                Clock::time_point deadline,
                std::string& error) {
    while (true) {
        const ssize_t written = ::send(fd, packet.data(), packet.size(), MSG_NOSIGNAL);
        if (written == static_cast<ssize_t>(packet.size())) {
            return true;
        }
        if (written >= 0) {
            error = "SOCK_SEQPACKET send was not atomic";
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            error = std::strerror(errno);
            return false;
        }
        if (!waitFor(fd, POLLOUT, deadline, error)) {
            return false;
        }
    }
}

bool receiveResponse(int fd,
                     Clock::time_point deadline,
                     std::string& response,
                     std::string& error) {
    std::vector<char> frame(wire::HEADER_BYTES + RESPONSE_CHUNK_BYTES);
    std::size_t expectedTotal = 0;

    while (response.size() < expectedTotal || expectedTotal == 0) {
        if (!waitFor(fd, POLLIN, deadline, error)) {
            return false;
        }

        iovec vector{frame.data(), frame.size()};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        const ssize_t received = ::recvmsg(fd, &message, 0);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            error = std::strerror(errno);
            return false;
        }
        if (received == 0) {
            error = "daemon closed the IPC connection before a complete response";
            return false;
        }
        if ((message.msg_flags & MSG_TRUNC) != 0) {
            error = "daemon response frame exceeds the transport chunk limit";
            return false;
        }

        std::size_t total = 0;
        std::size_t offset = 0;
        std::size_t chunk = 0;
        if (!wire::parseResponseHeader(frame.data(), static_cast<std::size_t>(received),
                                       total, offset, chunk, error)) {
            return false;
        }
        if (total == 0 || total > MAX_RESPONSE_BYTES) {
            error = "daemon response exceeds the transport limit";
            return false;
        }
        if ((expectedTotal != 0 && total != expectedTotal) || offset != response.size() ||
            chunk == 0 || chunk > RESPONSE_CHUNK_BYTES || chunk > total - offset) {
            error = "daemon response frames are inconsistent";
            return false;
        }
        expectedTotal = total;
        response.append(frame.data() + wire::HEADER_BYTES, chunk);
    }
    return response.size() == expectedTotal;
}
} // namespace

Client::Client()
    : socketPath_(endpoint_socket_path(Endpoint::PolicyDaemon)) {}

Client::Client(Endpoint endpoint)
    : socketPath_(endpoint_socket_path(endpoint)) {}

Client::Client(std::string socketPath)
    : socketPath_(socketPath.empty()
          ? endpoint_socket_path(Endpoint::PolicyDaemon)
          : std::move(socketPath)) {}

Client::Client(std::string socketPath, std::chrono::milliseconds timeout)
    : socketPath_(socketPath.empty()
          ? endpoint_socket_path(Endpoint::PolicyDaemon)
          : std::move(socketPath)),
      timeout_(timeout) {}

json Client::request(const json& payload) const {
    std::string requestText;
    try {
        requestText = payload.dump();
    } catch (const std::exception& exception) {
        return make_error_response("could not serialize IPC request: " +
            std::string(exception.what()));
    }
    if (requestText.empty() || requestText.size() > MAX_REQUEST_BYTES) {
        return make_error_response("request exceeds the 65536-byte IPC limit");
    }
    if (timeout_.count() <= 0) {
        return make_error_response("IPC timeout must be positive");
    }

    const int rawFd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (rawFd < 0) {
        return make_error_response("socket() failed: " + std::string(std::strerror(errno)));
    }
    ScopedFd fd(rawFd);
    const Clock::time_point deadline = Clock::now() + timeout_;

    std::string error;
    if (!connectWithDeadline(fd.get(), socketPath_, deadline, error)) {
        return make_error_response("connect(" + socketPath_ + ") failed: " + error);
    }
    if (!sendPacket(fd.get(), requestText, deadline, error)) {
        return make_error_response("send failed: " + error);
    }

    std::string responseText;
    if (!receiveResponse(fd.get(), deadline, responseText, error)) {
        return make_error_response("receive failed: " + error);
    }

    try {
        return json::parse(responseText);
    } catch (const std::exception& exception) {
        const std::string raw = responseText.substr(0, 512);
        return make_error_response("invalid daemon response: " +
            std::string(exception.what()) + "; raw=" + raw);
    }
}

} // namespace fic::ipc
