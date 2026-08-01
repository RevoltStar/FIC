#include <fic/ipc/FicIpcTransport.h>

#include <fic/ipc/FicIpcClient.h>

#include "FicIpcWire.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace fic::ipc {
namespace {
using Clock = std::chrono::steady_clock;

enum class ConnectionState {
    WaitingForRequest,
    Ready,
    WritingResponse
};

struct Connection {
    int fd = -1;
    ConnectionState state = ConnectionState::WaitingForRequest;
    Clock::time_point deadline;
    std::string request;
    std::string response;
    std::size_t responseOffset = 0;
};

void closeConnection(Connection& connection) {
    if (connection.fd >= 0) {
        ::close(connection.fd);
        connection.fd = -1;
    }
}

bool setNonBlockingAndCloseOnExec(int fd) {
    const int statusFlags = ::fcntl(fd, F_GETFL, 0);
    const int descriptorFlags = ::fcntl(fd, F_GETFD, 0);
    return statusFlags >= 0 && descriptorFlags >= 0 &&
        ::fcntl(fd, F_SETFL, statusFlags | O_NONBLOCK) == 0 &&
        ::fcntl(fd, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0;
}

std::string boundedResponse(std::string response) {
    if (!response.empty() && response.size() <= MAX_RESPONSE_BYTES) {
        return response;
    }
    return make_error_response("daemon response exceeds the 1048576-byte IPC limit").dump();
}
} // namespace

class AdminSocketTransport::Impl {
public:
    explicit Impl(int serverFd) : serverFd_(serverFd) {}

    ~Impl() {
        for (Connection& connection : connections_) {
            closeConnection(connection);
        }
    }

    bool pollOnce(int timeoutMilliseconds,
                  const RequestHandler& handler,
                  std::string& error) {
        expireConnections();

        std::vector<pollfd> descriptors;
        descriptors.reserve(connections_.size() + 1U);
        descriptors.push_back({serverFd_, POLLIN, 0});
        for (const Connection& connection : connections_) {
            short events = 0;
            if (connection.state == ConnectionState::WaitingForRequest) {
                events = POLLIN;
            } else if (connection.state == ConnectionState::WritingResponse) {
                events = POLLOUT;
            }
            descriptors.push_back({connection.fd, events, 0});
        }

        const int boundedTimeout = timeoutForNearestDeadline(timeoutMilliseconds);
        const int ready = ::poll(descriptors.data(), descriptors.size(), boundedTimeout);
        if (ready < 0) {
            if (errno == EINTR) {
                return true;
            }
            error = "poll() failed: " + std::string(std::strerror(errno));
            return false;
        }

        if ((descriptors.front().revents & POLLIN) != 0 && !acceptClients(error)) {
            return false;
        }
        if ((descriptors.front().revents & (POLLERR | POLLNVAL)) != 0) {
            error = "administrative listener reported a poll error";
            return false;
        }

        for (std::size_t index = 1; index < descriptors.size(); ++index) {
            const int fd = descriptors[index].fd;
            auto found = std::find_if(connections_.begin(), connections_.end(),
                [fd](const Connection& connection) { return connection.fd == fd; });
            if (found == connections_.end()) {
                continue;
            }

            const short events = descriptors[index].revents;
            if ((events & (POLLERR | POLLNVAL)) != 0) {
                closeConnection(*found);
                continue;
            }
            if (found->state == ConnectionState::WaitingForRequest &&
                (events & POLLIN) != 0) {
                receiveRequest(*found);
            } else if (found->state == ConnectionState::WritingResponse &&
                       (events & POLLOUT) != 0) {
                writeResponseChunk(*found);
            }
            if ((events & POLLHUP) != 0 &&
                found->state == ConnectionState::WaitingForRequest) {
                closeConnection(*found);
            }
        }

        connections_.erase(
            std::remove_if(connections_.begin(), connections_.end(),
                [](const Connection& connection) { return connection.fd < 0; }),
            connections_.end());

        auto readyRequest = std::find_if(connections_.begin(), connections_.end(),
            [](const Connection& connection) {
                return connection.state == ConnectionState::Ready;
            });
        if (readyRequest != connections_.end()) {
            try {
                queueResponse(*readyRequest, handler(readyRequest->fd, readyRequest->request));
            } catch (const std::exception& exception) {
                queueResponse(*readyRequest,
                    make_error_response("request handler exception: " +
                        std::string(exception.what())).dump());
            } catch (...) {
                queueResponse(*readyRequest,
                    make_error_response("request handler failed with an unknown exception").dump());
            }
        }

        expireConnections();
        return true;
    }

    std::size_t connectionCount() const {
        return connections_.size();
    }

private:
    bool acceptClients(std::string& error) {
        while (true) {
            const int clientFd = ::accept(serverFd_, nullptr, nullptr);
            if (clientFd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return true;
                }
                error = "accept() failed: " + std::string(std::strerror(errno));
                return false;
            }
            if (!setNonBlockingAndCloseOnExec(clientFd)) {
                ::close(clientFd);
                continue;
            }
            if (connections_.size() >= MAX_ADMIN_CONNECTIONS) {
                ::close(clientFd);
                continue;
            }
            connections_.push_back({
                clientFd,
                ConnectionState::WaitingForRequest,
                Clock::now() + FIRST_PACKET_TIMEOUT,
                {},
                {},
                0
            });
        }
    }

    void receiveRequest(Connection& connection) {
        std::vector<char> request(MAX_REQUEST_BYTES);
        iovec vector{request.data(), request.size()};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        const ssize_t received = ::recvmsg(connection.fd, &message, 0);
        if (received < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                closeConnection(connection);
            }
            return;
        }
        if (received == 0) {
            closeConnection(connection);
            return;
        }
        if ((message.msg_flags & MSG_TRUNC) != 0) {
            queueResponse(connection,
                make_error_response("request exceeds the 65536-byte IPC limit").dump());
            return;
        }

        connection.request.assign(request.data(), static_cast<std::size_t>(received));
        connection.state = ConnectionState::Ready;
    }

    void queueResponse(Connection& connection, std::string response) {
        connection.response = boundedResponse(std::move(response));
        connection.responseOffset = 0;
        connection.deadline = Clock::now() + RESPONSE_WRITE_TIMEOUT;
        connection.state = ConnectionState::WritingResponse;
    }

    void writeResponseChunk(Connection& connection) {
        const std::size_t remaining = connection.response.size() - connection.responseOffset;
        const std::size_t chunkBytes = std::min(remaining, RESPONSE_CHUNK_BYTES);
        const std::string frame = wire::responseFrame(
            connection.response, connection.responseOffset, chunkBytes);
        const ssize_t written = ::send(
            connection.fd, frame.data(), frame.size(), MSG_NOSIGNAL);
        if (written < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                closeConnection(connection);
            }
            return;
        }
        if (written != static_cast<ssize_t>(frame.size())) {
            closeConnection(connection);
            return;
        }
        connection.responseOffset += chunkBytes;
        if (connection.responseOffset == connection.response.size()) {
            closeConnection(connection);
        }
    }

    void expireConnections() {
        const Clock::time_point now = Clock::now();
        for (Connection& connection : connections_) {
            if (connection.state != ConnectionState::Ready && now >= connection.deadline) {
                closeConnection(connection);
            }
        }
        connections_.erase(
            std::remove_if(connections_.begin(), connections_.end(),
                [](const Connection& connection) { return connection.fd < 0; }),
            connections_.end());
    }

    int timeoutForNearestDeadline(int requestedTimeout) const {
        int timeout = std::max(requestedTimeout, 0);
        const Clock::time_point now = Clock::now();
        for (const Connection& connection : connections_) {
            if (connection.state == ConnectionState::Ready) {
                timeout = 0;
                continue;
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                connection.deadline - now);
            timeout = std::min(timeout, static_cast<int>(
                std::max<std::int64_t>(remaining.count(), 0)));
        }
        return timeout;
    }

    int serverFd_;
    std::vector<Connection> connections_;
};

AdminSocketTransport::AdminSocketTransport(int serverFd)
    : impl_(std::make_unique<Impl>(serverFd)) {}

AdminSocketTransport::~AdminSocketTransport() = default;

bool AdminSocketTransport::pollOnce(int timeoutMilliseconds,
                                    const RequestHandler& handler,
                                    std::string& error) {
    return impl_->pollOnce(timeoutMilliseconds, handler, error);
}

std::size_t AdminSocketTransport::connectionCount() const {
    return impl_->connectionCount();
}

} // namespace fic::ipc
