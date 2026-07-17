#ifndef FIC_IPC_CLIENT_H
#define FIC_IPC_CLIENT_H

#include <fic/ipc/FicIpcPathDefaults.h>

#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>

namespace fic::ipc {

using json = nlohmann::json;

inline constexpr const char* DEFAULT_RUNTIME_DIR = path_defaults::RUNTIME_DIR;
inline constexpr const char* DEFAULT_SOCKET_PATH = path_defaults::DAEMON_SOCKET;
inline constexpr const char* DEFAULT_DEVICE_SOCKET_PATH = path_defaults::DEVICE_SOCKET;

enum class Endpoint {
    PolicyDaemon,
    DeviceDaemon
};

inline std::string endpoint_socket_path(Endpoint endpoint) {
    const char* environmentName = endpoint == Endpoint::PolicyDaemon
        ? "FIC_SOCKET_PATH"
        : "FIC_DEVICE_SOCKET_PATH";
    const char* environmentPath = std::getenv(environmentName);
    if (environmentPath != nullptr && environmentPath[0] != '\0') {
        return environmentPath;
    }
    return endpoint == Endpoint::PolicyDaemon
        ? DEFAULT_SOCKET_PATH
        : DEFAULT_DEVICE_SOCKET_PATH;
}

inline json make_error_response(const std::string& message) {
    return json{{"ok", false}, {"message", message}};
}

inline json make_ok_response(const std::string& message = "OK") {
    return json{{"ok", true}, {"message", message}};
}

inline bool write_all(int fd, const std::string& data, std::string& error) {
    const char* ptr = data.c_str();
    size_t left = data.size();
    while (left > 0) {
        ssize_t written = ::write(fd, ptr, left);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = std::strerror(errno);
            return false;
        }
        if (written == 0) {
            error = "socket write returned 0";
            return false;
        }
        ptr += written;
        left -= static_cast<size_t>(written);
    }
    return true;
}

inline bool read_until_eof(int fd, std::string& output, std::string& error) {
    char buffer[4096];
    while (true) {
        ssize_t received = ::read(fd, buffer, sizeof(buffer));
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = std::strerror(errno);
            return false;
        }
        if (received == 0) {
            return true;
        }
        output.append(buffer, static_cast<size_t>(received));
    }
}

class Client {
public:
    Client()
        : socketPath_(endpoint_socket_path(Endpoint::PolicyDaemon)) {}

    explicit Client(Endpoint endpoint)
        : socketPath_(endpoint_socket_path(endpoint)) {}

    explicit Client(std::string socketPath)
        : socketPath_(socketPath.empty()
              ? endpoint_socket_path(Endpoint::PolicyDaemon)
              : std::move(socketPath)) {}

    json request(const json& payload) const {
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            return make_error_response("socket() failed: " + std::string(std::strerror(errno)));
        }

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (socketPath_.size() >= sizeof(addr.sun_path)) {
            ::close(fd);
            return make_error_response("socket path is too long: " + socketPath_);
        }
        std::strncpy(addr.sun_path, socketPath_.c_str(), sizeof(addr.sun_path) - 1);

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::string err = std::strerror(errno);
            ::close(fd);
            return make_error_response("connect(" + socketPath_ + ") failed: " + err);
        }

        std::string error;
        std::string requestText = payload.dump() + "\n";
        if (!write_all(fd, requestText, error)) {
            ::close(fd);
            return make_error_response("write failed: " + error);
        }

        ::shutdown(fd, SHUT_WR);

        std::string responseText;
        if (!read_until_eof(fd, responseText, error)) {
            ::close(fd);
            return make_error_response("read failed: " + error);
        }
        ::close(fd);

        try {
            return json::parse(responseText);
        } catch (const std::exception& e) {
            return make_error_response("invalid daemon response: " + std::string(e.what()) + "; raw=" + responseText);
        }
    }

private:
    std::string socketPath_;
};

} // namespace fic::ipc

#endif // FIC_IPC_CLIENT_H
