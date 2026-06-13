#include <atomic>
#include <cctype>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include "ipc/FicIpcClient.h"

namespace {
std::atomic_bool stopRequested{false};

void handle_signal(int) {
    stopRequested = true;
}

std::string environment_value(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

bool valid_session_id(const std::string& id) {
    if (id.empty()) {
        return false;
    }
    for (const unsigned char ch : id) {
        if (!std::isalnum(ch) && ch != '_' && ch != '-') {
            return false;
        }
    }
    return true;
}

bool verify_runtime_directory(const std::string& runtimeDirectory) {
    struct stat info {};
    return !runtimeDirectory.empty() &&
           ::lstat(runtimeDirectory.c_str(), &info) == 0 &&
           S_ISDIR(info.st_mode) &&
           info.st_uid == ::getuid();
}

int create_server_socket(const std::string& socketPath) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(address.sun_path)) {
        ::close(fd);
        return -1;
    }
    std::strncpy(address.sun_path, socketPath.c_str(), sizeof(address.sun_path) - 1);

    ::unlink(socketPath.c_str());
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    if (::chmod(socketPath.c_str(), 0600) != 0 || ::listen(fd, 8) != 0) {
        ::close(fd);
        ::unlink(socketPath.c_str());
        return -1;
    }
    return fd;
}

bool is_root_peer(int fd) {
#ifdef SO_PEERCRED
    struct ucred credentials {};
    socklen_t credentialsLength = sizeof(credentials);
    return ::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialsLength) == 0 &&
           credentials.uid == 0;
#else
    return false;
#endif
}

void serve_client(int fd, const std::string& sessionId) {
    if (!is_root_peer(fd)) {
        return;
    }

    std::string requestText;
    std::string error;
    if (!fic::ipc::read_until_eof(fd, requestText, error)) {
        return;
    }

    nlohmann::json response;
    try {
        const nlohmann::json request = nlohmann::json::parse(requestText);
        if (request.value("command", "") != "session_context") {
            response = fic::ipc::make_error_response("unsupported session agent command");
        } else {
            std::string desktop = environment_value("XDG_CURRENT_DESKTOP");
            if (desktop.empty()) {
                desktop = environment_value("DESKTOP_SESSION");
            }
            response = {
                {"ok", true},
                {"message", "session context loaded"},
                {"session_id", sessionId},
                {"desktop", desktop},
                {"session_type", environment_value("XDG_SESSION_TYPE")},
                {"display", environment_value("DISPLAY")},
                {"wayland_display", environment_value("WAYLAND_DISPLAY")}
            };
        }
    } catch (const std::exception& exception) {
        response = fic::ipc::make_error_response("invalid request: " + std::string(exception.what()));
    }

    fic::ipc::write_all(fd, response.dump() + "\n", error);
}
} // namespace

int main() {
    const std::string sessionId = environment_value("XDG_SESSION_ID");
    const std::string runtimeDirectory = environment_value("XDG_RUNTIME_DIR");
    if (!valid_session_id(sessionId) || !verify_runtime_directory(runtimeDirectory)) {
        std::cerr << "fic-session-agent requires a valid graphical session environment" << std::endl;
        return 1;
    }

    const std::filesystem::path agentDirectory = std::filesystem::path(runtimeDirectory) / "fic";
    std::error_code filesystemError;
    std::filesystem::create_directory(agentDirectory, filesystemError);
    if (filesystemError || ::chmod(agentDirectory.c_str(), 0700) != 0) {
        std::cerr << "failed to create session agent directory: " << agentDirectory << std::endl;
        return 1;
    }

    const std::string lockPath = (agentDirectory / ("session-" + sessionId + ".lock")).string();
    const int lockFd = ::open(lockPath.c_str(), O_CREAT | O_RDWR, 0600);
    if (lockFd < 0 || ::flock(lockFd, LOCK_EX | LOCK_NB) != 0) {
        if (lockFd >= 0) {
            ::close(lockFd);
        }
        return 0;
    }

    const std::string socketPath = (agentDirectory / ("session-" + sessionId + ".sock")).string();
    const int serverFd = create_server_socket(socketPath);
    if (serverFd < 0) {
        std::cerr << "failed to create session agent socket: " << socketPath << std::endl;
        ::close(lockFd);
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    while (!stopRequested) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(serverFd, &readSet);
        timeval timeout{};
        timeout.tv_sec = 1;

        const int ready = ::select(serverFd + 1, &readSet, nullptr, nullptr, &timeout);
        if (ready > 0 && FD_ISSET(serverFd, &readSet)) {
            const int clientFd = ::accept(serverFd, nullptr, nullptr);
            if (clientFd >= 0) {
                timeval clientTimeout{};
                clientTimeout.tv_sec = 2;
                ::setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &clientTimeout, sizeof(clientTimeout));
                serve_client(clientFd, sessionId);
                ::close(clientFd);
            }
        }
    }

    ::close(serverFd);
    ::unlink(socketPath.c_str());
    ::close(lockFd);
    return 0;
}
