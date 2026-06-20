#include "session/SessionAgentClient.h"

#include <fic/ipc/FicIpcClient.h>

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
bool verify_socket(const std::string& path, uid_t expectedUid, std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        error = "session agent socket is unavailable: " + path;
        return false;
    }
    if (!S_ISSOCK(info.st_mode) || info.st_uid != expectedUid) {
        error = "session agent socket has invalid type or owner: " + path;
        return false;
    }
    return true;
}
} // namespace

std::string SessionAgentClient::socketPath(const UserSession& session) {
    return "/run/user/" + std::to_string(session.uid) + "/fic/session-" + session.id + ".sock";
}

bool SessionAgentClient::query(const UserSession& session, SessionContext& context, std::string& error) {
    const std::string path = socketPath(session);
    if (!verify_socket(path, session.uid, error)) {
        return false;
    }

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = "socket() failed: " + std::string(std::strerror(errno));
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = 2;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.size() >= sizeof(address.sun_path)) {
        error = "session agent socket path is too long";
        ::close(fd);
        return false;
    }
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        error = "connect(" + path + ") failed: " + std::string(std::strerror(errno));
        ::close(fd);
        return false;
    }

#ifdef SO_PEERCRED
    struct ucred credentials {};
    socklen_t credentialsLength = sizeof(credentials);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialsLength) != 0 ||
        credentials.uid != session.uid) {
        error = "session agent peer credentials do not match the graphical session";
        ::close(fd);
        return false;
    }
#endif

    const std::string request = fic::ipc::json{{"command", "session_context"}}.dump() + "\n";
    if (!fic::ipc::write_all(fd, request, error)) {
        ::close(fd);
        return false;
    }
    ::shutdown(fd, SHUT_WR);

    std::string responseText;
    if (!fic::ipc::read_until_eof(fd, responseText, error)) {
        ::close(fd);
        return false;
    }
    ::close(fd);

    try {
        const fic::ipc::json response = fic::ipc::json::parse(responseText);
        if (!response.value("ok", false)) {
            error = response.value("message", "session agent returned an error");
            return false;
        }
        context.sessionId = response.value("session_id", "");
        context.desktop = response.value("desktop", "");
        context.sessionType = response.value("session_type", "");
        context.display = response.value("display", "");
        context.waylandDisplay = response.value("wayland_display", "");
    } catch (const std::exception& exception) {
        error = "invalid session agent response: " + std::string(exception.what());
        return false;
    }

    if (context.sessionId != session.id ||
        (!context.sessionType.empty() && context.sessionType != session.type)) {
        error = "session agent context does not match the logind session";
        return false;
    }
    return true;
}
