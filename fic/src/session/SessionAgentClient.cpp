#include "session/SessionAgentClient.h"
#include "session/SessionAgentClientInternal.h"

#include <fic/ipc/FicIpcClient.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
constexpr auto SESSION_AGENT_READINESS_TIMEOUT = std::chrono::seconds(10);
constexpr auto SESSION_AGENT_RETRY_INTERVAL = std::chrono::milliseconds(200);

enum class SocketVerification { Ready, Retryable, Fatal };

SocketVerification verify_socket(
    const std::string& path,
    uid_t expectedUid,
    std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        const int errorNumber = errno;
        if (errorNumber == ENOENT) {
            error = "session agent socket is unavailable: " + path;
            return SocketVerification::Retryable;
        }
        error = "could not inspect session agent socket " + path + ": " +
            std::strerror(errorNumber);
        return SocketVerification::Fatal;
    }
    if (!S_ISSOCK(info.st_mode) || info.st_uid != expectedUid) {
        error = "session agent socket has invalid type or owner: " + path;
        return SocketVerification::Fatal;
    }
    return SocketVerification::Ready;
}

bool wait_before_retry(
    const std::chrono::steady_clock::time_point& deadline,
    std::chrono::milliseconds retryInterval) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return false;
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
    std::this_thread::sleep_for(std::min(retryInterval, remaining));
    return true;
}

int connect_when_ready(
    const UserSession& session,
    const std::string& path,
    std::chrono::milliseconds readinessTimeout,
    std::chrono::milliseconds retryInterval,
    std::string& error) {
    if (path.size() >= sizeof(sockaddr_un::sun_path)) {
        error = "session agent socket path is too long";
        return -1;
    }
    if (readinessTimeout.count() < 0 || retryInterval.count() <= 0) {
        error = "invalid session agent readiness timing";
        return -1;
    }

    const auto deadline = std::chrono::steady_clock::now() + readinessTimeout;
    for (;;) {
        const SocketVerification verification =
            verify_socket(path, session.uid, error);
        if (verification == SocketVerification::Fatal) {
            return -1;
        }
        if (verification == SocketVerification::Ready) {
            const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) {
                error = "socket() failed: " + std::string(std::strerror(errno));
                return -1;
            }

            timeval timeout {};
            timeout.tv_sec = 2;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            sockaddr_un address {};
            address.sun_family = AF_UNIX;
            std::strncpy(
                address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
            if (::connect(
                    fd,
                    reinterpret_cast<sockaddr*>(&address),
                    sizeof(address)) == 0) {
                return fd;
            }

            const int errorNumber = errno;
            ::close(fd);
            error = "connect(" + path + ") failed: " +
                std::strerror(errorNumber);
            if (errorNumber != ENOENT && errorNumber != ECONNREFUSED) {
                return -1;
            }
        }

        if (!wait_before_retry(deadline, retryInterval)) {
            return -1;
        }
    }
}
} // namespace

bool session_agent_client_detail::safeEndpointPresent(
    const std::string& path,
    uid_t expectedUid) {
    struct stat info {};
    return ::lstat(path.c_str(), &info) == 0 &&
        S_ISSOCK(info.st_mode) && info.st_uid == expectedUid;
}

bool session_agent_client_detail::validateContextIdentity(
    const UserSession& session,
    const SessionContext& context,
    std::string& error)
{
    if (context.sessionId != session.id) {
        error = "session agent context does not match the logind session";
        return false;
    }

    if (session.type == "tty") {
        const bool graphicalContext =
            (context.sessionType == "wayland" &&
             !context.waylandDisplay.empty()) ||
            (context.sessionType == "x11" && !context.display.empty());
        if (!graphicalContext) {
            error = "TTY logind session does not have a consistent graphical "
                "session agent context";
            return false;
        }
    } else if (context.sessionType != session.type ||
               (context.sessionType == "wayland" &&
                context.waylandDisplay.empty()) ||
               ((context.sessionType == "x11" ||
                 context.sessionType == "mir") && context.display.empty())) {
        error = "session agent context does not match the logind session";
        return false;
    }

    error.clear();
    return true;
}

std::string SessionAgentClient::socketPath(const UserSession& session) {
    return "/run/user/" + std::to_string(session.uid) + "/fic/session-" + session.id + ".sock";
}

bool SessionAgentClient::query(const UserSession& session, SessionContext& context, std::string& error) {
    const std::string path = socketPath(session);
    return session_agent_client_detail::queryAtPath(
        session,
        path,
        SESSION_AGENT_READINESS_TIMEOUT,
        SESSION_AGENT_RETRY_INTERVAL,
        context,
        error);
}

bool session_agent_client_detail::queryAtPath(
    const UserSession& session,
    const std::string& path,
    std::chrono::milliseconds readinessTimeout,
    std::chrono::milliseconds retryInterval,
    SessionContext& context,
    std::string& error) {
    const int fd = connect_when_ready(
        session, path, readinessTimeout, retryInterval, error);
    if (fd < 0) {
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

    return validateContextIdentity(session, context, error);
}
