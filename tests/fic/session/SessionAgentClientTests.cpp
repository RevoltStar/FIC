#include "session/SessionAgentClientInternal.h"

#include <fic/ipc/FicIpcClient.h>

#include <chrono>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

namespace {
namespace fs = std::filesystem;
using namespace std::chrono_literals;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

int bindServer(const fs::path& path) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    require(fd >= 0, "could not create test server socket");

    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    const std::string encoded = path.string();
    require(encoded.size() < sizeof(address.sun_path),
            "test server socket path is too long");
    std::strncpy(
        address.sun_path, encoded.c_str(), sizeof(address.sun_path) - 1);
    ::unlink(encoded.c_str());
    if (::bind(
            fd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)) != 0) {
        const std::string error = std::strerror(errno);
        ::close(fd);
        throw std::runtime_error(
            "could not bind test server socket: " + error);
    }
    require(::listen(fd, 1) == 0, "could not listen on test server socket");
    return fd;
}

struct ServerResult {
    bool requestValid = false;
    std::string error;
};

std::thread startServerAfter(
    const fs::path& path,
    const UserSession& session,
    std::chrono::milliseconds delay,
    ServerResult& result,
    const std::string& responseSessionId = {},
    const std::string& responseSessionType = {},
    const std::string& display = {},
    const std::string& waylandDisplay = "wayland-0") {
    return std::thread([path, session, delay, &result, responseSessionId,
                        responseSessionType, display, waylandDisplay]() {
        try {
            std::this_thread::sleep_for(delay);
            const int serverFd = bindServer(path);
            timeval acceptTimeout {};
            acceptTimeout.tv_sec = 3;
            ::setsockopt(
                serverFd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &acceptTimeout,
                sizeof(acceptTimeout));
            const int clientFd = ::accept(serverFd, nullptr, nullptr);
            if (clientFd < 0) {
                ::close(serverFd);
                throw std::runtime_error("could not accept test client");
            }

            std::string requestText;
            std::string ipcError;
            if (!fic::ipc::read_until_eof(clientFd, requestText, ipcError)) {
                ::close(clientFd);
                ::close(serverFd);
                throw std::runtime_error(ipcError);
            }
            const auto request = fic::ipc::json::parse(requestText);
            result.requestValid =
                request.value("command", "") == "session_context";
            const fic::ipc::json response = {
                {"ok", true},
                {"message", "session context loaded"},
                {"session_id", responseSessionId.empty()
                    ? session.id : responseSessionId},
                {"desktop", "KDE"},
                {"session_type", responseSessionType.empty()
                    ? session.type : responseSessionType},
                {"display", display},
                {"wayland_display", waylandDisplay}
            };
            if (!fic::ipc::write_all(
                    clientFd, response.dump() + "\n", ipcError)) {
                ::close(clientFd);
                ::close(serverFd);
                throw std::runtime_error(ipcError);
            }
            ::close(clientFd);
            ::close(serverFd);
            ::unlink(path.c_str());
        } catch (const std::exception& exception) {
            result.error = exception.what();
        }
    });
}

UserSession testSession() {
    return {"test-session", ::getuid(), "test-user", "wayland"};
}

void testDelayedSocket(const fs::path& root) {
    const fs::path path = root / "delayed.sock";
    const UserSession session = testSession();
    ServerResult serverResult;
    std::thread server = startServerAfter(path, session, 100ms, serverResult);

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(ok, "delayed session agent was not accepted: " + error);
    require(serverResult.requestValid, "session context request is incorrect");
    require(context.sessionId == session.id && context.desktop == "KDE" &&
                context.sessionType == "wayland" &&
                context.waylandDisplay == "wayland-0",
            "delayed session context was parsed incorrectly");
}

void testRefusedSocketIsRetried(const fs::path& root) {
    const fs::path path = root / "refused.sock";
    const int staleFd = bindServer(path);
    ::close(staleFd);

    const UserSession session = testSession();
    ServerResult serverResult;
    std::thread server = startServerAfter(path, session, 100ms, serverResult);

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(ok, "refused session agent socket was not retried: " + error);
    require(serverResult.requestValid, "retried request is incorrect");
}

void testMissingSocketTimesOut(const fs::path& root) {
    const fs::path path = root / "missing.sock";
    const UserSession session = testSession();
    SessionContext context;
    std::string error;
    const auto started = std::chrono::steady_clock::now();
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 120ms, 20ms, context, error);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    require(!ok, "missing session agent unexpectedly succeeded");
    require(error.find("socket is unavailable") != std::string::npos,
            "missing session agent diagnostic is incorrect: " + error);
    require(elapsed >= 80ms && elapsed < 1s,
            "missing session agent did not use the bounded readiness timeout");
}

void testUnsafePathFailsImmediately(const fs::path& root) {
    const fs::path path = root / "unsafe.sock";
    std::ofstream(path) << "not a socket";

    const UserSession session = testSession();
    SessionContext context;
    std::string error;
    const auto started = std::chrono::steady_clock::now();
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    require(!ok, "unsafe session agent path unexpectedly succeeded");
    require(error.find("invalid type or owner") != std::string::npos,
            "unsafe session agent diagnostic is incorrect: " + error);
    require(elapsed < 500ms,
            "unsafe session agent path was retried instead of rejected");
}

void testDiscoveryRequiresOwnedSocket(const fs::path& root) {
    const fs::path regular = root / "endpoint-file";
    std::ofstream(regular) << "not a socket";
    require(!session_agent_client_detail::safeEndpointPresent(
                regular.string(), ::getuid()),
            "regular file was accepted as a discovery endpoint");

    const fs::path socket = root / "endpoint.sock";
    const int socketFd = bindServer(socket);
    require(session_agent_client_detail::safeEndpointPresent(
                socket.string(), ::getuid()),
            "owned socket was rejected as a discovery endpoint");
    require(!session_agent_client_detail::safeEndpointPresent(
                socket.string(), ::getuid() + 1),
            "socket owned by a different uid was accepted");

    const fs::path link = root / "endpoint-link";
    fs::create_symlink(socket.filename(), link);
    require(!session_agent_client_detail::safeEndpointPresent(
                link.string(), ::getuid()),
            "symlink was accepted as a discovery endpoint");
    ::close(socketFd);
    ::unlink(socket.c_str());
}

void testMismatchedSessionIdentityIsRejected(const fs::path& root) {
    const fs::path path = root / "mismatch.sock";
    const UserSession session = testSession();
    ServerResult serverResult;
    std::thread server = startServerAfter(
        path, session, 10ms, serverResult, "different-session");

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(!ok, "mismatched agent session identity was accepted");
    require(error.find("does not match the logind session") !=
                std::string::npos,
            "session mismatch diagnostic is incorrect: " + error);
}

void testStartxTtyGraphicalContextIsAccepted(const fs::path& root) {
    const fs::path path = root / "startx.sock";
    UserSession session = testSession();
    session.type = "tty";
    ServerResult serverResult;
    std::thread server = startServerAfter(
        path, session, 10ms, serverResult, {}, "x11", ":1", "");

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(ok, "valid startx context was rejected: " + error);
}

void testWaylandInTtyCanonicalContextIsAccepted(const fs::path& root) {
    const fs::path path = root / "startx-wayland.sock";
    UserSession session = testSession();
    session.type = "tty";
    ServerResult serverResult;
    std::thread server = startServerAfter(
        path, session, 10ms, serverResult, {}, "wayland", "", "wayland-1");

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(ok, "valid Wayland-in-TTY context was rejected: " + error);
}

void testRawTtyContextIsRejectedByDaemon(const fs::path& root) {
    const fs::path path = root / "raw-tty.sock";
    UserSession session = testSession();
    session.type = "tty";
    ServerResult serverResult;
    std::thread server = startServerAfter(
        path, session, 10ms, serverResult, {}, "tty", ":1", "");

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(!ok, "raw tty IPC context bypassed canonicalization contract");
}

void testContradictoryTtyContextIsRejected(const fs::path& root) {
    const fs::path path = root / "tty-mismatch.sock";
    UserSession session = testSession();
    session.type = "tty";
    ServerResult serverResult;
    std::thread server = startServerAfter(
        path, session, 10ms, serverResult, {}, "x11", "", "");

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(!ok, "TTY context without DISPLAY was accepted");
    require(error.find("consistent graphical") != std::string::npos,
            "TTY mismatch diagnostic is incorrect: " + error);
}

void testContradictoryNativeSessionTypeIsRejected(const fs::path& root) {
    const fs::path path = root / "native-type-mismatch.sock";
    const UserSession session = testSession();
    ServerResult serverResult;
    std::thread server = startServerAfter(
        path, session, 10ms, serverResult, {}, "x11", ":2", "");

    SessionContext context;
    std::string error;
    const bool ok = session_agent_client_detail::queryAtPath(
        session, path.string(), 2s, 20ms, context, error);
    server.join();

    require(serverResult.error.empty(), serverResult.error);
    require(!ok, "contradictory native session type was accepted");
    require(error.find("does not match the logind session") !=
                std::string::npos,
            "native session mismatch diagnostic is incorrect: " + error);
}
} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-session-agent-client-tests-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);

    try {
        const fs::path probePath = root / "probe.sock";
        const int probeFd = bindServer(probePath);
        ::close(probeFd);
        ::unlink(probePath.c_str());

        testDelayedSocket(root);
        testRefusedSocketIsRetried(root);
        testMissingSocketTimesOut(root);
        testUnsafePathFailsImmediately(root);
        testDiscoveryRequiresOwnedSocket(root);
        testMismatchedSessionIdentityIsRejected(root);
        testStartxTtyGraphicalContextIsAccepted(root);
        testWaylandInTtyCanonicalContextIsAccepted(root);
        testRawTtyContextIsRejectedByDaemon(root);
        testContradictoryTtyContextIsRejected(root);
        testContradictoryNativeSessionTypeIsRejected(root);
    } catch (const std::exception& exception) {
        fs::remove_all(root);
        if (std::string(exception.what()).find("Operation not permitted") !=
            std::string::npos) {
            return 77;
        }
        throw;
    }

    fs::remove_all(root);
    return 0;
}
