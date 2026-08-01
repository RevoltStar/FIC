#ifndef FIC_IPC_TRANSPORT_H
#define FIC_IPC_TRANSPORT_H

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>

namespace fic::ipc {

inline constexpr std::size_t MAX_REQUEST_BYTES = 64U * 1024U;
inline constexpr std::size_t MAX_RESPONSE_BYTES = 1024U * 1024U;
inline constexpr std::size_t RESPONSE_CHUNK_BYTES = 60U * 1024U;
inline constexpr std::size_t MAX_ADMIN_CONNECTIONS = 32U;
inline constexpr std::size_t MAX_JSON_DEPTH = 16U;
inline constexpr std::size_t MAX_JSON_STRING_BYTES = 16U * 1024U;
inline constexpr std::size_t MAX_JSON_CONTAINER_ITEMS = 4096U;
inline constexpr std::chrono::seconds FIRST_PACKET_TIMEOUT{2};
inline constexpr std::chrono::seconds RESPONSE_WRITE_TIMEOUT{5};
inline constexpr std::chrono::seconds DEFAULT_CLIENT_TIMEOUT{30};

using RequestHandler = std::function<std::string(int, const std::string&)>;

class AdminSocketTransport {
public:
    explicit AdminSocketTransport(int serverFd);
    ~AdminSocketTransport();

    AdminSocketTransport(const AdminSocketTransport&) = delete;
    AdminSocketTransport& operator=(const AdminSocketTransport&) = delete;

    // Polls the listener and connected clients once. At most one request is
    // dispatched to handler per call, keeping daemon-owned work serialized.
    bool pollOnce(int timeoutMilliseconds,
                  const RequestHandler& handler,
                  std::string& error);

    std::size_t connectionCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace fic::ipc

#endif // FIC_IPC_TRANSPORT_H
