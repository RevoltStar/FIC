#ifndef FIC_ADMIN_SOCKET_H
#define FIC_ADMIN_SOCKET_H

#include <filesystem>
#include <fic/ipc/FicIpcTransport.h>
#include <optional>
#include <string>
#include <sys/types.h>

namespace fic::ipc {

enum class AdminSocketSecurityProfile {
    ProductionAdmin,
    Development
};

struct AdminSocketOptions {
    std::filesystem::path socketPath;
    AdminSocketSecurityProfile security = AdminSocketSecurityProfile::ProductionAdmin;
    int backlog = 32;
    std::string label = "FIC administrative socket";
};

struct AdminSocketResult {
    int fileDescriptor = -1;
    std::optional<pid_t> existingPeerPid;
    std::string error;
};

AdminSocketResult create_admin_server_socket(const AdminSocketOptions& options);

} // namespace fic::ipc

#endif // FIC_ADMIN_SOCKET_H
