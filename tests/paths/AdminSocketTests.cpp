#include <fic/ipc/FicAdminSocket.h>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-admin-socket-test-" + std::to_string(::getpid()));
    fs::remove_all(root);

    const fs::path socketPath = root / "runtime/admin.sock";
    auto result = fic::ipc::create_admin_server_socket({
        socketPath,
        fic::ipc::AdminSocketSecurityProfile::Development,
        4,
        "test socket"
    });
    if (result.fileDescriptor < 0) {
        std::cerr << result.error << '\n';
        if (result.error.find("Operation not permitted") != std::string::npos) {
            fs::remove_all(root);
            return 77;
        }
    }
    assert(result.fileDescriptor >= 0);

    struct stat info {};
    assert(::lstat(socketPath.c_str(), &info) == 0);
    assert(S_ISSOCK(info.st_mode));
    assert((info.st_mode & 0777) == 0600);
    assert(::lstat(socketPath.parent_path().c_str(), &info) == 0);
    assert((info.st_mode & 0777) == 0700);
    ::close(result.fileDescriptor);
    fs::remove(socketPath);

    fs::create_directories(socketPath.parent_path());
    std::ofstream(socketPath) << "do not replace";
    result = fic::ipc::create_admin_server_socket({
        socketPath,
        fic::ipc::AdminSocketSecurityProfile::Development,
        4,
        "test socket"
    });
    assert(result.fileDescriptor < 0);
    assert(fs::is_regular_file(socketPath));

    fs::remove_all(root);
    return 0;
}
