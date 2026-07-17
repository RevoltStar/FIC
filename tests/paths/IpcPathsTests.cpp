#include <fic/ipc/FicIpcClient.h>

#include <cassert>
#include <cstdlib>
#include <string>

int main() {
    using fic::ipc::Endpoint;
    using fic::ipc::endpoint_socket_path;

    unsetenv("FIC_SOCKET_PATH");
    unsetenv("FIC_DEVICE_SOCKET_PATH");
    assert(endpoint_socket_path(Endpoint::PolicyDaemon) == fic::ipc::DEFAULT_SOCKET_PATH);
    assert(endpoint_socket_path(Endpoint::DeviceDaemon) == fic::ipc::DEFAULT_DEVICE_SOCKET_PATH);

    setenv("FIC_SOCKET_PATH", "/tmp/fic-policy-test.sock", 1);
    setenv("FIC_DEVICE_SOCKET_PATH", "/tmp/fic-device-test.sock", 1);
    assert(endpoint_socket_path(Endpoint::PolicyDaemon) == "/tmp/fic-policy-test.sock");
    assert(endpoint_socket_path(Endpoint::DeviceDaemon) == "/tmp/fic-device-test.sock");
    return 0;
}
