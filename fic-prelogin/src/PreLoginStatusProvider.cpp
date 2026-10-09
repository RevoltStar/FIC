#include "PreLoginStatusProvider.h"
namespace fic::prelogin {
PreLoginStatusProvider::PreLoginStatusProvider()
    : client_(ipc::path_defaults::DAEMON_SOCKET, std::chrono::milliseconds(250), 0) {}
PreLoginStatusProvider::PreLoginStatusProvider(std::string path, uid_t uid)
    : client_(std::move(path), std::chrono::milliseconds(250), uid) {}
Observation PreLoginStatusProvider::read() {
    Observation observation;
    const auto response = client_.requestWithStatus({{"command", "prelogin_status"}});
    observation.systemd = systemd_.observe();
    ipc::PreLoginStatus status;
    if (!response.hasResponse) observation.error = response.error;
    else if (!ipc::parsePreLoginStatus(response.response, status, observation.error)) {}
    else if (status.daemonPid != response.peerPid ||
             (observation.systemd.available && observation.systemd.pid != static_cast<unsigned int>(status.daemonPid)))
        observation.error = "daemon instance changed or disagrees with kernel/systemd peer identity";
    else observation.verified = std::move(status);
    return observation;
}
}
