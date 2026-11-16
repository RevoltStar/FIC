#include "PreLoginStatusProvider.h"
namespace fic::prelogin {
PreLoginStatusProvider::PreLoginStatusProvider()
    : client_(ipc::path_defaults::DAEMON_SOCKET, std::chrono::milliseconds(250), 0) {}
PreLoginStatusProvider::PreLoginStatusProvider(std::string path, uid_t uid,
    PreLoginSystemdIntegration::OpenBus openBus)
    : client_(std::move(path), std::chrono::milliseconds(250), uid), systemd_(std::move(openBus)) {}
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
    // Keep the systemd failure first: an absent startup IPC socket must not
    // obscure why the fallback observer could not establish current state.
    if (!observation.verified && !observation.systemd.error.empty()) {
        observation.error = observation.systemd.error +
            (observation.error.empty() ? "" : "\nIPC: " + observation.error.substr(0, 2048));
    }
    return observation;
}
}
