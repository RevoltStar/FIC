#include "daemon/DeviceStartupReadiness.h"
#include <fic/ipc/FicIpcClient.h>
#include <fic/version/ProductVersion.h>
#include <algorithm>
#include <thread>

namespace fic::daemon {
DeviceStartupReadiness waitForDeviceStartup(const std::function<bool()>& stopping,
                                           std::chrono::milliseconds budget) {
    using Clock = std::chrono::steady_clock;
    const auto start = Clock::now(), deadline = start + budget;
    const auto endpoint = fic::ipc::endpoint_socket_path(fic::ipc::Endpoint::DeviceDaemon);
    const auto result = [&](DeviceStartupState state, const std::string& message) {
        return DeviceStartupReadiness{state, message,
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-start)};
    };
    std::string last = "device status unavailable";
    while (Clock::now() < deadline) {
        if (stopping()) return result(DeviceStartupState::Stopped, "device IPC wait interrupted by shutdown");
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now());
        if (remaining.count() <= 0) break;
        // A bounded request also bounds shutdown latency; no new IPC transport.
        const auto response = fic::ipc::Client(endpoint,
            std::min(remaining, std::chrono::milliseconds(1000)), 0).requestWithStatus({{"command","status"}});
        if (stopping()) return result(DeviceStartupState::Stopped, "device IPC wait interrupted by shutdown");
        if (Clock::now() >= deadline) break;
        if (response.hasResponse) {
            const auto& value = response.response;
            if (value.is_object() && value.contains("ok") && value["ok"].is_boolean() &&
                value["ok"].get<bool>() && value.contains("message") && value["message"].is_string() &&
                value.contains("product_version") && value["product_version"].is_string() &&
                value["product_version"] == fic::version::PRODUCT_VERSION &&
                value.contains("database_schema_version") && value["database_schema_version"].is_number_integer() &&
                value["database_schema_version"] == fic::version::DEVICE_DB_SCHEMA_VERSION)
                return result(DeviceStartupState::Ready, "device administrative IPC is responsive and compatible");
            last = "device status is unsuccessful, malformed or version/schema incompatible";
        } else {
            // Do not copy untrusted response bodies (Client diagnostics may
            // contain raw JSON) into startup/audit output.
            last = "trusted device status response unavailable (transport/API/peer check failed)";
        }
        const auto pause = std::min(std::chrono::milliseconds(100),
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()));
        if (pause.count() > 0) std::this_thread::sleep_for(pause);
    }
    if (stopping()) return result(DeviceStartupState::Stopped, "device IPC wait interrupted by shutdown");
    return result(DeviceStartupState::TimedOut, "startup device IPC deadline exceeded: " + last);
}
}
