#pragma once
#include <chrono>
#include <functional>
#include <string>

namespace fic::daemon {
enum class DeviceStartupState { Ready, TimedOut, Stopped };
struct DeviceStartupReadiness {
    DeviceStartupState state = DeviceStartupState::TimedOut;
    std::string diagnostic;
    std::chrono::milliseconds elapsed{0};
    bool ready() const { return state == DeviceStartupState::Ready; }
};
// Read-only administrative status, not an inventory or incident-delivery proof.
// Sixty seconds admits the measured 45s initialization and leaves most of the
// unchanged 600s unit budget for early protection and actual policy application.
DeviceStartupReadiness waitForDeviceStartup(
    const std::function<bool()>& stopping,
    std::chrono::milliseconds budget = std::chrono::seconds(60));
}
