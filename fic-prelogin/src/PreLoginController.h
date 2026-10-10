#pragma once
#include <fic/ipc/FicReadinessStatus.h>
#include <optional>
#include <chrono>
#include <functional>

namespace fic::prelogin {
enum class UiState { Waiting, Starting, Applying, Succeeded, Failed, Degraded, Unavailable, Handoff, PowerAction };
enum class Action { Handoff, Reboot, PowerOff };
struct SystemdStatus {
    bool available = false;
    unsigned int pid = 0;
    std::string active, sub, text;
};
struct Observation {
    std::optional<ipc::PreLoginStatus> verified;
    SystemdStatus systemd;
    std::string error;
};
class StatusProvider {
public:
    virtual ~StatusProvider() = default;
    virtual Observation read() = 0;
};
class GuiLifecycle {
public:
    virtual ~GuiLifecycle() = default;
    virtual bool readyForHandoff() const { return true; }
    // Stop polling/rendering/input and prove resource release. Parent of a
    // graphics process must reap it, not merely acknowledge window closing.
    virtual bool cleanup(std::string& error) = 0;
};
class PowerController {
public:
    virtual ~PowerController() = default;
    virtual bool execute(Action action, std::string& error) = 0;
};
class PreLoginController {
public:
    PreLoginController(StatusProvider& status, GuiLifecycle& gui, PowerController& power,
                       std::string bootId,
                       std::function<std::chrono::steady_clock::time_point()> now = std::chrono::steady_clock::now);
    void poll();
    void request(Action action);
    UiState state() const { return state_; }
    const Observation& observation() const { return observation_; }
    std::optional<int> countdownSeconds() const { return countdownSeconds_; }
    bool finished() const { return finished_; }
    int exitCode() const { return exitCode_; }
    const std::string& error() const { return error_; }
private:
    StatusProvider& status_;
    GuiLifecycle& gui_;
    PowerController& power_;
    std::string bootId_, error_;
    Observation observation_;
    std::function<std::chrono::steady_clock::time_point()> now_;
    std::optional<std::chrono::steady_clock::time_point> countdownStarted_;
    std::optional<int> countdownSeconds_;
    pid_t countdownDaemon_ = 0;
    UiState state_ = UiState::Waiting;
    bool requested_ = false, finished_ = false;
    int exitCode_ = 1;
};
const char* uiStateToken(UiState state);
}
