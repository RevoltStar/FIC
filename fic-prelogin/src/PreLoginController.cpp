#include "PreLoginController.h"

namespace fic::prelogin {
const char* uiStateToken(UiState state) {
    switch (state) {
        case UiState::Waiting: return "WAITING_FOR_DAEMON";
        case UiState::Starting: return "DAEMON_STARTING";
        case UiState::Applying: return "STARTUP_APPLYING";
        case UiState::Succeeded: return "STARTUP_SUCCEEDED";
        case UiState::Failed: return "STARTUP_FAILED";
        case UiState::Degraded: return "DAEMON_DEGRADED";
        case UiState::Unavailable: return "DAEMON_UNAVAILABLE";
        case UiState::Handoff: return "HANDOFF";
        case UiState::PowerAction: return "POWER_ACTION";
    }
    return "DAEMON_UNAVAILABLE";
}
PreLoginController::PreLoginController(StatusProvider& status, GuiLifecycle& gui,
    PowerController& power, std::string bootId)
    : status_(status), gui_(gui), power_(power), bootId_(std::move(bootId)) {}
void PreLoginController::poll() {
    if (requested_ || finished_) return;
    observation_ = status_.read();
    if (observation_.verified && observation_.verified->bootId != bootId_) {
        observation_.verified.reset();
        observation_.error = "daemon boot identity does not match the current kernel boot";
    }
    state_ = UiState::Unavailable;
    if (observation_.verified && observation_.verified->bootId == bootId_) {
        const auto& s = *observation_.verified;
        if (s.access.state == "DEGRADED") state_ = UiState::Degraded;
        else if (s.completed && !s.applyOk) state_ = UiState::Failed;
        else if (s.completed && s.applyOk) state_ = UiState::Succeeded;
        else if (s.started) state_ = UiState::Applying;
        else state_ = UiState::Starting;
        if (ipc::mayAutoHandoff(s, bootId_)) request(Action::Handoff);
    } else if (observation_.systemd.available) {
        const auto& s = observation_.systemd;
        if (s.active == "inactive") state_ = UiState::Waiting;
        else if (s.active == "activating") state_ = s.text == "Applying startup policies" ? UiState::Applying : UiState::Starting;
        // active/READY=1/StatusText never grant automatic handoff.
    }
}
void PreLoginController::request(Action action) {
    if (requested_ || finished_) return;
    requested_ = true;
    if (action != Action::Handoff && action != Action::Reboot && action != Action::PowerOff) {
        error_ = "unsupported local action"; finished_ = true; return;
    }
    state_ = action == Action::Handoff ? UiState::Handoff : UiState::PowerAction;
    if (!gui_.cleanup(error_)) { finished_ = true; return; }
    if (action != Action::Handoff && !power_.execute(action, error_)) { finished_ = true; return; }
    exitCode_ = 0;
    finished_ = true;
}
}
