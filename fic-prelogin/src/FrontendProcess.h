#pragma once
#include "PreLoginController.h"
#include <sys/types.h>
#include <optional>
namespace fic::prelogin {
// A long-lived renderer needs asynchronous status/actions and explicit reap;
// the synchronous, finite-command ProcessExecutor does not provide that lifecycle.
class FrontendProcess final : public GuiLifecycle {
public:
    FrontendProcess() = default;
    FrontendProcess(pid_t child, int channel); // Owned child/channel; test seam.
    ~FrontendProcess();
    FrontendProcess(const FrontendProcess&) = delete;
    FrontendProcess& operator=(const FrontendProcess&) = delete;
    bool start(std::string& error);
    bool running();
    bool ready() const { return ready_; }
    void render(const PreLoginController& controller);
    std::optional<Action> action();
    bool cleanup(std::string& error) override;
private:
    bool awaitExit(int milliseconds);
    void forceReap();
    pid_t child_ = -1;
    int channel_ = -1, status_ = -1;
    bool ready_ = false, protocolFailed_ = false;
};
}
