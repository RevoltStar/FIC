#include "PreLoginController.h"
#include "PreLoginStatusProvider.h"
#ifdef FIC_PRELOGIN_GRAPHICS
#include "FrontendProcess.h"
#endif
#include <fic/core/runtime/SystemBootInfo.h>
#include <fic/version/BuildInfo.h>
#include <fic/version/ProductVersion.h>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <linux/vt.h>
#include <linux/kd.h>
#include <termios.h>
#include <chrono>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace fic::prelogin {
namespace {
volatile sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
class ConsoleLifecycle final : public GuiLifecycle {
public:
    ConsoleLifecycle() {
      try {
        const char* tty = ::ttyname(STDIN_FILENO);
        if (::geteuid() != 0 || !tty || std::string(tty) != "/dev/tty7")
            throw std::runtime_error("prelogin requires the root system service on /dev/tty7");
        descriptor_ = ::open("/dev/tty0", O_RDWR | O_CLOEXEC | O_NOCTTY);
        vt_stat state{};
        if (descriptor_ < 0 || ::ioctl(descriptor_, VT_GETSTATE, &state) < 0)
            throw std::runtime_error("cannot inspect current VT; recovery TTY remains available");
        previous_ = state.v_active;
        if (::tcgetattr(STDIN_FILENO, &terminal_) != 0 || ::ioctl(STDIN_FILENO, KDGETMODE, &displayMode_) != 0 ||
            ::ioctl(STDIN_FILENO, KDGKBMODE, &keyboardMode_) != 0 ||
            ::ioctl(STDIN_FILENO, VT_GETMODE, &vtMode_) != 0 || vtMode_.mode != VT_AUTO)
            throw std::runtime_error("cannot preserve prelogin terminal state");
        terminalSaved_ = true;
        activated_ = true;
        if (::ioctl(descriptor_, VT_ACTIVATE, 7) < 0 || ::ioctl(descriptor_, VT_WAITACTIVE, 7) < 0)
            throw std::runtime_error("cannot activate prelogin VT");
        output_ = ::open("/dev/tty", O_WRONLY | O_CLOEXEC | O_NOCTTY);
        if (output_ < 0) throw std::runtime_error("cannot open prelogin console output");
      } catch (...) { std::string ignored; cleanup(ignored); throw; }
    }
    ~ConsoleLifecycle() { std::string error; cleanup(error); }
    void render(const PreLoginController& controller) {
        std::string text = std::string("FIC SECURITY — ") + uiStateToken(controller.state()) + "\n";
        const auto& observation = controller.observation();
        if (observation.verified) {
            const auto& s = *observation.verified;
            text += s.access.state + " / " + s.access.mode + " / " + s.access.severity + "\n" + s.diagnostic;
        } else text += observation.systemd.text + "\n" + observation.error;
        if (const auto seconds = controller.countdownSeconds())
            text += "\nПереход к системному DE через " + std::to_string(*seconds) + " секунд...";
        text += "\nПерейти к системному DM: Enter или handoff\nПерезагрузить: reboot; выключить: poweroff\n";
        if (text != last_) {
            last_ = text;
            (void)::write(output_, text.data(), text.size());
            std::cout << text << std::flush;
        }
    }
    bool recoverConsole(std::string& error) {
        const bool ok = terminalSaved_ && ::tcsetattr(STDIN_FILENO, TCSANOW, &terminal_) == 0 &&
            ::ioctl(STDIN_FILENO, KDSKBMODE, keyboardMode_) == 0 &&
            ::ioctl(STDIN_FILENO, VT_SETMODE, &vtMode_) == 0 &&
            ::ioctl(STDIN_FILENO, KDSETMODE, KD_TEXT) == 0 && ::ioctl(descriptor_, VT_ACTIVATE, 7) == 0 &&
            ::ioctl(descriptor_, VT_WAITACTIVE, 7) == 0;
        last_.clear();
        if (!ok) error = "cannot restore interactive console fallback";
        return ok;
    }
    bool cleanup(std::string& error) override {
        if (descriptor_ < 0) return true;
        if (output_ >= 0) { ::close(output_); output_ = -1; }
        const bool terminalRestored = !terminalSaved_ ||
            (::tcsetattr(STDIN_FILENO, TCSANOW, &terminal_) == 0 &&
             ::ioctl(STDIN_FILENO, KDSKBMODE, keyboardMode_) == 0 &&
             ::ioctl(STDIN_FILENO, VT_SETMODE, &vtMode_) == 0 &&
             ::ioctl(STDIN_FILENO, KDSETMODE, displayMode_) == 0);
        const bool restored = terminalRestored && (!activated_ || (::ioctl(descriptor_, VT_ACTIVATE, previous_) == 0 &&
            ::ioctl(descriptor_, VT_WAITACTIVE, previous_) == 0));
        ::close(descriptor_); descriptor_ = -1;
        if (!restored) error = "prelogin VT release could not be proven";
        return restored;
    }
private:
    int descriptor_ = -1, output_ = -1;
    termios terminal_{};
    int displayMode_ = KD_TEXT, keyboardMode_ = 0;
    vt_mode vtMode_{};
    bool terminalSaved_ = false, activated_ = false;
    unsigned short previous_ = 1;
    std::string last_;
};
}
}
int main(int argc, char** argv) {
    using namespace fic::prelogin;
    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "fic-prelogin " << fic::version::PRODUCT_VERSION << "\n"; return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--build-info") {
        fic::version::writeBuildInfo(std::cout, "fic-prelogin"); return 0;
    }
    if (argc != 1 && !(argc == 2 && std::string(argv[1]) == "--console")) return 2;
    ::clearenv(); ::setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1); ::setenv("LANG", "C.UTF-8", 1);
    ::signal(SIGTERM, stop); ::signal(SIGINT, stop);
    try {
        ConsoleLifecycle console;
#ifdef FIC_PRELOGIN_GRAPHICS
        FrontendProcess graphics;
        bool graphical = argc == 1;
        class CombinedLifecycle final : public GuiLifecycle {
        public:
            CombinedLifecycle(FrontendProcess& graphics, ConsoleLifecycle& console, bool& graphical)
                : graphics_(graphics), console_(console), graphical_(graphical) {}
            bool readyForHandoff() const override { return !graphical_ || graphics_.ready(); }
            bool cleanup(std::string& error) override {
                std::string terminalError;
                const bool renderer = graphics_.cleanup(error);
                const bool terminal = console_.cleanup(terminalError);
                if (!terminal) error += "; " + terminalError;
                return renderer && terminal && PreLoginSystemdIntegration::proveBrokerOnly(error);
            }
        private:
            FrontendProcess& graphics_; ConsoleLifecycle& console_; bool& graphical_;
        } gui(graphics, console, graphical);
        std::string graphicsError;
        if (graphical && !graphics.start(graphicsError)) {
            std::cerr << graphicsError << "; using interactive console fallback\n";
            graphical = false;
        }
        const auto graphicsStarted = std::chrono::steady_clock::now();
#else
        auto& gui = console;
#endif
        PreLoginStatusProvider provider;
        PreLoginPowerController power;
        PreLoginController controller(provider, gui, power, SystemBootInfo::get_boot_id());
        std::string input;
        while (!controller.finished() && !stopping) {
#ifdef FIC_PRELOGIN_GRAPHICS
            if (graphical) {
                const auto action = graphics.action();
                if (action) controller.request(*action);
                if (controller.finished()) break;
                if (!graphics.running() || (!graphics.ready() && std::chrono::steady_clock::now() - graphicsStarted > std::chrono::seconds(15))) {
                    graphics.cleanup(graphicsError);
                    std::cerr << "Qt EGLFS/KMS unavailable: " << graphicsError << "; interactive console fallback\n";
                    graphical = false;
                    if (!console.recoverConsole(graphicsError)) throw std::runtime_error(graphicsError);
                }
            }
#endif
            controller.poll();
            if (controller.finished()) break;
#ifdef FIC_PRELOGIN_GRAPHICS
            if (graphical) {
                graphics.render(controller);
                ::poll(nullptr, 0, 100);
                continue;
            }
#endif
            console.render(controller);
            pollfd descriptor{STDIN_FILENO, POLLIN, 0};
            if (::poll(&descriptor, 1, 1000) > 0 && (descriptor.revents & POLLIN)) {
                char ch;
                if (::read(STDIN_FILENO, &ch, 1) != 1) throw std::runtime_error("console input lost");
                if (ch == '\n') {
                    if (input.empty() || input == "handoff") controller.request(Action::Handoff);
                    else if (input == "reboot") controller.request(Action::Reboot);
                    else if (input == "poweroff") controller.request(Action::PowerOff);
                    input.clear();
                } else if (input.size() < 32) input += ch;
            }
        }
        if (stopping) { std::string error; gui.cleanup(error); return 1; }
        if (!controller.error().empty()) std::cerr << controller.error() << '\n';
        return controller.exitCode();
    } catch (const std::exception& e) {
        std::cerr << "FIC prelogin failed; use recovery TTY: " << e.what() << '\n'; return 1;
    }
}
