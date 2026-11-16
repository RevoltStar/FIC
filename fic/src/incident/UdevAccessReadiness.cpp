#include "incident/UdevAccessReadiness.h"
#include <fic/core/process/VerifiedProcessExecutor.h>

namespace fic::incident {
UdevAccessReadiness::UdevAccessReadiness(Runner runner, Now now)
    : runner_(runner ? std::move(runner) : Runner(VerifiedProcessExecutor::execute)),
      now_(now ? std::move(now) : Now(Clock::now)) {}

fic::ipc::AccessGateStatus UdevAccessReadiness::apply(
    fic::ipc::AccessGateStatus status,
    const platform::PlatformExecutableResolver& executables) {
    if (status.mode != "ACTIVE") {
        checkedAt_.reset(); // A later ACTIVE transition needs its own fresh proof.
        ready_ = false;
        diagnostic_.clear();
    } else {
        const auto now = now_();
        // Age is measured from the START of the probe, not from process exit.
        if (!checkedAt_ || now < *checkedAt_ || now - *checkedAt_ >= std::chrono::seconds(2)) {
            checkedAt_ = now;
            ready_ = false;
            std::filesystem::path executable;
            std::string error;
            try {
                if (!executables.resolve(platform::ExecutableId::Udevadm, executable, error)) {
                    diagnostic_ = "udev control ping: udevadm unavailable: " + error;
                } else {
                    ProcessOptions options;
                    options.timeout = std::chrono::milliseconds(1250);
                    options.clearEnvironment = true;
                    options.environment = {{"LANG", "C"}, {"LC_ALL", "C"}};
                    options.maxOutputBytes = 4096;
                    const auto result = runner_(executable.string(),
                        {"control", "--ping", "--timeout=1"}, options);
                    ready_ = result.success();
                    diagnostic_ = ready_ ? "" : result.timedOut
                        ? "udev control ping: process deadline exceeded"
                        : !result.started ? "udev control ping: cannot execute verified udevadm: " + result.error
                        : result.outputLimitExceeded ? "udev control ping: output limit exceeded"
                        : "udev control ping: exit code " + std::to_string(result.exitCode);
                }
            } catch (const std::exception&) {
                diagnostic_ = "udev control ping: execution failed";
            }
        }
        // Never use an expired positive, even if a process returned unusually late.
        const auto observed = now_();
        const bool fresh = observed >= *checkedAt_ && observed - *checkedAt_ < std::chrono::seconds(2);
        if ((!ready_ || !fresh) && status.state == "READY") status.state = "DEGRADED";
        if (!fresh) diagnostic_ = "udev control ping: observation expired";
    }
    status.loginAllowed = fic::ipc::computedLoginAllowed(status);
    return status;
}
}
