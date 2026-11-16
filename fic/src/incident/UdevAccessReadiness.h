#pragma once

#include "platform/PlatformExecutableResolver.h"
#include <fic/core/process/ProcessExecutor.h>
#include <fic/ipc/FicReadinessStatus.h>
#include <chrono>
#include <functional>
#include <optional>

namespace fic::incident {

// Daemon-thread-only, bounded observation of the control interface. This is
// neither device enforcement nor a proof that workers/rules/queues completed.
class UdevAccessReadiness {
public:
    using Clock = std::chrono::steady_clock;
    using Runner = std::function<ProcessResult(const std::string&,
        const std::vector<std::string>&, const ProcessOptions&)>;
    using Now = std::function<Clock::time_point()>;
    explicit UdevAccessReadiness(Runner runner = {}, Now now = {});
    fic::ipc::AccessGateStatus apply(fic::ipc::AccessGateStatus status,
        const platform::PlatformExecutableResolver& executables);
    const std::string& diagnostic() const { return diagnostic_; }
private:
    Runner runner_;
    Now now_;
    std::optional<Clock::time_point> checkedAt_;
    bool ready_ = false;
    std::string diagnostic_;
};
}
