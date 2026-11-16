#pragma once
#include "PreLoginController.h"
#include <ostream>

namespace fic::prelogin {
// Broker-local suppression state; the observer already bounds and sanitizes errors.
class PreLoginObservationLog {
public:
    explicit PreLoginObservationLog(std::ostream& output) : output_(output) {}
    void record(const SystemdStatus& status) {
        if (status.available) { lastError_.clear(); return; }
        if (status.error.empty() || status.error == lastError_) return;
        output_ << "fic-prelogin broker: " << status.error << '\n' << std::flush;
        lastError_ = status.error;
    }
private:
    std::ostream& output_;
    std::string lastError_;
};
}
