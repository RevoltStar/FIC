#ifndef FIC_DAEMON_PERIODIC_APPLY_SCHEDULE_H
#define FIC_DAEMON_PERIODIC_APPLY_SCHEDULE_H

#include <chrono>
#include <optional>

namespace fic::daemon {
// Single-threaded, start-based schedule. Startup/manual passes never call finished().
class PeriodicApplySchedule {
public:
    using Clock = std::chrono::steady_clock;
    using Time = Clock::time_point;
    PeriodicApplySchedule(Time initialized, std::chrono::seconds interval,
                          std::chrono::seconds pause)
        : interval_(interval), pause_(pause), deadline_(initialized + interval) {}
    bool due(Time now) const {
        return now >= deadline_ && (!finished_ || now >= *finished_ + pause_);
    }
    // Also used for refused preflight: retain existing start-based postponement.
    void attempted(Time start) { deadline_ = start + interval_; }
    void finished(Time finish) { finished_ = finish; }
private:
    const std::chrono::seconds interval_;
    const std::chrono::seconds pause_;
    Time deadline_;
    std::optional<Time> finished_;
};
} // namespace fic::daemon
#endif
