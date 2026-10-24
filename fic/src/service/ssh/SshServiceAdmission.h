#pragma once
#include <string>
#include <chrono>
#include <deque>
#include <cstdint>
namespace fic::service::ssh::detail {
enum class ServiceAdmission { Ready, Wait };
// Enablement/launch proof is separate. Only an already pending lifecycle can
// wait; this classifier never starts, enables or repairs a service.
ServiceAdmission classifyServiceAdmission(const std::string& active,
    const std::string& substate,const std::string& job);
// Conservative rolling budget: wait out unknown attempts once, then account
// for this process's attempts. External privileged restarts remain interference,
// not something this local ledger can prohibit or silently repair.
class RestartBudget {
    using Clock=std::chrono::steady_clock;
    std::chrono::microseconds interval_{0};
    std::uint64_t burst_=0;
    bool initialized_=false;
    Clock::time_point initialUntil_{};
    std::deque<Clock::time_point> attempts_;
public:
    Clock::time_point availableAt(Clock::time_point now, std::chrono::microseconds interval, std::uint64_t burst) {
        if(!initialized_||interval_!=interval||burst_!=burst) {
            initialized_=true;interval_=interval;burst_=burst;attempts_.clear();initialUntil_=now+interval;
        }
        if(interval.count()==0) return now;
        while(!attempts_.empty()&&attempts_.front()+interval<=now) attempts_.pop_front();
        if(now<initialUntil_) return initialUntil_;
        if(attempts_.size()>=burst) return attempts_.front()+interval;
        return now;
    }
    void record(Clock::time_point now) { if(interval_.count()!=0) attempts_.push_back(now); }
};
// Production loop; injected observation/wait keeps transition tests deterministic.
// Wait must enforce its deadline. Preflight independently re-proves ready state.
template<class Current, class Preflight, class Validate, class Wait>
auto awaitServiceAdmission(Current current, Preflight preflight, Validate validate, Wait wait) {
    while (true) {
        const auto state=current(); validate(state);
        if(classifyServiceAdmission(state.at("ActiveState"),state.at("SubState"),state.at("Job"))==ServiceAdmission::Ready) break;
        wait();
    }
    auto ready=preflight(); validate(ready); return ready;
}
}
