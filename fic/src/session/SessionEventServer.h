#ifndef FIC_SESSION_EVENT_SERVER_H
#define FIC_SESSION_EVENT_SERVER_H

#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"

#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <sys/types.h>

class SessionEventServer {
public:
    using Validator = std::function<bool(
        uid_t, const std::string&, ClassifiedGraphicalSession&, std::string&)>;
    using Reconciler = std::function<void(const ClassifiedGraphicalSession&)>;

    SessionEventServer(int serverFd, Validator validator, Reconciler reconciler);
    bool pollOnce(int timeoutMilliseconds, std::string& error);
    void processOne();
    std::size_t pendingCount() const { return pending_.size(); }

private:
    static constexpr std::size_t MaxRequestBytes = 4096;
    static constexpr std::size_t MaxPending = 128;
    int serverFd_;
    Validator validator_;
    Reconciler reconciler_;
    std::deque<ClassifiedGraphicalSession> pending_;
    std::map<std::string, std::chrono::steady_clock::time_point> pendingOrRecent_;
    std::set<std::string> pendingKeys_;
};

#endif
