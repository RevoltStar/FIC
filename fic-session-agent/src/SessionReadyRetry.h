#ifndef FIC_SESSION_READY_RETRY_H
#define FIC_SESSION_READY_RETRY_H

#include <algorithm>
#include <chrono>

namespace fic::session_agent {

template<typename Attempt, typename StopRequested, typename Wait>
bool retrySessionReady(Attempt attempt, StopRequested stopRequested, Wait wait)
{
    auto delay = std::chrono::milliseconds(250);
    while (!stopRequested()) {
        if (attempt()) return true;
        wait(delay);
        delay = std::min(delay * 2, std::chrono::milliseconds(30000));
    }
    return false;
}

} // namespace fic::session_agent

#endif
