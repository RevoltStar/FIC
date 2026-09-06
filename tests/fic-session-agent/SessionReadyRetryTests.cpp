#include "SessionReadyRetry.h"

#include <chrono>
#include <stdexcept>
#include <vector>

int main() {
    int attempts = 0;
    std::vector<std::chrono::milliseconds> delays;
    const bool delivered = fic::session_agent::retrySessionReady(
        [&]() { return ++attempts == 3; },
        []() { return false; },
        [&](std::chrono::milliseconds delay) { delays.push_back(delay); });
    if (!delivered || attempts != 3 ||
        delays != std::vector<std::chrono::milliseconds>{
            std::chrono::milliseconds(250), std::chrono::milliseconds(500)}) {
        throw std::runtime_error("daemon-unavailable retry contract failed");
    }
    return 0;
}
