#ifndef FIC_DICK_DAEMON_STATIC_PROOF_WATCH_H
#define FIC_DICK_DAEMON_STATIC_PROOF_WATCH_H

#include <string>

namespace fic::device_control {

// Tracks which static-inventory publication was FULLY processed.
//
// A publication is marked processed only after every static check of that pass
// actually ran. A temporary database error therefore leaves the publication
// pending, so the daemon retries it instead of silently dropping it; the retry
// cadence is bounded by the caller's throttling.
//
// A delivery failure is NOT a processing failure: the established violation
// keeps its own incident retry obligation, and the publication itself was
// handled.
class StaticProofWatch {
public:
    bool pending(const std::string& key) const { return key != processedKey_; }

    void markProcessed(const std::string& key) { processedKey_ = key; }

    const std::string& processedKey() const { return processedKey_; }

    void reset() { processedKey_.clear(); }

private:
    std::string processedKey_;
};

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_STATIC_PROOF_WATCH_H
