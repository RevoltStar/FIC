#ifndef FIC_DICK_DAEMON_BLOCK_FAILURE_OBLIGATION_H
#define FIC_DICK_DAEMON_BLOCK_FAILURE_OBLIGATION_H

#include "daemon/PermanentDeviceIncident.h"

#include <algorithm>
#include <cstddef>
#include <set>
#include <vector>

namespace fic::device_control {

// The in-memory delivery obligation for failed dynamic blocks.
//
// A failed block is an ESTABLISHED fact that cannot be re-derived from the
// inventory (reconciliation never re-attempts enforcement), so the device
// daemon keeps the obligations until the main daemon acknowledges the event.
//
// The container is deliberately MERGE-only: a new violation must never replace
// a violation that is still undelivered. Delivery closes exactly the
// obligations that were carried by the acknowledged event, and a successful
// event of another kind never touches this container.
//
// The list is bounded by the detector-event payload: the sender truncates the
// id list while `device_ids_total` stays truthful, and the security-relevant
// content of the aggregated event is the FACT of a failed block, not the
// complete id list.
inline constexpr std::size_t MAX_PENDING_BLOCK_FAILURES = MAX_DEVICE_INCIDENT_IDS;

// Identity of one obligation: the device occurrence id when it is known,
// otherwise the managed DEVPATH of the live device that could not be
// restricted. Never a synthetic id.
inline std::string blockFailureKey(const PermanentViolation& violation) {
    if (violation.deviceId > 0) {
        return "id:" + std::to_string(violation.deviceId);
    }
    return "path:" + violation.devpath;
}

class BlockFailureObligation {
public:
    // Merges `violations` into the pending set. Returns true when at least one
    // NEW obligation was added.
    bool remember(const std::vector<PermanentViolation>& violations) {
        bool added = false;
        for (const PermanentViolation& violation : violations) {
            const std::string key = blockFailureKey(violation);
            if (key == "path:" || key == "id:") {
                continue;
            }
            const bool known = std::any_of(
                pending_.begin(), pending_.end(),
                [&key](const PermanentViolation& pending) {
                    return blockFailureKey(pending) == key;
                });
            if (known) {
                continue;
            }
            if (pending_.size() >= MAX_PENDING_BLOCK_FAILURES) {
                // The payload is bounded: further occurrences are still part of
                // the same aggregated fact and are delivered with the next
                // event, so the obligation is not lost as a fact.
                continue;
            }
            pending_.push_back(violation);
            added = true;
        }
        return added;
    }

    // The obligations a delivery attempt must carry.
    std::vector<PermanentViolation> snapshot() const { return pending_; }

    // Closes exactly the acknowledged obligations. Returns how many were
    // removed.
    std::size_t acknowledge(const std::vector<PermanentViolation>& delivered) {
        std::set<std::string> deliveredKeys;
        for (const PermanentViolation& violation : delivered) {
            deliveredKeys.insert(blockFailureKey(violation));
        }
        const std::size_t before = pending_.size();
        pending_.erase(
            std::remove_if(pending_.begin(), pending_.end(),
                           [&deliveredKeys](const PermanentViolation& pending) {
                               return deliveredKeys.count(
                                          blockFailureKey(pending)) > 0;
                           }),
            pending_.end());
        return before - pending_.size();
    }

    bool empty() const { return pending_.empty(); }
    std::size_t size() const { return pending_.size(); }
    void clear() { pending_.clear(); }

private:
    std::vector<PermanentViolation> pending_;
};

} // namespace fic::device_control

#endif // FIC_DICK_DAEMON_BLOCK_FAILURE_OBLIGATION_H
