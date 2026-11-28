// Regression tests for the static-inventory publication watch.
//
// A publication is processed ONCE, and only after every static check of that
// pass actually ran: a temporary database error must leave it pending so the
// daemon retries it, while a delivery failure is a separate retry obligation
// owned by the incident retry flags.
#include "daemon/StaticProofWatch.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

} // namespace

int main() {
    using fic::device_control::StaticProofWatch;

    // The first publication is pending; after a successful pass it is not.
    {
        StaticProofWatch watch;
        const std::string key = "boot-a|111|1700000000000000000";
        require(watch.pending(key), "a new publication must be processed");
        watch.markProcessed(key);
        require(!watch.pending(key),
                "a processed publication must not be processed again");
        require(watch.processedKey() == key,
                "the watch must remember the processed publication");
    }

    // A temporary database error must NOT mark the publication processed: the
    // same publication stays pending for the bounded retry.
    {
        StaticProofWatch watch;
        const std::string key = "boot-a|111|1700000000000000000";
        // The pass failed: no markProcessed() call.
        require(watch.pending(key),
                "a failed pass must keep the publication pending");
        require(watch.pending(key),
                "the publication must still be pending on the next tick");
        // The retry succeeded this time.
        watch.markProcessed(key);
        require(!watch.pending(key), "the successful retry must close it");
    }

    // A REPEATED publication with identical subsystem flags of the same boot is
    // a new publication (different stamp) and is processed again.
    {
        StaticProofWatch watch;
        const std::string first = "boot-a|111|1700000000000000000";
        const std::string second = "boot-a|111|1700000000000001000";
        require(first != second,
                "the publication stamp must distinguish two publications");
        watch.markProcessed(first);
        require(watch.pending(second),
                "a re-publication with the same flags must be processed again");
        watch.markProcessed(second);
        require(!watch.pending(second), "the new publication is now processed");
    }

    // An unavailable proof is its own state and is re-examined when it appears.
    {
        StaticProofWatch watch;
        const std::string absent = "unproven";
        watch.markProcessed(absent);
        require(!watch.pending(absent), "an absent proof must not loop");
        require(watch.pending("boot-a|111|1700000000000000000"),
                "the proof appearing later must be processed");
    }

    std::cout << "Static inventory proof watch contract proven\n";
    return 0;
}
