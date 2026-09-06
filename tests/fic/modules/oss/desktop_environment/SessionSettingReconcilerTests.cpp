#include "modules/oss/desktop_environment/SessionSettingReconciler.h"

#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
}

int main() {
    std::string error;
    std::vector<std::string> calls;

    require(desktop_policy::reconcileEffectiveSetting(
                [&](bool& matches, std::string&) {
                    calls.push_back("read"); matches = true; return true;
                },
                [&](std::string&) {
                    calls.push_back("write"); return false;
                }, "mismatch", error),
            "already compliant state failed");
    require(calls == std::vector<std::string>{"read"},
            "already compliant state attempted mutation");

    calls.clear();
    require(!desktop_policy::reconcileEffectiveSetting(
                [&](bool&, std::string& value) {
                    calls.push_back("read"); value = "read failed"; return false;
                },
                [&](std::string&) { calls.push_back("write"); return true; },
                "mismatch", error),
            "unreadable state attempted blind convergence");
    require(calls == std::vector<std::string>{"read"},
            "read failure attempted mutation");

    calls.clear();
    int reads = 0;
    require(desktop_policy::reconcileEffectiveSetting(
                [&](bool& matches, std::string&) {
                    calls.push_back("read"); matches = ++reads == 2; return true;
                },
                [&](std::string&) { calls.push_back("write"); return true; },
                "mismatch", error),
            "wrong state did not converge");
    require(calls == std::vector<std::string>{"read", "write", "read"},
            "write/readback ordering is wrong");

    calls.clear();
    require(!desktop_policy::reconcileEffectiveSetting(
                [&](bool& matches, std::string&) {
                    calls.push_back("read"); matches = false; return true;
                },
                [&](std::string&) { calls.push_back("write"); return true; },
                "readback mismatch", error),
            "readback mismatch succeeded");
    require(error == "readback mismatch", "mismatch diagnostic was lost");
    return 0;
}
