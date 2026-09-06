#include "session/SessionReadyValidation.h"

#include <stdexcept>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
}

int main() {
    using session_ready_validation::validLogindClaim;
    require(validLogindClaim(1000, 1000, "user", "active", "wayland", false),
            "valid graphical session rejected");
    require(!validLogindClaim(1000, 1001, "user", "active", "wayland", false),
            "UID/session mismatch accepted");
    require(!validLogindClaim(1000, 1000, "manager", "active", "wayland", false),
            "non-user session accepted");
    require(!validLogindClaim(1000, 1000, "user", "closing", "x11", false),
            "closing session accepted");
    require(!validLogindClaim(1000, 1000, "user", "dead", "x11", false),
            "dead session accepted");
    require(!validLogindClaim(1000, 1000, "user", "active", "tty", false),
            "plain non-graphical TTY accepted");
    require(validLogindClaim(1000, 1000, "user", "online", "tty", true),
            "session-bound graphical startx candidate rejected");
    require(!validLogindClaim(1000, 1000, "user", "active", "unspecified", true),
            "unknown logind session type accepted");
    return 0;
}
