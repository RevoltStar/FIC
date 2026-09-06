#include "session/SessionSelection.h"

#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

SessionProperties properties(const std::string& type,
                             const std::string& state,
                             bool remote = false)
{
    SessionProperties result;
    result.session.id = "session";
    result.session.type = type;
    result.sessionClass = "user";
    result.state = state;
    result.remote = remote;
    return result;
}

} // namespace

int main()
{
    const SessionProperties foreground = properties("wayland", "active");
    require(session_selection::graphicalSessionCandidate(foreground, false),
            "foreground graphical session was omitted");

    const SessionProperties background = properties("x11", "online");
    require(session_selection::graphicalSessionCandidate(background, false),
            "background graphical session was omitted");

    const SessionProperties remote = properties("x11", "online", true);
    require(session_selection::graphicalSessionCandidate(remote, false),
            "remote graphical session was omitted");

    const SessionProperties startx = properties("tty", "online");
    require(session_selection::graphicalSessionCandidate(startx, true),
            "TTY session with a session-bound agent was omitted");
    require(!session_selection::graphicalSessionCandidate(startx, false),
            "plain TTY session without an agent became a candidate");
    require(!session_selection::graphicalSessionCandidate(
                properties("unspecified", "online"), true),
            "non-graphical non-TTY session became an agent-backed candidate");

    require(!session_selection::graphicalSessionCandidate(
                properties("wayland", "closing"), true),
            "closing session became a candidate");
    require(!session_selection::graphicalSessionCandidate(
                properties("x11", "dead"), true),
            "dead session became a candidate");

    return 0;
}
