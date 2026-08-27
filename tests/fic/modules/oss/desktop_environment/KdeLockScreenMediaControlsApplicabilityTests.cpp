#include "modules/oss/desktop_environment/policies/KdeLockScreenMediaControlsApplicability.h"
#include "session/SessionSelection.h"
#include "session/SessionCommandExecutor.h"
#include "session/SessionCommandExecutorInternal.h"

#include <algorithm>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

UserSession session(const std::string& id)
{
    UserSession result;
    result.id = id;
    result.user = "user-" + id;
    result.type = "wayland";
    return result;
}

UserSession selectedCandidate(const std::string& id,
                              const std::string& type,
                              const std::string& state,
                              bool remote,
                              bool agentEndpointPresent)
{
    SessionProperties properties;
    properties.session = session(id);
    properties.session.type = type;
    properties.sessionClass = "user";
    properties.state = state;
    properties.remote = remote;
    require(session_selection::kdeMediaControlsCandidate(
                properties, agentEndpointPresent),
            "expected session candidate was not discovered: " + id);
    return properties.session;
}

void requireScenario(const std::vector<UserSession>& sessions,
                     const std::map<std::string, std::string>& desktops,
                     const std::map<std::string, bool>& applyResults,
                     bool expectedSuccess,
                     std::size_t expectedApplicable,
                     const std::vector<std::string>& expectedApplied,
                     std::size_t expectedClassificationFailures = 0)
{
    std::vector<std::string> applied;
    std::vector<std::string> contextFailures;
    const auto result =
        kde_lock_screen_media_controls::applyToKdeSessions(
            sessions,
            [&desktops](const UserSession& candidate,
                        SessionContext& context,
                        std::string& error) {
                const auto found = desktops.find(candidate.id);
                if (found == desktops.end()) {
                    error = "desktop is unknown";
                    return false;
                }
                context.desktop = found->second;
                return true;
            },
            [&applyResults, &applied](const UserSession& candidate,
                                     const SessionContext&) {
                applied.push_back(candidate.id);
                const auto found = applyResults.find(candidate.id);
                return found != applyResults.end() && found->second;
            },
            [&contextFailures](const UserSession& candidate,
                               const std::string& error) {
                contextFailures.push_back(candidate.id + ":" + error);
            });

    require(result.success == expectedSuccess, "unexpected aggregate result");
    require(result.applicableSessions == expectedApplicable,
            "unexpected applicable KDE session count");
    require(result.classificationFailures == expectedClassificationFailures,
            "unexpected classification failure count");
    require(result.notApplicable() ==
                (expectedSuccess && expectedApplicable == 0),
            "not-applicable summary contradicts aggregate result");
    require(applied == expectedApplied,
            "non-KDE session was applied or KDE session was omitted");
    require(contextFailures.size() == expectedClassificationFailures,
            "unexpected context-query failure reporting");
}

void testStartxCommandUsesCanonicalType()
{
    UserSession startx{"tty2", 1000, "test-user", "tty"};
    SessionContext context{"tty2", "KDE", "x11", ":1", ""};
    const ProcessOptions options = session_command_executor_detail::buildOptions(
        startx, context, "/home/test-user", 1000);
    const auto sessionType = std::find(
        options.environment.begin(), options.environment.end(),
        std::pair<std::string, std::string>{"XDG_SESSION_TYPE", "x11"});
    require(sessionType != options.environment.end(),
            "startx command inherited logind Type=tty");
}

} // namespace

int main()
{
    requireScenario(
        {session("kde1")},
        {{"kde1", "KDE"}},
        {{"kde1", true}},
        true, 1, {"kde1"});
    requireScenario(
        {session("kde1"), session("gnome1")},
        {{"kde1", "PLASMA"}, {"gnome1", "GNOME"}},
        {{"kde1", true}},
        true, 1, {"kde1"});
    requireScenario(
        {session("kde1"), session("gnome1")},
        {{"kde1", "KDE"}, {"gnome1", "GNOME"}},
        {{"kde1", false}},
        false, 1, {"kde1"});
    requireScenario(
        {session("kde1"), session("kde2")},
        {{"kde1", "KDE"}, {"kde2", "KDE"}},
        {{"kde1", true}, {"kde2", false}},
        false, 2, {"kde1", "kde2"});
    requireScenario(
        {session("gnome1"), session("xfce1")},
        {{"gnome1", "GNOME"}, {"xfce1", "XFCE"}},
        {},
        true, 0, {});
    requireScenario({}, {}, {}, true, 0, {});
    requireScenario(
        {session("unavailable")},
        {},
        {},
        false, 0, {}, 1);
    requireScenario(
        {session("unknown")},
        {{"unknown", ""}},
        {},
        false, 0, {}, 1);
    requireScenario(
        {session("unknown-literal")},
        {{"unknown-literal", "UNKNOWN"}},
        {},
        false, 0, {}, 1);
    for (const std::string desktop : {"COSMIC", "MATE", "CINNAMON", "SOME_NEW_DE"}) {
        requireScenario(
            {session("unclassified")},
            {{"unclassified", desktop}},
            {},
            false, 0, {}, 1);
    }
    for (const std::string desktop : {"GNOME", "XFCE", "FLY"}) {
        requireScenario(
            {session("known-non-kde")},
            {{"known-non-kde", desktop}},
            {},
            true, 0, {});
    }
    requireScenario(
        {
            selectedCandidate("foreground", "wayland", "active", false, false),
            selectedCandidate("background", "x11", "online", false, false)
        },
        {{"foreground", "KDE"}, {"background", "PLASMA"}},
        {{"foreground", true}, {"background", true}},
        true, 2, {"foreground", "background"});
    requireScenario(
        {selectedCandidate("xrdp-kde", "x11", "online", true, false)},
        {{"xrdp-kde", "KDE"}},
        {{"xrdp-kde", true}},
        true, 1, {"xrdp-kde"});
    requireScenario(
        {selectedCandidate("remote-gnome", "x11", "online", true, false)},
        {{"remote-gnome", "GNOME"}},
        {},
        true, 0, {});
    requireScenario(
        {selectedCandidate("startx", "tty", "online", false, true)},
        {{"startx", "KDE"}},
        {{"startx", true}},
        true, 1, {"startx"});
    testStartxCommandUsesCanonicalType();
    return 0;
}
