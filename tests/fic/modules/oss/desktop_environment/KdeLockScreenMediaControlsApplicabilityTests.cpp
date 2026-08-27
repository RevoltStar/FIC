#include "modules/oss/desktop_environment/policies/KdeLockScreenMediaControlsApplicability.h"

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

void requireScenario(const std::vector<UserSession>& sessions,
                     const std::map<std::string, std::string>& desktops,
                     const std::map<std::string, bool>& applyResults,
                     bool expectedSuccess,
                     std::size_t expectedApplicable,
                     const std::vector<std::string>& expectedApplied)
{
    std::vector<std::string> applied;
    std::size_t applicable = 0;
    const bool success =
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
            applicable);

    require(success == expectedSuccess, "unexpected aggregate result");
    require(applicable == expectedApplicable,
            "unexpected applicable KDE session count");
    require(applied == expectedApplied,
            "non-KDE session was applied or KDE session was omitted");
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
    return 0;
}
