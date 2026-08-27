#include "SessionIdentityResolver.h"

#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
using fic::session_agent::LogindSessionInfo;
using fic::session_agent::LogindSessionProvider;
using fic::session_agent::SessionIdentityResolver;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class FakeLogind final : public LogindSessionProvider {
public:
    bool processAvailable = true;
    std::string processSession = "current";
    std::unordered_map<std::string, LogindSessionInfo> sessions;
    mutable size_t processLookups = 0;
    mutable std::vector<std::string> sessionLookups;

    bool currentProcessSession(
        std::string& sessionId,
        std::string& error) const override {
        ++processLookups;
        if (!processAvailable) {
            error = "No data available";
            return false;
        }
        sessionId = processSession;
        return true;
    }

    bool sessionInfo(
        const std::string& sessionId,
        LogindSessionInfo& info,
        std::string& error) const override {
        sessionLookups.push_back(sessionId);
        const auto it = sessions.find(sessionId);
        if (it == sessions.end()) {
            error = "session does not exist";
            return false;
        }
        info = it->second;
        return true;
    }
};

LogindSessionInfo graphical(uid_t uid, const std::string& type = "wayland") {
    return {uid, "user", false, type};
}

bool resolve(
    const std::string& environmentSession,
    uid_t uid,
    const FakeLogind& logind,
    std::string& sessionId,
    std::string& error) {
    return SessionIdentityResolver::resolve(
        environmentSession, uid, logind, sessionId, error);
}

void testValidEnvironmentSessionIsPreferred() {
    FakeLogind logind;
    logind.sessions["env-session"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("env-session", 1000, logind, sessionId, error), error);
    require(sessionId == "env-session", "valid XDG_SESSION_ID was not used");
    require(logind.processLookups == 0,
            "process fallback ran for a valid environment session");
}

void testMissingEnvironmentUsesCurrentProcessSession() {
    FakeLogind logind;
    logind.processSession = "pid-session";
    logind.sessions["pid-session"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("", 1000, logind, sessionId, error), error);
    require(sessionId == "pid-session",
            "current process session was not used as fallback");
}

void testInvalidEnvironmentDoesNotSelectArbitrarySession() {
    FakeLogind logind;
    logind.processSession = "owned-session";
    logind.sessions["owned-session"] = graphical(1000);
    logind.sessions["other-session"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("../other-session", 1000, logind, sessionId, error), error);
    require(sessionId == "owned-session",
            "invalid environment id selected another user session");
    require(logind.sessionLookups.size() == 1 &&
                logind.sessionLookups.front() == "owned-session",
            "resolver inspected sessions other than the current process session");
}

void testRejectedEnvironmentFallsBackOnlyToProcessSession() {
    FakeLogind logind;
    logind.processSession = "owned-session";
    logind.sessions["stale-session"] = graphical(2000);
    logind.sessions["owned-session"] = graphical(1000);
    logind.sessions["unrelated-session"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("stale-session", 1000, logind, sessionId, error), error);
    require(sessionId == "owned-session",
            "rejected environment did not fall back to the process session");
    require(logind.sessionLookups ==
                std::vector<std::string>({"stale-session", "owned-session"}),
            "fallback inspected an unrelated session of the same uid");
}

void testForeignUidFails() {
    FakeLogind logind;
    logind.processAvailable = false;
    logind.sessions["foreign"] = graphical(2000);

    std::string sessionId;
    std::string error;
    require(!resolve("foreign", 1000, logind, sessionId, error),
            "foreign uid session was accepted");
    require(error.find("does not belong to the current uid") != std::string::npos,
            "foreign uid diagnostic is missing: " + error);
}

void testNonUserClassFails() {
    FakeLogind logind;
    logind.processAvailable = false;
    logind.sessions["manager"] = {1000, "manager", false, "wayland"};

    std::string sessionId;
    std::string error;
    require(!resolve("manager", 1000, logind, sessionId, error),
            "non-user class was accepted");
}

void testRemoteSessionFails() {
    FakeLogind logind;
    logind.processAvailable = false;
    logind.sessions["remote"] = {1000, "user", true, "wayland"};

    std::string sessionId;
    std::string error;
    require(!resolve("remote", 1000, logind, sessionId, error),
            "remote session was accepted");
}

void testNonGraphicalTypeFails() {
    FakeLogind logind;
    logind.processAvailable = false;
    logind.sessions["tty"] = graphical(1000, "tty");

    std::string sessionId;
    std::string error;
    require(!resolve("tty", 1000, logind, sessionId, error),
            "non-graphical session was accepted");
}

void testEverySupportedGraphicalTypeIsAccepted() {
    for (const std::string type : {"x11", "wayland", "mir"}) {
        FakeLogind logind;
        logind.sessions[type] = graphical(1000, type);
        std::string sessionId;
        std::string error;
        require(resolve(type, 1000, logind, sessionId, error),
                type + " session was rejected: " + error);
    }
}

void testUnavailableProcessSessionFailsClosed() {
    FakeLogind logind;
    logind.processAvailable = false;

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "missing process session did not fail closed");
    require(error.find("XDG_SESSION_ID is not set") != std::string::npos &&
                error.find("not associated with a logind session") !=
                    std::string::npos,
            "missing process session diagnostic is unclear: " + error);
}

void testMultipleSessionsUseOnlyExactProcessSession() {
    FakeLogind logind;
    logind.processSession = "second";
    logind.sessions["first"] = graphical(1000, "x11");
    logind.sessions["second"] = graphical(1000, "wayland");

    std::string sessionId;
    std::string error;
    require(resolve("", 1000, logind, sessionId, error), error);
    require(sessionId == "second", "resolver selected a different user session");
    require(logind.sessionLookups == std::vector<std::string>{"second"},
            "resolver enumerated or inspected another user session");
}
} // namespace

int main() {
    testValidEnvironmentSessionIsPreferred();
    testMissingEnvironmentUsesCurrentProcessSession();
    testInvalidEnvironmentDoesNotSelectArbitrarySession();
    testRejectedEnvironmentFallsBackOnlyToProcessSession();
    testForeignUidFails();
    testNonUserClassFails();
    testRemoteSessionFails();
    testNonGraphicalTypeFails();
    testEverySupportedGraphicalTypeIsAccepted();
    testUnavailableProcessSessionFailsClosed();
    testMultipleSessionsUseOnlyExactProcessSession();
    return 0;
}
