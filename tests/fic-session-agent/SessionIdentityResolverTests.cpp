#include "SessionIdentityResolver.h"

#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
using fic::session_agent::LogindSessionInfo;
using fic::session_agent::LogindSessionProvider;
using fic::session_agent::ProcessSessionResult;
using fic::session_agent::SessionIdentityResolver;
using fic::session_agent::AgentSessionContext;
using fic::session_agent::effectiveGraphicalSessionType;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class FakeLogind final : public LogindSessionProvider {
public:
    ProcessSessionResult processResult = ProcessSessionResult::Found;
    std::string processSession = "current";
    std::string processError = "Input/output error";
    bool enumerationAvailable = true;
    std::vector<std::string> enumeratedSessions;
    std::unordered_map<std::string, LogindSessionInfo> sessions;
    // Deliberately not exposed through LogindSessionInfo: Active must never be
    // a resolver input or an ambiguity discriminator.
    std::unordered_map<std::string, bool> activeStates;
    mutable size_t processLookups = 0;
    mutable size_t enumerationLookups = 0;
    mutable std::vector<std::string> sessionLookups;

    ProcessSessionResult currentProcessSession(
        std::string& sessionId,
        std::string& error) const override {
        ++processLookups;
        if (processResult == ProcessSessionResult::Found) {
            sessionId = processSession;
            error.clear();
        } else if (processResult == ProcessSessionResult::Error) {
            error = processError;
        } else {
            error.clear();
        }
        return processResult;
    }

    bool userSessions(
        uid_t,
        std::vector<std::string>& result,
        std::string& error) const override {
        ++enumerationLookups;
        if (!enumerationAvailable) {
            error = "enumeration failed";
            return false;
        }
        result = enumeratedSessions;
        error.clear();
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
        error.clear();
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
    std::string& error,
    const AgentSessionContext& context =
        {"wayland", "KDE", "", "wayland-0"}) {
    return SessionIdentityResolver::resolve(
        environmentSession, context, uid, logind, sessionId, error);
}

void testValidEnvironmentSessionIsPreferred() {
    FakeLogind logind;
    logind.sessions["env-session"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("env-session", 1000, logind, sessionId, error), error);
    require(sessionId == "env-session", "valid XDG_SESSION_ID was not used");
    require(logind.processLookups == 0 && logind.enumerationLookups == 0,
            "fallback ran for a valid environment session");
}

void testInvalidEnvironmentUsesGraphicalProcessSession() {
    FakeLogind logind;
    logind.processSession = "pid-session";
    logind.sessions["pid-session"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("../unsafe", 1000, logind, sessionId, error), error);
    require(sessionId == "pid-session",
            "invalid environment did not fall back to the process session");
    require(logind.enumerationLookups == 0,
            "UID enumeration ran despite a process-bound session");
}

void testMissingEnvironmentUsesGraphicalProcessSession() {
    FakeLogind logind;
    logind.processSession = "pid-session";
    logind.sessions["pid-session"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("", 1000, logind, sessionId, error), error);
    require(sessionId == "pid-session", "process session fallback failed");
    require(logind.enumerationLookups == 0,
            "UID enumeration ran despite a process-bound session");
}

void testNotAssociatedWithOneGraphicalSessionSucceeds() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;
    logind.enumeratedSessions = {"3"};
    logind.sessions["3"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(resolve("", 1000, logind, sessionId, error), error);
    require(sessionId == "3", "unique graphical session was not selected");
}

void testNotAssociatedWithNoGraphicalSessionFails() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "zero graphical candidates unexpectedly succeeded");
    require(error.find("no graphical user session exists for uid 1000") !=
                std::string::npos,
            "zero-candidate diagnostic is unclear: " + error);
}

void testNotAssociatedWithTwoGraphicalSessionsFails() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;
    logind.enumeratedSessions = {"3", "7"};
    logind.sessions["3"] = graphical(1000, "wayland");
    logind.sessions["7"] = graphical(1000, "x11");

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "ambiguous graphical sessions unexpectedly succeeded");
    require(error.find("multiple graphical sessions exist for uid 1000: 3, 7") !=
                std::string::npos,
            "ambiguity diagnostic is unclear: " + error);
}

void testAltGnomeManagerSshAndWaylandSelectsOnlyWayland() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;
    logind.enumeratedSessions = {"3", "4", "6"};
    logind.sessions["3"] = graphical(1000, "wayland");
    logind.sessions["4"] = {1000, "manager", false, "unspecified"};
    logind.sessions["6"] = {1000, "user", true, "tty"};

    std::string sessionId;
    std::string error;
    require(resolve("", 1000, logind, sessionId, error), error);
    require(sessionId == "3", "ALT GNOME session was not resolved to 3");
    require(logind.sessionLookups ==
                std::vector<std::string>({"3", "4", "6"}),
            "ALT candidate set was not fully validated");
}

void requireProcessSessionRejectedWithoutEnumeration(
    const LogindSessionInfo& info,
    const std::string& description) {
    FakeLogind logind;
    logind.processSession = "6";
    logind.sessions["6"] = info;
    logind.enumeratedSessions = {"3"};
    logind.sessions["3"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            description + " process session unexpectedly succeeded");
    require(logind.enumerationLookups == 0,
            description + " process session incorrectly used UID fallback");
    require(error.find("current process belongs to logind session 6") !=
                std::string::npos,
            description + " process diagnostic is unclear: " + error);
}

void testTtyProcessSessionFailsWithoutEnumeration() {
    FakeLogind logind;
    logind.processSession = "6";
    logind.sessions["6"] = {1000, "user", false, "tty"};
    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error, {}),
            "TTY without graphical context unexpectedly succeeded");
    require(logind.enumerationLookups == 0,
            "TTY process session incorrectly used UID fallback");
}

void testRemoteGraphicalProcessSessionSucceeds() {
    FakeLogind logind;
    logind.processSession = "xrdp";
    logind.sessions["xrdp"] = {1000, "user", true, "x11"};
    std::string sessionId;
    std::string error;
    require(resolve(
                "", 1000, logind, sessionId, error,
                {"x11", "KDE", ":10", ""}),
            "remote XRDP session was rejected: " + error);
    require(sessionId == "xrdp", "wrong XRDP session was selected");
}

void testStartxTtyProcessSessionSucceeds() {
    FakeLogind logind;
    logind.processSession = "tty2";
    logind.sessions["tty2"] = {1000, "user", false, "tty"};
    std::string sessionId;
    std::string error;
    require(resolve(
                "", 1000, logind, sessionId, error,
                {"tty", "KDE", ":1", ""}),
            "startx KDE context was rejected: " + error);
    require(sessionId == "tty2", "startx was bound to the wrong session");
}

void testStartxTtyWithEmptyRawTypeSucceeds() {
    FakeLogind logind;
    logind.processSession = "tty2";
    logind.sessions["tty2"] = {1000, "user", false, "tty"};
    std::string sessionId;
    std::string error;
    require(resolve(
                "", 1000, logind, sessionId, error,
                {"", "KDE", ":1", ""}),
            "startx with empty XDG_SESSION_TYPE was rejected: " + error);
}

void testTtyGraphicalInferenceIsFailClosed() {
    FakeLogind logind;
    logind.processSession = "tty2";
    logind.sessions["tty2"] = {1000, "user", false, "tty"};
    std::string sessionId;
    std::string error;
    for (const AgentSessionContext context : {
             AgentSessionContext{"tty", "", "", ""},
             AgentSessionContext{"tty", "", ":1", ""}}) {
        require(!resolve("", 1000, logind, sessionId, error, context),
                "plain or desktop-less TTY was accepted");
    }
}

void testWaylandInTtySucceeds() {
    FakeLogind logind;
    logind.processSession = "tty2";
    logind.sessions["tty2"] = {1000, "user", false, "tty"};
    std::string sessionId;
    std::string error;
    require(resolve(
                "", 1000, logind, sessionId, error,
                {"tty", "KDE", "", "wayland-0"}),
            "Wayland-in-TTY context was rejected: " + error);
}

void testEffectiveGraphicalTypeCanonicalization() {
    const auto requireType = [](const AgentSessionContext& context,
                                const std::string& expected) {
        const auto actual = effectiveGraphicalSessionType(context);
        require(actual.has_value() && *actual == expected,
                "unexpected effective graphical type");
    };
    requireType({"wayland", "", "", "wayland-0"}, "wayland");
    requireType({"x11", "", ":1", ""}, "x11");
    requireType({"tty", "KDE", ":1", ""}, "x11");
    requireType({"", "KDE", ":1", ""}, "x11");
    requireType({"tty", "KDE", "", "wayland-0"}, "wayland");
    requireType({"", "KDE", "", "wayland-0"}, "wayland");
    requireType({"tty", "KDE", ":1", "wayland-0"}, "wayland");
    requireType({"x11", "KDE", ":1", "wayland-0"}, "wayland");
    requireType({"mir", "", ":0", ""}, "mir");
    require(!effectiveGraphicalSessionType({"tty", "", ":1", ""}),
            "DISPLAY without desktop identity was canonicalized");
    require(!effectiveGraphicalSessionType({"x11", "KDE", "", ""}),
            "explicit X11 without DISPLAY was canonicalized");
    require(!effectiveGraphicalSessionType(
                {"wayland", "KDE", "", ""}),
            "explicit Wayland without WAYLAND_DISPLAY was canonicalized");
}

void testStartxTtyRequiresConsistentDisplay() {
    FakeLogind logind;
    logind.processSession = "tty2";
    logind.sessions["tty2"] = {1000, "user", false, "tty"};
    std::string sessionId;
    std::string error;
    require(!resolve(
                "", 1000, logind, sessionId, error,
                {"x11", "KDE", "", ""}),
            "startx context without DISPLAY unexpectedly succeeded");
}

void testTtyIsNotSelectedByUidFallback() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;
    logind.enumeratedSessions = {"tty2"};
    logind.sessions["tty2"] = {1000, "user", false, "tty"};
    std::string sessionId;
    std::string error;
    require(!resolve(
                "", 1000, logind, sessionId, error,
                {"tty", "KDE", ":1", ""}),
            "unbound agent ambiguously selected a TTY session");
}

void testForeignProcessSessionFailsWithoutEnumeration() {
    requireProcessSessionRejectedWithoutEnumeration(
        graphical(2000), "foreign uid");
}

void testHardProcessLookupErrorFailsWithoutEnumeration() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::Error;
    logind.processError = "Permission denied";
    logind.enumeratedSessions = {"3"};
    logind.sessions["3"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "hard process lookup error unexpectedly succeeded");
    require(logind.enumerationLookups == 0,
            "hard process lookup error incorrectly used UID fallback");
    require(error.find("could not determine the current process logind session") !=
                std::string::npos,
            "hard process error diagnostic is unclear: " + error);
}

void testActiveStateDoesNotResolveAmbiguity() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;
    logind.enumeratedSessions = {"3", "7"};
    logind.sessions["3"] = graphical(1000, "wayland");
    logind.sessions["7"] = graphical(1000, "x11");
    logind.activeStates = {{"3", true}, {"7", false}};

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "Active state was incorrectly used to select a session");
    require(error.find("3, 7") != std::string::npos,
            "both graphical sessions were not reported as ambiguous");
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

void testInvalidProcessSessionIdFailsWithoutEnumeration() {
    FakeLogind logind;
    logind.processSession = "../unsafe";
    logind.enumeratedSessions = {"3"};
    logind.sessions["3"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "unsafe process session id unexpectedly succeeded");
    require(logind.enumerationLookups == 0,
            "unsafe process session id incorrectly used UID fallback");
    require(error.find("invalid logind session id") != std::string::npos,
            "unsafe session diagnostic is missing: " + error);
}

void testInvalidEnumeratedSessionIdFailsClosed() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;
    logind.enumeratedSessions = {"3", "../unsafe"};
    logind.sessions["3"] = graphical(1000);

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "unsafe enumerated session id was ignored");
    require(error.find("could not be validated") != std::string::npos,
            "unsafe enumerated id diagnostic is missing: " + error);
}

void testEnumerationErrorFailsClosed() {
    FakeLogind logind;
    logind.processResult = ProcessSessionResult::NotAssociated;
    logind.enumerationAvailable = false;

    std::string sessionId;
    std::string error;
    require(!resolve("", 1000, logind, sessionId, error),
            "session enumeration error unexpectedly succeeded");
    require(error.find("could not be enumerated") != std::string::npos,
            "enumeration error diagnostic is missing: " + error);
}
} // namespace

int main() {
    testValidEnvironmentSessionIsPreferred();
    testInvalidEnvironmentUsesGraphicalProcessSession();
    testMissingEnvironmentUsesGraphicalProcessSession();
    testNotAssociatedWithOneGraphicalSessionSucceeds();
    testNotAssociatedWithNoGraphicalSessionFails();
    testNotAssociatedWithTwoGraphicalSessionsFails();
    testAltGnomeManagerSshAndWaylandSelectsOnlyWayland();
    testTtyProcessSessionFailsWithoutEnumeration();
    testRemoteGraphicalProcessSessionSucceeds();
    testStartxTtyProcessSessionSucceeds();
    testStartxTtyWithEmptyRawTypeSucceeds();
    testTtyGraphicalInferenceIsFailClosed();
    testWaylandInTtySucceeds();
    testEffectiveGraphicalTypeCanonicalization();
    testStartxTtyRequiresConsistentDisplay();
    testTtyIsNotSelectedByUidFallback();
    testForeignProcessSessionFailsWithoutEnumeration();
    testHardProcessLookupErrorFailsWithoutEnumeration();
    testActiveStateDoesNotResolveAmbiguity();
    testEverySupportedGraphicalTypeIsAccepted();
    testInvalidProcessSessionIdFailsWithoutEnumeration();
    testInvalidEnumeratedSessionIdFailsClosed();
    testEnumerationErrorFailsClosed();
    return 0;
}
