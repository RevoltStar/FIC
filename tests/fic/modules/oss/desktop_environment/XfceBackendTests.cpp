#include "modules/oss/desktop_environment/backends/XfceBackend.h"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

// Trusted canonical helper location compiled into the backend. The backend
// must never resolve the helper from the session PATH.
constexpr const char* kHelperPath = "/usr/libexec/fic/fic-xfconf-inspect";

struct FakeCommands {
    std::vector<std::string> executables;
    std::vector<std::vector<std::string>> arguments;
    std::string helperOutput;
    bool helperOk = true;
    bool queryOk = true;
    bool writeOk = true;

    XfceBackendDependencies dependencies() {
        return {
            [](const std::vector<std::string>& candidates) {
                return candidates.front();
            },
            [this](const std::string& executable,
                   const std::vector<std::string>& commandArguments,
                   std::string& output, std::string& error) {
                executables.push_back(executable);
                arguments.push_back(commandArguments);
                if (executable == kHelperPath) {
                    output = helperOutput;
                    error = helperOk ? "" : "helper exited with code 3";
                    return helperOk;
                }
                if (commandArguments == std::vector<std::string>{"--query"}) {
                    error = queryOk ? "" : "no running screensaver";
                    return queryOk;
                }
                if (commandArguments.size() > 4 &&
                    commandArguments[4] == "--create") {
                    error = writeOk ? "" : "xfconf-query failed";
                    return writeOk;
                }
                output.clear();
                error.clear();
                return true;
            }
        };
    }
};

void testSetPropertyUsesSingleTypedMutation() {
    FakeCommands commands;
    XfceBackend backend({}, {}, commands.dependencies());
    std::string error;
    require(backend.setProperty(
                "xfce4-screensaver", "/saver/fullscreen-inhibit",
                "bool", "false", error), error);
    require(commands.arguments.size() == 1,
            "typed XFCE property mutation did not use exactly one command");
    require(commands.arguments[0] == std::vector<std::string>{
                "--channel", "xfce4-screensaver", "--property",
                "/saver/fullscreen-inhibit", "--create", "--type", "bool",
                "--set", "false"},
            "XFCE typed property mutation arguments are wrong");
}

void testSetPropertyFailureHasNoUntypedFallback() {
    FakeCommands commands;
    commands.writeOk = false;
    XfceBackend backend({}, {}, commands.dependencies());
    std::string error;
    require(!backend.setProperty(
                "xfce4-screensaver", "/saver/idle-activation/delay",
                "int", "5", error),
            "failing XFCE property mutation reported success");
    require(!error.empty(), "XFCE property mutation failure hid the error");
    // Exactly one typed mutation attempt: no plain `--set` fallback may exist
    // because it preserves a wrong storage type.
    require(commands.arguments.size() == 1,
            "failed XFCE typed mutation retried with an untyped fallback");
}

void testAvailabilityOnlyQueriesExistingLocker() {
    FakeCommands commands;
    XfceBackend backend({}, {}, commands.dependencies());
    std::string error;
    require(backend.screenSaverAvailable(error), error);
    require(commands.executables == std::vector<std::string>{
                "/usr/bin/xfce4-screensaver-command"} &&
            commands.arguments ==
                std::vector<std::vector<std::string>>{{"--query"}},
            "XFCE availability check does more than query the locker");

    commands.executables.clear();
    commands.arguments.clear();
    commands.queryOk = false;
    require(!backend.screenSaverAvailable(error) &&
                commands.arguments ==
                    std::vector<std::vector<std::string>>{{"--query"}},
            "unavailable XFCE locker was accepted or started");
}

void testGetPropertyStateUsesTrustedHelperAndParsesTypes() {
    struct ProtocolCase {
        std::string output;
        XfcePropertyStateKind expectedKind;
        XfcePropertyType expectedType;
        std::string expectedValue;
    };
    const ProtocolCase cases[] = {
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=bool\nvalue=true\n",
         XfcePropertyStateKind::Present, XfcePropertyType::Bool, "true"},
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=bool\nvalue=false\n",
         XfcePropertyStateKind::Present, XfcePropertyType::Bool, "false"},
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=int\nvalue=5\n",
         XfcePropertyStateKind::Present, XfcePropertyType::Int, "5"},
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=int\nvalue=0\n",
         XfcePropertyStateKind::Present, XfcePropertyType::Int, "0"},
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=uint\nvalue=5\n",
         XfcePropertyStateKind::Present, XfcePropertyType::UInt, "5"},
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=double\nvalue=5.000000\n",
         XfcePropertyStateKind::Present, XfcePropertyType::Double,
         "5.000000"},
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=string\nvalue=5\n",
         XfcePropertyStateKind::Present, XfcePropertyType::String, "5"},
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=string\nvalue=true\n",
         XfcePropertyStateKind::Present, XfcePropertyType::String, "true"},
        // Unknown storage types keep their type name and no value: the
        // backend must see the mismatch, never a guessed value.
        {"fic-xfconf-inspect-protocol=2\nstate=present\ntype=gint64\n",
         XfcePropertyStateKind::Present, XfcePropertyType::Other, ""},
    };

    for (const ProtocolCase& protocolCase : cases) {
        FakeCommands commands;
        commands.helperOutput = protocolCase.output;
        XfceBackend backend({}, {}, commands.dependencies());
        XfcePropertyState state;
        std::string error;
        require(backend.getPropertyState(
                    "xfce4-screensaver", "/saver/idle-activation/delay",
                    state, error),
                "valid helper output was rejected: " + error);
        require(state.kind == protocolCase.expectedKind &&
                    state.type == protocolCase.expectedType &&
                    state.value == protocolCase.expectedValue,
                "helper protocol was parsed into the wrong property state");

        require(commands.executables == std::vector<std::string>{kHelperPath},
                "XFCE typed read did not use the trusted canonical helper");
        require(commands.arguments[0] ==
                    std::vector<std::string>{"--channel", "xfce4-screensaver",
                                             "--property",
                                             "/saver/idle-activation/delay"},
                "XFCE typed read used wrong helper arguments");
    }
}

void testGetPropertyStateReportsAuthoritativeAbsence() {
    // Absence is a valid protocol result, not a failure: the backend must
    // report it as kind=Absent without any fake type or value.
    FakeCommands commands;
    commands.helperOutput = "fic-xfconf-inspect-protocol=2\nstate=absent\n";
    XfceBackend backend({}, {}, commands.dependencies());
    XfcePropertyState state;
    std::string error;
    require(backend.getPropertyState(
                "xfce4-screensaver", "/saver/idle-activation/delay",
                state, error),
            "authoritative absence was rejected: " + error);
    require(state.kind == XfcePropertyStateKind::Absent &&
                state.type == XfcePropertyType::Other && state.value.empty(),
            "absence was not reported as an explicit Absent state");
    require(commands.executables == std::vector<std::string>{kHelperPath},
            "XFCE absent read did not use the trusted canonical helper");
}

void testGetPropertyStateRejectsMalformedProtocol() {
    const char* malformedOutputs[] = {
        "",
        "type=int\nvalue=5\n",
        // Old protocol version must fail closed: helper and daemon ship as
        // one product version, no compatibility fallback exists.
        "fic-xfconf-inspect-protocol=1\ntype=int\nvalue=5\n",
        "fic-xfconf-inspect-protocol=3\nstate=present\ntype=int\nvalue=5\n",
        "fic-xfconf-inspect-protocol=2\ntype=int\nvalue=5\n",
        "fic-xfconf-inspect-protocol=2\nstate=unknown\n",
        // Absence must stay bare: no type/value records may ride along.
        "fic-xfconf-inspect-protocol=2\nstate=absent\ntype=int\n",
        "fic-xfconf-inspect-protocol=2\nstate=absent\nvalue=5\n",
        "fic-xfconf-inspect-protocol=2\nstate=absent\ntype=int\nvalue=5\n",
        // Present requires a type, and a value only for policy-known types.
        "fic-xfconf-inspect-protocol=2\nstate=present\n",
        "fic-xfconf-inspect-protocol=2\nstate=present\ntype=\n",
        "fic-xfconf-inspect-protocol=2\nstate=present\ntype=int\n",
        "fic-xfconf-inspect-protocol=2\nstate=present\ntype=int\noutput=5\n",
        "fic-xfconf-inspect-protocol=2\nstate=present\ntype=gint64\nvalue=5\n",
        "fic-xfconf-inspect-protocol=2\nstate=present\ntype=int\nvalue=5\nextra=1\n",
        "fic-xfconf-inspect-protocol=2\nstate=present\ntype=int\nvalue=5\nvalue=6\n",
    };
    for (const char* malformedOutput : malformedOutputs) {
        FakeCommands commands;
        commands.helperOutput = malformedOutput;
        XfceBackend backend({}, {}, commands.dependencies());
        XfcePropertyState state;
        std::string error;
        require(!backend.getPropertyState(
                    "xfce4-screensaver", "/saver/idle-activation/delay",
                    state, error),
                "malformed helper output was accepted");
        require(!error.empty(), "malformed helper output hid the error");
    }
}

void testGetPropertyStateFailsClosedOnHelperFailure() {
    FakeCommands commands;
    commands.helperOk = false;
    XfceBackend backend({}, {}, commands.dependencies());
    XfcePropertyState state;
    std::string error;
    require(!backend.getPropertyState(
                "xfce4-screensaver", "/saver/idle-activation/delay",
                state, error),
            "helper failure was accepted as state");
    require(!error.empty(), "helper failure hid the error");
}
} // namespace

int main() {
    testSetPropertyUsesSingleTypedMutation();
    testSetPropertyFailureHasNoUntypedFallback();
    testAvailabilityOnlyQueriesExistingLocker();
    testGetPropertyStateUsesTrustedHelperAndParsesTypes();
    testGetPropertyStateReportsAuthoritativeAbsence();
    testGetPropertyStateRejectsMalformedProtocol();
    testGetPropertyStateFailsClosedOnHelperFailure();
    return 0;
}
