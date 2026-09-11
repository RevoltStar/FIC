#include "modules/oss/desktop_environment/backends/XfceBackend.h"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

struct FakeCommands {
    std::vector<std::string> executables;
    std::vector<std::vector<std::string>> arguments;
    bool propertyExists = false;
    bool queryOk = true;

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
                if (commandArguments == std::vector<std::string>{"--query"}) {
                    error = queryOk ? "" : "no running screensaver";
                    return queryOk;
                }
                const bool create = std::find(
                    commandArguments.begin(), commandArguments.end(),
                    "--create") != commandArguments.end();
                if (!propertyExists && !create) {
                    error = "property does not exist";
                    return false;
                }
                propertyExists = true;
                output.clear();
                error.clear();
                return true;
            }
        };
    }
};

void testMissingPropertyUsesCreateFallback() {
    FakeCommands commands;
    XfceBackend backend({}, {}, commands.dependencies());
    std::string error;
    require(backend.setProperty(
                "xfce4-screensaver", "/saver/fullscreen-inhibit",
                "bool", "false", error), error);
    require(commands.arguments.size() == 2,
            "missing XFCE property did not use exactly one fallback");
    require(commands.arguments[0] == std::vector<std::string>{
                "--channel", "xfce4-screensaver", "--property",
                "/saver/fullscreen-inhibit", "--set", "false"},
            "XFCE initial property update arguments changed");
    require(commands.arguments[1] == std::vector<std::string>{
                "--channel", "xfce4-screensaver", "--property",
                "/saver/fullscreen-inhibit", "--create", "--type", "bool",
                "--set", "false"},
            "XFCE property create fallback arguments are wrong");
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
} // namespace

int main() {
    testMissingPropertyUsesCreateFallback();
    testAvailabilityOnlyQueriesExistingLocker();
    return 0;
}
