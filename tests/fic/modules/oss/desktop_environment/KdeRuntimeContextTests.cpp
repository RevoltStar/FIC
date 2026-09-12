#include "modules/oss/desktop_environment/backends/KdeBackend.h"
#include "modules/oss/desktop_environment/backends/KdeScreenLockerRuntimeContextResolver.h"
#include "modules/oss/desktop_environment/backends/KdeScreenLockerRuntimeContextResolverInternal.h"
#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"
#include "session/SessionCommandExecutorInternal.h"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

UserSession session() { return {"7", 1000, "user", "wayland"}; }

SessionContext sessionContext() {
    return {"7", "KDE", "wayland", "", "wayland-0"};
}

KdeSessionTopologyInfo topo(KdeSessionTopology state) {
    KdeSessionTopologyInfo info;
    info.state = state;
    return info;
}

ClassifiedGraphicalSession topologySession(uid_t uid, const std::string& id,
                                           DesktopEnvironmentKind desktop,
                                           std::string error = {}) {
    ClassifiedGraphicalSession value;
    value.session.id = id;
    value.session.uid = uid;
    value.desktop = desktop;
    value.classificationError = std::move(error);
    return value;
}

std::string environment(
    const std::vector<std::pair<std::string, std::string>>& entries) {
    std::string result;
    for (const auto& entry : entries) {
        result += entry.first + "=" + entry.second;
        result.push_back('\0');
    }
    return result;
}

struct FakeBus {
    std::vector<std::string> owners{":1.42", ":1.42", ":1.42"};
    std::vector<pid_t> pids{4242, 4242, 4242};
    std::vector<uid_t> uids{1000, 1000, 1000};
    bool available = true;
    int calls = 0;

    ProcessResult execute(const UserSession&, const SessionContext&,
                          const std::string& executable,
                          const std::vector<std::string>& arguments) {
        ProcessResult result;
        result.started = true;
        result.exitCode = available ? 0 : 1;
        if (!available) {
            result.standardError = "name has no owner";
            return result;
        }
        require(executable == "/usr/bin/busctl", "untrusted busctl path");
        require(arguments.front() ==
                    "--address=unix:path=/run/user/1000/bus",
                "bus address was not daemon-controlled");
        const std::size_t round = static_cast<std::size_t>(calls / 3);
        const std::string& method = arguments[5];
        if (method == "GetNameOwner")
            result.standardOutput = "s \"" + owners.at(round) + "\"\n";
        else if (method == "GetConnectionUnixProcessID")
            result.standardOutput = "u " + std::to_string(pids.at(round)) + "\n";
        else if (method == "GetConnectionUnixUser")
            result.standardOutput = "u " + std::to_string(uids.at(round)) + "\n";
        else
            throw std::runtime_error("unexpected D-Bus method");
        ++calls;
        return result;
    }
};

KdeScreenLockerRuntimeContextResolver resolver(
    FakeBus& bus, std::string environ, bool readable = true) {
    return KdeScreenLockerRuntimeContextResolver({
        [](const auto&) { return std::string("/usr/bin/busctl"); },
        [&bus](const auto& target, const auto& context, const auto& executable,
               const auto& arguments) {
            return bus.execute(target, context, executable, arguments);
        },
        [environ = std::move(environ), readable](pid_t pid,
                                                 std::string& output,
                                                 std::string& error) {
            require(pid == 4242,
                    "resolver read environment for wrong process");
            if (!readable) {
                error = "unreadable";
                return false;
            }
            output = environ;
            error.clear();
            return true;
        }});
}

void testProductionReaderAcceptsRootOwnedProcMetadata() {
    FakeBus bus;
    const std::string source = environment({
        {"HOME", "/home/user"},
        {"XDG_CONFIG_HOME", "/home/user/root-owned-proc-metadata"}});
    std::size_t offset = 0;
    int openCalls = 0;
    int fstatCalls = 0;
    int closeCalls = 0;
    constexpr int Descriptor = 73;
    kde_screen_locker_runtime_context_detail::
        ProcessEnvironmentFileOperations operations{
            [&](const std::string& path, int flags) {
                ++openCalls;
                require(path == "/proc/4242/environ",
                        "production reader selected wrong proc path");
                require((flags & O_ACCMODE) == O_RDONLY &&
                            (flags & O_NOFOLLOW) != 0 &&
                            (flags & O_CLOEXEC) != 0 &&
                            (flags & O_NONBLOCK) != 0,
                        "production reader lost safe open flags");
                return Descriptor;
            },
            [&](int descriptor, struct stat& info) {
                ++fstatCalls;
                require(descriptor == Descriptor,
                        "production reader fstat used wrong fd");
                std::memset(&info, 0, sizeof(info));
                info.st_mode = S_IFREG | 0400;
                info.st_uid = 0;
                return 0;
            },
            [&](int descriptor, char* buffer, std::size_t capacity) {
                require(descriptor == Descriptor,
                        "production reader read from wrong fd");
                const std::size_t count = std::min(capacity,
                    source.size() - offset);
                if (count == 0) return static_cast<ssize_t>(0);
                std::memcpy(buffer, source.data() + offset, count);
                offset += count;
                return static_cast<ssize_t>(count);
            },
            [&](int descriptor) {
                ++closeCalls;
                require(descriptor == Descriptor,
                        "production reader closed wrong fd");
                return 0;
            }};
    KdeScreenLockerRuntimeContextResolver target({
        [](const auto&) { return std::string("/usr/bin/busctl"); },
        [&bus](const auto& userSession, const auto& context,
               const auto& executable, const auto& arguments) {
            return bus.execute(
                userSession, context, executable, arguments);
        },
        [&](pid_t pid, std::string& output, std::string& error) {
            return kde_screen_locker_runtime_context_detail::
                readProcessEnvironment(
                    pid, output, error, operations);
        }});
    KdeScreenLockerRuntimeContext captured;
    std::string error;
    require(target.resolve(
                session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error), error);
    require(openCalls == 1 && fstatCalls == 1 && closeCalls == 1 &&
                captured.uid == 1000 &&
                captured.kconfigEnvironment[1].value ==
                    "/home/user/root-owned-proc-metadata",
            "root-owned procfs metadata changed resolver identity or content");
}

void testResolverSuccessPresenceAndAllowlist() {
    FakeBus bus;
    auto target = resolver(bus, environment({
        {"HOME", "/home/user"},
        {"XDG_CONFIG_HOME", "/home/user/custom-config"},
        {"XDG_CONFIG_DIRS", "/home/user/custom-config/kdedefaults:/home/user/custom-system-config:/etc/xdg"},
        {"KDE_SKIP_KDERC", "1"}, {"LD_PRELOAD", "/tmp/evil.so"},
        {"LD_LIBRARY_PATH", "/tmp/evil-libraries"},
        {"PATH", "/tmp/evil"},
        {"DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/evil-bus"},
        {"XDG_RUNTIME_DIR", "/tmp/evil-runtime"}}));
    KdeScreenLockerRuntimeContext captured;
    std::string error;
    require(target.resolve(session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error), error);
    require(captured.uniqueBusOwner == ":1.42" && captured.pid == 4242 &&
                captured.uid == 1000,
            "wrong captured locker identity");
    require(captured.kconfigEnvironment.size() == 4,
            "allowlist size changed");
    const auto& values = captured.kconfigEnvironment;
    require(values[0].name == "HOME" && values[0].value == "/home/user",
            "HOME changed");
    require(values[1].value == "/home/user/custom-config",
            "XDG_CONFIG_HOME changed");
    require(values[2].value ==
                "/home/user/custom-config/kdedefaults:/home/user/custom-system-config:/etc/xdg",
            "XDG_CONFIG_DIRS was reordered or normalized");
    require(values[3].value == "1", "KDE_SKIP_KDERC changed");
    for (const auto& value : values)
        require(value.name != "PATH" && value.name != "LD_PRELOAD",
                "unsafe environment escaped allowlist");
}

void testResolverFailures() {
    std::string error;
    KdeScreenLockerRuntimeContext captured;
    FakeBus absent;
    absent.available = false;
    auto absentResolver = resolver(absent, {});
    require(!absentResolver.resolve(
                session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error),
            "missing screen locker was accepted");

    FakeBus wrongUid;
    wrongUid.uids[0] = 1001;
    auto wrongUidResolver = resolver(wrongUid, {});
    require(!wrongUidResolver.resolve(
                session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error),
            "wrong owner UID was accepted");

    FakeBus unreadable;
    auto unreadableResolver = resolver(unreadable, {}, false);
    require(!unreadableResolver.resolve(
                session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error),
            "unreadable environ was accepted");

    FakeBus ownerChanged;
    ownerChanged.owners[1] = ":1.99";
    auto ownerChangedResolver = resolver(ownerChanged, {});
    require(!ownerChangedResolver.resolve(
                session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error),
            "owner change was accepted");

    FakeBus pidChanged;
    pidChanged.pids[1] = 9999;
    auto pidChangedResolver = resolver(pidChanged, {});
    require(!pidChangedResolver.resolve(
                session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error),
            "PID change was accepted");

    FakeBus malformed;
    auto malformedResolver = resolver(malformed, "HOME=/home/user");
    require(!malformedResolver.resolve(
                session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error),
            "malformed environ was accepted");

    FakeBus ambiguous;
    auto ambiguousResolver = resolver(ambiguous, {});
    require(!ambiguousResolver.resolve(
                session(), sessionContext(),
                topo(KdeSessionTopology::Ambiguous), captured, error) &&
                ambiguous.calls == 0 &&
                error.find("multiple KDE graphical sessions") !=
                    std::string::npos,
            "multiple KDE sessions were accepted");

    // Unknown topology обязан fail closed с диагностикой, отличимой от
    // доказанной multiple-KDE ambiguity, и с деталями проблемной сессии.
    // Target присутствует; Unknown — same-UID сосед.
    FakeBus unknownBus;
    auto unknownResolver = resolver(unknownBus, {});
    KdeSessionTopologyInfo unknownTopology;
    unknownTopology.state = KdeSessionTopology::Unknown;
    unknownTopology.targetPresent = true;
    unknownTopology.unknownSessionId = "9";
    unknownTopology.unknownClassificationError = "agent query failed";
    require(!unknownResolver.resolve(
                session(), sessionContext(), unknownTopology,
                captured, error) &&
                unknownBus.calls == 0 &&
                error.find("KDE session topology is unknown") !=
                    std::string::npos &&
                error.find("session 9") != std::string::npos &&
                error.find("agent query failed") != std::string::npos,
            "unprovable KDE topology did not fail closed with a "
            "distinct diagnostic");
}

void testKdeSessionTopologyComputation() {
    // 1. Одна KDE сессия — Unique.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto info = determineKdeSessionTopology(target, {target}, true);
        require(info.state == KdeSessionTopology::Unique &&
                    info.kdeSessionCount == 1 && info.unknownSessionCount == 0,
                "single KDE session was not Unique");
    }
    // 2. Две KDE сессии одного UID — Ambiguous.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto second =
            topologySession(1000, "2", DesktopEnvironmentKind::Kde);
        const auto info =
            determineKdeSessionTopology(target, {target, second}, true);
        require(info.state == KdeSessionTopology::Ambiguous &&
                    info.kdeSessionCount == 2,
                "two same-UID KDE sessions were not Ambiguous");
    }
    // 3. KDE + Unknown того же UID — Unknown (ключевой regression).
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto unknown = topologySession(
            1000, "2", DesktopEnvironmentKind::Unknown, "agent query failed");
        const auto info =
            determineKdeSessionTopology(target, {target, unknown}, true);
        require(info.state == KdeSessionTopology::Unknown &&
                    info.unknownSessionCount == 1 &&
                    info.unknownSessionId == "2" &&
                    info.unknownClassificationError == "agent query failed",
                "KDE + unclassified same-UID session was not Unknown");
    }
    // 4. KDE + Unknown другого UID — Unique.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto unknown = topologySession(
            1001, "2", DesktopEnvironmentKind::Unknown, "agent query failed");
        const auto info =
            determineKdeSessionTopology(target, {target, unknown}, true);
        require(info.state == KdeSessionTopology::Unique,
                "foreign-UID unknown session polluted KDE topology");
    }
    // 5. KDE + известный GNOME того же UID — Unique.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto gnome =
            topologySession(1000, "2", DesktopEnvironmentKind::Gnome);
        const auto info =
            determineKdeSessionTopology(target, {target, gnome}, true);
        require(info.state == KdeSessionTopology::Unique &&
                    info.kdeSessionCount == 1,
                "known non-KDE same-UID session was treated as ambiguity");
    }
}

void testKdeSessionTopologyComputationPart2() {
    // 6. KDE + KDE + GNOME одного UID — Ambiguous.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto second =
            topologySession(1000, "2", DesktopEnvironmentKind::Kde);
        const auto gnome =
            topologySession(1000, "3", DesktopEnvironmentKind::Gnome);
        const auto info = determineKdeSessionTopology(
            target, {target, second, gnome}, true);
        require(info.state == KdeSessionTopology::Ambiguous &&
                    info.kdeSessionCount == 2,
                "known non-KDE session masked multiple KDE sessions");
    }
    // 7. Inventory incomplete / KDE target отсутствует — Unknown.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto incomplete =
            determineKdeSessionTopology(target, {target}, false);
        require(incomplete.state == KdeSessionTopology::Unknown,
                "incomplete inventory masqueraded as Unique topology");
        const auto missingTarget =
            determineKdeSessionTopology(target, {}, true);
        require(missingTarget.state == KdeSessionTopology::Unknown,
                "KDE target missing from inventory was treated as Unique");
    }
}

void testKdeSessionTopologyTargetPresence() {
    // A. Ключевой regression: target заменён другой KDE session того же UID.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto other =
            topologySession(1000, "2", DesktopEnvironmentKind::Kde);
        const auto info =
            determineKdeSessionTopology(target, {other}, true);
        require(info.state == KdeSessionTopology::Unknown &&
                    !info.targetPresent,
                "replacement same-UID KDE session masqueraded as the target");
    }
    // B. Exact target присутствует — happy path сохранён.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto info = determineKdeSessionTopology(target, {target}, true);
        require(info.state == KdeSessionTopology::Unique &&
                    info.targetPresent && info.targetClassifiedKde,
                "exact target presence broke the Unique happy path");
    }
    // C. Exact target + вторая KDE того же UID — Ambiguous.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto second =
            topologySession(1000, "2", DesktopEnvironmentKind::Kde);
        const auto info =
            determineKdeSessionTopology(target, {target, second}, true);
        require(info.state == KdeSessionTopology::Ambiguous,
                "target plus second KDE was not Ambiguous");
    }
    // D. Target отсутствует, две другие KDE того же UID — Unknown,
    // а не Ambiguous: reconciliation target больше не доказан.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto other1 =
            topologySession(1000, "2", DesktopEnvironmentKind::Kde);
        const auto other2 =
            topologySession(1000, "3", DesktopEnvironmentKind::Kde);
        const auto info =
            determineKdeSessionTopology(target, {other1, other2}, true);
        require(info.state == KdeSessionTopology::Unknown,
                "missing target with multiple other KDE sessions was "
                "treated as Ambiguous");
    }
    // E. Exact target присутствует, но больше не классифицирован как KDE.
    {
        const auto target =
            topologySession(1000, "1", DesktopEnvironmentKind::Kde);
        const auto degenerated = topologySession(
            1000, "1", DesktopEnvironmentKind::Unknown, "agent query failed");
        const auto kdeNeighbour =
            topologySession(1000, "2", DesktopEnvironmentKind::Kde);
        const auto info = determineKdeSessionTopology(
            target, {degenerated, kdeNeighbour}, true);
        require(info.state == KdeSessionTopology::Unknown &&
                    info.targetPresent && !info.targetClassifiedKde,
                "declassified target plus another KDE session was accepted");
    }
}

void testResolverDiagnosticForMissingTarget() {
    FakeBus bus;
    auto target = resolver(bus, {});
    KdeSessionTopologyInfo missing;
    missing.state = KdeSessionTopology::Unknown;
    missing.kdeSessionCount = 1;
    missing.targetPresent = false;
    KdeScreenLockerRuntimeContext captured;
    std::string error;
    require(!target.resolve(session(), sessionContext(), missing,
                captured, error) &&
                bus.calls == 0 &&
                error.find("target session 7 is absent from the current "
                           "inventory") != std::string::npos,
            "missing-target topology did not produce a distinct diagnostic");
}

void testKdeBackendFailsClosedOnUnknownTopology() {
    FakeBus bus;
    auto runtimeResolver =
        std::make_shared<KdeScreenLockerRuntimeContextResolver>(
            resolver(bus, environment({{"HOME", "/home/user"}})));
    KdeSessionTopologyInfo unknown;
    unknown.state = KdeSessionTopology::Unknown;
    unknown.targetPresent = true;
    unknown.unknownSessionId = "9";
    unknown.unknownClassificationError = "agent query failed";
    KdeBackend backend(session(), sessionContext(), unknown,
        {runtimeResolver,
         [](const std::vector<std::string>& paths) { return paths.front(); },
         [](const UserSession&, const SessionContext&, const std::string&,
            const std::vector<std::string>&,
            const std::vector<SessionEnvironmentOverride>&) {
             ProcessResult result;
             (void)result;
             throw std::runtime_error(
                 "KDE command executed without proven unique topology");
             return result;
         }});
    std::string error;
    require(!backend.writeConfig(
                 "kscreenlockerrc", "Daemon", "Lock", "true", error) &&
                bus.calls == 0 &&
                error.find("KDE session topology is unknown") !=
                    std::string::npos &&
                error.find("session 9") != std::string::npos,
            "KDE backend reconciled without proven unique topology");
}

void testEveryAllowlistedVariablePreservesPresence() {
    const std::vector<std::string> names{
        "HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "KDE_SKIP_KDERC"};
    for (const int shape : {0, 1, 2}) {
        FakeBus bus;
        std::vector<std::pair<std::string, std::string>> entries;
        if (shape != 0) {
            for (const auto& name : names)
                entries.push_back({name, shape == 1 ? "" : "value-" + name});
        }
        auto target = resolver(bus, environment(entries));
        KdeScreenLockerRuntimeContext captured;
        std::string error;
        require(target.resolve(
                    session(), sessionContext(), topo(KdeSessionTopology::Unique), captured, error), error);
        for (std::size_t index = 0; index < names.size(); ++index) {
            require(captured.kconfigEnvironment[index].name == names[index],
                    "allowlist order changed");
            const auto& value = captured.kconfigEnvironment[index].value;
            require(shape == 0 ? !value.has_value()
                               : value.has_value() &&
                    (shape == 1 ? value->empty()
                                : *value == "value-" + names[index]),
                    "environment presence shape changed for " + names[index]);
        }
    }
}

void testSessionExecutorOverridesAreConstrained() {
    std::string error;
    ProcessOptions options = session_command_executor_detail::buildOptions(
        session(), sessionContext(), "/home/user", 1000,
        {{"HOME", std::nullopt}, {"XDG_CONFIG_HOME", ""},
         {"XDG_CONFIG_DIRS", "/a:/b"}, {"KDE_SKIP_KDERC", "1"}}, error);
    require(error.empty() && options.uid == 1000 && options.gid == 1000 &&
                options.workingDirectory == "/home/user",
            "KDE overrides changed execution identity or cwd");
    std::map<std::string, std::string> values(
        options.environment.begin(), options.environment.end());
    require(values.find("HOME") == values.end() &&
                values["USER"] == "user" && values["LOGNAME"] == "user" &&
                values["PATH"] == "/usr/local/bin:/usr/bin:/bin" &&
                values["DBUS_SESSION_BUS_ADDRESS"] ==
                    "unix:path=/run/user/1000/bus" &&
                values["XDG_RUNTIME_DIR"] == "/run/user/1000" &&
                values["XDG_CONFIG_HOME"].empty() &&
                values["XDG_CONFIG_DIRS"] == "/a:/b" &&
                values["KDE_SKIP_KDERC"] == "1",
            "KDE override presence semantics are wrong");
    for (const auto& forbidden : {"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH",
                                  "DBUS_SESSION_BUS_ADDRESS",
                                  "XDG_RUNTIME_DIR"}) {
        (void)session_command_executor_detail::buildOptions(
            session(), sessionContext(), "/home/user", 1000,
            {{forbidden, "/tmp/evil"}}, error);
        require(!error.empty(), std::string(forbidden) +
                    " override was accepted");
    }
}

void testKdeBackendUsesLockerSelectedGraph() {
    FakeBus bus;
    auto runtimeResolver = std::make_shared<KdeScreenLockerRuntimeContextResolver>(
        resolver(bus, environment({{"HOME", "/home/user"},
            {"XDG_CONFIG_HOME", "/tmp/locker-config"},
            {"XDG_CONFIG_DIRS", ""}, {"KDE_SKIP_KDERC", "1"}})));
    std::map<std::string, std::string> defaultGraph{{"Lock", "false"}};
    std::map<std::string, std::string> lockerGraph{{"Lock", "false"}};
    KdeBackend backend(session(), sessionContext(), topo(KdeSessionTopology::Unique),
        {runtimeResolver,
         [](const std::vector<std::string>& paths) {
             require(!paths.empty() &&
                         std::all_of(paths.begin(), paths.end(),
                             [](const auto& path) {
                                 return !path.empty() && path.front() == '/';
                             }),
                     "KDE executable lookup accepted a non-absolute path");
             return paths.front();
         },
         [&](const UserSession& target, const SessionContext&,
             const std::string& executable,
             const std::vector<std::string>& arguments,
             const std::vector<SessionEnvironmentOverride>& overrides) {
             require(target.uid == 1000, "KDE tool ran under wrong UID");
             ProcessResult result;
             result.started = true;
             result.exitCode = 0;
             if (executable.find("busctl") != std::string::npos) {
                 require(overrides.empty() && arguments[2] == ":1.42",
                         "configure did not target captured unique owner");
                 return result;
             }
             std::map<std::string, std::optional<std::string>> environment;
             for (const auto& item : overrides)
                 environment[item.name] = item.value;
             require(environment["XDG_CONFIG_HOME"] ==
                         std::optional<std::string>("/tmp/locker-config"),
                     "KDE tool used synthetic config root");
             require(environment.find("PATH") == environment.end() &&
                         environment.find("LD_PRELOAD") == environment.end(),
                     "unsafe variable reached KDE command overrides");
             if (executable.find("kwriteconfig") != std::string::npos)
                 lockerGraph[arguments[arguments.size() - 2]] = arguments.back();
             else if (executable.find("kreadconfig") != std::string::npos)
                 result.standardOutput = lockerGraph[arguments.back()] + "\n";
             return result;
         }});
    std::string error;
    require(backend.writeConfig("kscreenlockerrc", "Daemon", "Lock", "true", error), error);
    std::string value;
    require(backend.readConfig("kscreenlockerrc", "Daemon", "Lock", value, error), error);
    require(value == "true" && lockerGraph["Lock"] == "true" &&
                defaultGraph["Lock"] == "false",
            "KDE backend changed the wrong KConfig graph");
    require(backend.callDbusMethod("org.kde.screensaver", "/ScreenSaver",
                "org.kde.screensaver", "configure", error), error);
}

void testKdeBackendRejectsOwnerReplacementAfterConfigure() {
    FakeBus bus;
    bus.owners[2] = ":1.99";
    auto runtimeResolver = std::make_shared<KdeScreenLockerRuntimeContextResolver>(
        resolver(bus, environment({{"HOME", "/home/user"}})));
    KdeBackend backend(session(), sessionContext(), topo(KdeSessionTopology::Unique),
        {runtimeResolver,
         [](const std::vector<std::string>& paths) { return paths.front(); },
         [](const UserSession&, const SessionContext&, const std::string&,
            const std::vector<std::string>&,
            const std::vector<SessionEnvironmentOverride>&) {
             ProcessResult result;
             result.started = true;
             result.exitCode = 0;
             return result;
         }});
    std::string error;
    require(!backend.callDbusMethod("org.kde.screensaver", "/ScreenSaver",
                "org.kde.screensaver", "configure", error),
            "KScreenLocker owner replacement after configure was accepted");
}

} // namespace

int main() {
    testProductionReaderAcceptsRootOwnedProcMetadata();
    testKdeBackendUsesLockerSelectedGraph();
    testKdeBackendRejectsOwnerReplacementAfterConfigure();
    testResolverSuccessPresenceAndAllowlist();
    testResolverFailures();
    testKdeSessionTopologyComputation();
    testKdeSessionTopologyComputationPart2();
    testKdeSessionTopologyTargetPresence();
    testResolverDiagnosticForMissingTarget();
    testKdeBackendFailsClosedOnUnknownTopology();
    testEveryAllowlistedVariablePreservesPresence();
    testSessionExecutorOverridesAreConstrained();
    return 0;
}
