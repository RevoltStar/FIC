#include "modules/oss/desktop_environment/backends/KdeScreenLockerRuntimeContextResolver.h"

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/desktop_environment/backends/KdeScreenLockerRuntimeContextResolverInternal.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr std::size_t MaxEnvironmentBytes = 1024 * 1024;
constexpr const char* ScreenLockerService = "org.kde.screensaver";
const std::array<const char*, 4> KConfigEnvironmentNames{
    "HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "KDE_SKIP_KDERC"};

const kde_screen_locker_runtime_context_detail::
ProcessEnvironmentFileOperations ProcessEnvironmentOperations{
    [](const std::string& path, int flags) {
        return ::open(path.c_str(), flags);
    },
    [](int descriptor, struct stat& info) {
        return ::fstat(descriptor, &info);
    },
    [](int descriptor, char* buffer, std::size_t size) {
        return ::read(descriptor, buffer, size);
    },
    [](int descriptor) { return ::close(descriptor); }};

bool readProcessEnvironment(pid_t pid, std::string& content,
                            std::string& error) {
    return kde_screen_locker_runtime_context_detail::readProcessEnvironment(
        pid, content, error, ProcessEnvironmentOperations);
}

bool validEnvironmentName(const std::string& name) {
    if (name.empty() ||
        !(name.front() == '_' ||
          (name.front() >= 'A' && name.front() <= 'Z') ||
          (name.front() >= 'a' && name.front() <= 'z')))
        return false;
    for (const unsigned char ch : name) {
        if (ch != '_' && !(ch >= 'A' && ch <= 'Z') &&
            !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9'))
            return false;
    }
    return true;
}

bool isKConfigEnvironmentName(const std::string& name) {
    return std::find_if(KConfigEnvironmentNames.begin(),
        KConfigEnvironmentNames.end(), [&](const char* allowed) {
            return name == allowed;
        }) != KConfigEnvironmentNames.end();
}

} // namespace

bool kde_screen_locker_runtime_context_detail::readProcessEnvironment(
    pid_t pid, std::string& content, std::string& error,
    const ProcessEnvironmentFileOperations& operations) {
    const std::string path = "/proc/" + std::to_string(pid) + "/environ";
    const int descriptor = operations.open(
        path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        error = "could not open KScreenLocker environment: " +
            std::string(std::strerror(errno));
        return false;
    }
    struct stat info {};
    if (operations.fstat(descriptor, info) != 0 || !S_ISREG(info.st_mode)) {
        error = "unsafe KScreenLocker environment source";
        operations.close(descriptor);
        return false;
    }
    content.clear();
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = operations.read(
            descriptor, buffer.data(), buffer.size());
        if (count > 0) {
            if (content.size() + static_cast<std::size_t>(count) >
                MaxEnvironmentBytes) {
                error = "KScreenLocker environment exceeds size limit";
                operations.close(descriptor);
                return false;
            }
            content.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0)
            break;
        if (errno == EINTR)
            continue;
        error = "could not read KScreenLocker environment: " +
            std::string(std::strerror(errno));
        operations.close(descriptor);
        return false;
    }
    if (operations.close(descriptor) != 0) {
        error = "could not close KScreenLocker environment";
        return false;
    }
    error.clear();
    return true;
}

namespace {

bool parseEnvironment(
    const std::string& content,
    std::vector<SessionEnvironmentOverride>& environment,
    std::string& error) {
    if (!content.empty() && content.back() != '\0') {
        error = "malformed KScreenLocker environment";
        return false;
    }
    std::map<std::string, std::string> values;
    std::size_t offset = 0;
    while (offset < content.size()) {
        const std::size_t end = content.find('\0', offset);
        if (end == std::string::npos || end == offset) {
            error = "malformed KScreenLocker environment";
            return false;
        }
        const std::string entry = content.substr(offset, end - offset);
        const std::size_t separator = entry.find('=');
        const std::string name = entry.substr(0, separator);
        if (separator == std::string::npos || !validEnvironmentName(name)) {
            error = "malformed KScreenLocker environment";
            return false;
        }
        if (isKConfigEnvironmentName(name) &&
            !values.emplace(name, entry.substr(separator + 1)).second) {
            error = "ambiguous KScreenLocker environment";
            return false;
        }
        offset = end + 1;
    }
    environment.clear();
    for (const char* name : KConfigEnvironmentNames) {
        const auto found = values.find(name);
        environment.push_back({name, found == values.end()
                ? std::optional<std::string>{}
                : std::optional<std::string>{found->second}});
    }
    error.clear();
    return true;
}

std::string commandError(const ProcessResult& result) {
    if (!result.error.empty()) return result.error;
    if (result.timedOut) return "command timed out";
    if (!result.standardError.empty()) return result.standardError;
    return result.started ? "command exited with code " +
        std::to_string(result.exitCode) : "command failed to start";
}

bool parseStringReply(const std::string& output, std::string& value) {
    std::istringstream input(output);
    std::string signature;
    if (!(input >> signature >> std::quoted(value)) || signature != "s" ||
        value.empty() || value.front() != ':')
        return false;
    input >> std::ws;
    return input.eof();
}

template<typename Integer>
bool parseUnsignedReply(const std::string& output, Integer& value) {
    std::istringstream input(output);
    std::string signature;
    unsigned long long parsed = 0;
    if (!(input >> signature >> parsed) || signature != "u" ||
        parsed > std::numeric_limits<Integer>::max())
        return false;
    input >> std::ws;
    if (!input.eof()) return false;
    value = static_cast<Integer>(parsed);
    return true;
}

struct BusIdentity {
    std::string owner;
    pid_t pid = 0;
    uid_t uid = 0;
};

bool queryBusIdentity(
    const KdeScreenLockerRuntimeContextResolverDependencies& dependencies,
    const UserSession& session, const SessionContext& context,
    BusIdentity& identity, std::string& error) {
    error.clear();
    const std::string busctl = dependencies.findExecutable(
        {"/usr/bin/busctl", "/bin/busctl"});
    if (busctl.empty()) {
        error = "busctl was not found";
        return false;
    }
    const std::string address = "--address=unix:path=/run/user/" +
        std::to_string(session.uid) + "/bus";
    const auto call = [&](const std::string& method,
                          const std::vector<std::string>& tail,
                          std::string& output) {
        std::vector<std::string> arguments{address, "call",
            "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", method};
        arguments.insert(arguments.end(), tail.begin(), tail.end());
        const ProcessResult result = dependencies.execute(
            session, context, busctl, arguments);
        if (!result.success()) {
            error = "could not resolve KScreenLocker D-Bus owner: " +
                commandError(result);
            return false;
        }
        output = result.standardOutput;
        return true;
    };

    std::string output;
    if (!call("GetNameOwner", {"s", ScreenLockerService}, output) ||
        !parseStringReply(output, identity.owner)) {
        if (error.empty()) error = "malformed KScreenLocker owner reply";
        return false;
    }
    if (!call("GetConnectionUnixProcessID", {"s", identity.owner}, output) ||
        !parseUnsignedReply(output, identity.pid) || identity.pid <= 0) {
        if (error.empty()) error = "malformed KScreenLocker PID reply";
        return false;
    }
    if (!call("GetConnectionUnixUser", {"s", identity.owner}, output) ||
        !parseUnsignedReply(output, identity.uid)) {
        if (error.empty()) error = "malformed KScreenLocker UID reply";
        return false;
    }
    error.clear();
    return true;
}

} // namespace

KdeScreenLockerRuntimeContextResolver::
KdeScreenLockerRuntimeContextResolver()
    : dependencies_{
        [](const std::vector<std::string>& paths) {
            return DesktopEnvironmentBackend::findExecutable(paths);
        },
        [](const UserSession& session, const SessionContext& context,
           const std::string& executable,
           const std::vector<std::string>& arguments) {
            return SessionCommandExecutor::execute(
                session, context, executable, arguments);
        },
        readProcessEnvironment}
{
}

KdeScreenLockerRuntimeContextResolver::
KdeScreenLockerRuntimeContextResolver(
    KdeScreenLockerRuntimeContextResolverDependencies dependencies)
    : dependencies_(std::move(dependencies))
{
}

bool KdeScreenLockerRuntimeContextResolver::resolve(
    const UserSession& session, const SessionContext& context,
    const KdeSessionTopologyInfo& sameUidKdeTopology,
    KdeScreenLockerRuntimeContext& result, std::string& error) const {
    if (sameUidKdeTopology.state == KdeSessionTopology::Ambiguous) {
        error = "multiple KDE graphical sessions exist for UID " +
            std::to_string(session.uid) + ": " +
            std::to_string(sameUidKdeTopology.kdeSessionCount) +
            " KDE sessions cannot share one KScreenLocker owner";
        return false;
    }
    if (sameUidKdeTopology.state != KdeSessionTopology::Unique) {
        error = "KDE session topology is unknown for UID " +
            std::to_string(session.uid) +
            "; uniqueness of the KScreenLocker owner cannot be proven";
        if (!sameUidKdeTopology.unknownSessionId.empty()) {
            error += " (session " + sameUidKdeTopology.unknownSessionId +
                " could not be classified";
            if (!sameUidKdeTopology.unknownClassificationError.empty()) {
                error += ": " + sameUidKdeTopology.unknownClassificationError;
            }
            error += ")";
        }
        return false;
    }
    BusIdentity before;
    if (!queryBusIdentity(dependencies_, session, context, before, error))
        return false;
    if (before.uid != session.uid) {
        error = "KScreenLocker D-Bus owner UID does not match target session UID";
        return false;
    }
    std::string environ;
    if (!dependencies_.readEnviron(before.pid, environ, error) ||
        !parseEnvironment(environ, result.kconfigEnvironment, error))
        return false;
    BusIdentity after;
    if (!queryBusIdentity(dependencies_, session, context, after, error))
        return false;
    if (before.owner != after.owner || before.pid != after.pid ||
        before.uid != after.uid) {
        error = "KScreenLocker D-Bus owner changed during runtime context capture";
        return false;
    }
    result.uniqueBusOwner = before.owner;
    result.pid = before.pid;
    result.uid = before.uid;
    error.clear();
    return true;
}

bool KdeScreenLockerRuntimeContextResolver::validate(
    const UserSession& session, const SessionContext& context,
    const KdeScreenLockerRuntimeContext& captured,
    std::string& error) const {
    BusIdentity current;
    if (!queryBusIdentity(dependencies_, session, context, current, error))
        return false;
    if (current.owner != captured.uniqueBusOwner ||
        current.pid != captured.pid || current.uid != captured.uid) {
        error = "KScreenLocker D-Bus owner no longer matches captured runtime context";
        return false;
    }
    error.clear();
    return true;
}
