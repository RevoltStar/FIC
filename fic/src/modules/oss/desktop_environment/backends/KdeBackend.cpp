#include "modules/oss/desktop_environment/backends/KdeBackend.h"

#include "modules/oss/desktop_environment/backends/BackendCommand.h"

#include <utility>

namespace {
struct KConfigTools {
    std::string writer;
    std::string reader;
};
} // namespace

KdeBackend::KdeBackend(const UserSession& session,
                       const SessionContext& context,
                       const KdeSessionTopologyInfo& sameUidKdeTopology)
    : KdeBackend(session, context, sameUidKdeTopology,
          {std::make_shared<KdeScreenLockerRuntimeContextResolver>(),
           [](const std::vector<std::string>& paths) {
               return DesktopEnvironmentBackend::findExecutable(paths);
           },
           [](const UserSession& target, const SessionContext& sessionContext,
              const std::string& executable,
              const std::vector<std::string>& arguments,
              const std::vector<SessionEnvironmentOverride>& environment) {
               return SessionCommandExecutor::executeWithKdeConfigEnvironment(
                   target, sessionContext, executable, arguments, environment);
           }})
{
}

KdeBackend::KdeBackend(const UserSession& session,
                       const SessionContext& context,
                       const KdeSessionTopologyInfo& sameUidKdeTopology,
                       KdeBackendDependencies dependencies)
    : DesktopEnvironmentBackend(session, context), session_(session),
      context_(context), sameUidKdeTopology_(sameUidKdeTopology),
      dependencies_(std::move(dependencies))
{
}

bool KdeBackend::ensureRuntimeContext(std::string& error) const
{
    if (runtimeContext_.has_value()) {
        error.clear();
        return true;
    }
    KdeScreenLockerRuntimeContext captured;
    if (!dependencies_.resolver ||
        !dependencies_.resolver->resolve(session_, context_,
            sameUidKdeTopology_, captured, error))
        return false;
    runtimeContext_ = std::move(captured);
    error.clear();
    return true;
}

bool KdeBackend::executeWithKConfigEnvironment(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    std::string& output,
    std::string& error) const
{
    if (!ensureRuntimeContext(error)) return false;
    const ProcessResult result = dependencies_.execute(
        session_, context_, executable, arguments,
        runtimeContext_->kconfigEnvironment);
    if (!result.success()) {
        if (!result.error.empty()) error = result.error;
        else if (result.timedOut) error = "command timed out";
        else if (result.started)
            error = "command exited with code " +
                std::to_string(result.exitCode);
        else error = "command failed to start";
        if (!result.standardError.empty())
            error += ": " + desktop_backend::trim(result.standardError);
        return false;
    }
    output = desktop_backend::trim(result.standardOutput);
    error.clear();
    return true;
}

bool KdeBackend::writeConfig(
    const std::string& file,
    const std::string& group,
    const std::string& key,
    const std::string& value,
    std::string& error
) const
{
    return writeConfig(
        file,
        std::vector<std::string>{group},
        key,
        value,
        error
    );
}

bool KdeBackend::writeConfig(
    const std::string& file,
    const std::vector<std::string>& groups,
    const std::string& key,
    const std::string& value,
    std::string& error
) const
{
    if (!ensureRuntimeContext(error)) return false;
    const KConfigTools tools = [&]() {
        for (const int version : {6, 5}) {
            const std::string suffix = std::to_string(version);
            const std::string writer = dependencies_.findExecutable({
                "/usr/bin/kwriteconfig" + suffix,
                "/bin/kwriteconfig" + suffix});
            const std::string reader = dependencies_.findExecutable({
                "/usr/bin/kreadconfig" + suffix,
                "/bin/kreadconfig" + suffix});
            if (!writer.empty() && !reader.empty()) return KConfigTools{writer, reader};
        }
        return KConfigTools{};
    }();
    if (tools.writer.empty()) {
        error = "kwriteconfig and kreadconfig were not found";
        return false;
    }

    std::vector<std::string> arguments{
        "--file", file
    };

    for (const std::string& group : groups) {
        arguments.push_back("--group");
        arguments.push_back(group);
    }

    arguments.push_back("--key");
    arguments.push_back(key);
    arguments.push_back(value);

    std::string output;
    return executeWithKConfigEnvironment(
        tools.writer,
        arguments,
        output,
        error
    );
}

bool KdeBackend::readConfig(
    const std::string& file,
    const std::string& group,
    const std::string& key,
    std::string& value,
    std::string& error
) const
{
    return readConfig(
        file,
        std::vector<std::string>{group},
        key,
        value,
        error
    );
}

bool KdeBackend::readConfig(
    const std::string& file,
    const std::vector<std::string>& groups,
    const std::string& key,
    std::string& value,
    std::string& error
) const
{
    if (!ensureRuntimeContext(error)) return false;
    const KConfigTools tools = [&]() {
        for (const int version : {6, 5}) {
            const std::string suffix = std::to_string(version);
            const std::string writer = dependencies_.findExecutable({
                "/usr/bin/kwriteconfig" + suffix,
                "/bin/kwriteconfig" + suffix});
            const std::string reader = dependencies_.findExecutable({
                "/usr/bin/kreadconfig" + suffix,
                "/bin/kreadconfig" + suffix});
            if (!writer.empty() && !reader.empty()) return KConfigTools{writer, reader};
        }
        return KConfigTools{};
    }();
    if (tools.reader.empty()) {
        error = "kwriteconfig and kreadconfig were not found";
        return false;
    }

    std::vector<std::string> arguments{
        "--file", file
    };

    for (const std::string& group : groups) {
        arguments.push_back("--group");
        arguments.push_back(group);
    }

    arguments.push_back("--key");
    arguments.push_back(key);

    return executeWithKConfigEnvironment(
        tools.reader,
        arguments,
        value,
        error
    );
}

bool KdeBackend::callDbusMethod(
    const std::string& service,
    const std::string& path,
    const std::string& interface,
    const std::string& method,
    std::string& error
) const
{
    if (!ensureRuntimeContext(error)) return false;
    const std::string busctl = dependencies_.findExecutable({
        "/usr/bin/busctl",
        "/bin/busctl"
    });
    if (busctl.empty()) {
        error = "busctl was not found";
        return false;
    }
    std::string output;
    const std::string destination = service == "org.kde.screensaver"
        ? runtimeContext_->uniqueBusOwner : service;
    const std::string address = "--address=unix:path=/run/user/" +
        std::to_string(session_.uid) + "/bus";
    const ProcessResult result = dependencies_.execute(
        session_, context_, busctl,
        {address, "call", destination, path, interface, method}, {});
    if (!result.success()) {
        error = result.error.empty() ? "D-Bus method call failed" : result.error;
        return false;
    }
    return validateRuntimeContext(error);
}

bool KdeBackend::validateRuntimeContext(std::string& error) const
{
    return ensureRuntimeContext(error) && dependencies_.resolver->validate(
        session_, context_, *runtimeContext_, error);
}
