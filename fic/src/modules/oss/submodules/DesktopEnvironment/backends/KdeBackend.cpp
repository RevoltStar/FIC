#include "modules/oss/submodules/DesktopEnvironment/backends/KdeBackend.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/BackendCommand.h"

#include <optional>

namespace {
struct KConfigTools {
    std::string writer;
    std::string reader;
};

KConfigTools find_kconfig_tools() {
    for (const int version : {6, 5}) {
        const std::string suffix = std::to_string(version);
        const std::string writer = desktop_backend::findExecutable({
            "/usr/bin/kwriteconfig" + suffix,
            "/bin/kwriteconfig" + suffix
        });
        const std::string reader = desktop_backend::findExecutable({
            "/usr/bin/kreadconfig" + suffix,
            "/bin/kreadconfig" + suffix
        });
        if (!writer.empty() && !reader.empty()) {
            return {writer, reader};
        }
    }
    return {};
}
} // namespace

bool KdeBackend::apply(
    const UserSession& session,
    const SessionContext& context,
    int timeoutMinutes,
    std::string& error
) const {
    const KConfigTools tools = find_kconfig_tools();
    if (tools.writer.empty()) {
        error = "kwriteconfig and kreadconfig were not found";
        return false;
    }

    ProcessResult result;
    const auto writeValue = [&](const std::string& key, const std::string& value) {
        return desktop_backend::execute(
            session,
            context,
            tools.writer,
            {"--file", "kscreenlockerrc", "--group", "Daemon", "--key", key, value},
            result,
            error
        );
    };
    if (!writeValue("Autolock", "true") ||
        !writeValue("Timeout", std::to_string(timeoutMinutes)) ||
        !writeValue("LockGrace", "0") ||
        !writeValue("RequirePassword", "true")) {
        return false;
    }

    const std::string busctl = desktop_backend::findExecutable({
        "/usr/bin/busctl",
        "/bin/busctl"
    });
    if (busctl.empty()) {
        error = "busctl was not found";
        return false;
    }
    if (!desktop_backend::execute(
            session,
            context,
            busctl,
            {
                "--user", "call",
                "org.kde.screensaver",
                "/ScreenSaver",
                "org.kde.screensaver",
                "configure"
            },
            result,
            error)) {
        error = "failed to reload KDE screen lock settings: " + error;
        return false;
    }

    const auto readValue = [&](const std::string& key, ProcessResult& output) {
        return desktop_backend::execute(
            session,
            context,
            tools.reader,
            {"--file", "kscreenlockerrc", "--group", "Daemon", "--key", key},
            output,
            error
        );
    };

    ProcessResult autolock;
    ProcessResult timeout;
    ProcessResult lockGrace;
    ProcessResult requirePassword;
    if (!readValue("Autolock", autolock) ||
        !readValue("Timeout", timeout) ||
        !readValue("LockGrace", lockGrace) ||
        !readValue("RequirePassword", requirePassword)) {
        return false;
    }

    bool autolockEnabled = false;
    bool passwordRequired = false;
    const std::optional<int> actualTimeout = desktop_backend::parseInteger(timeout.standardOutput);
    const std::optional<int> actualLockGrace = desktop_backend::parseInteger(lockGrace.standardOutput);
    if (!desktop_backend::parseBoolean(autolock.standardOutput, autolockEnabled) ||
        !desktop_backend::parseBoolean(requirePassword.standardOutput, passwordRequired) ||
        !autolockEnabled || !passwordRequired ||
        !actualTimeout.has_value() || actualTimeout.value() != timeoutMinutes ||
        !actualLockGrace.has_value() || actualLockGrace.value() != 0) {
        error = "KDE screen lock settings did not reach the requested state";
        return false;
    }
    return true;
}
