#include "modules/oss/submodules/DesktopEnvironment/backends/XfceBackend.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/BackendCommand.h"

#include <optional>

namespace {
constexpr const char* CHANNEL = "xfce4-screensaver";

bool set_property(
    const UserSession& session,
    const SessionContext& context,
    const std::string& xfconfQuery,
    const std::string& property,
    const std::string& type,
    const std::string& value,
    std::string& error
) {
    ProcessResult result;
    if (desktop_backend::execute(
            session,
            context,
            xfconfQuery,
            {"--channel", CHANNEL, "--property", property, "--set", value},
            result,
            error)) {
        return true;
    }

    return desktop_backend::execute(
        session,
        context,
        xfconfQuery,
        {"--channel", CHANNEL, "--property", property, "--create", "--type", type, "--set", value},
        result,
        error
    );
}

bool get_property(
    const UserSession& session,
    const SessionContext& context,
    const std::string& xfconfQuery,
    const std::string& property,
    ProcessResult& result,
    std::string& error
) {
    return desktop_backend::execute(
        session,
        context,
        xfconfQuery,
        {"--channel", CHANNEL, "--property", property},
        result,
        error
    );
}
} // namespace

bool XfceBackend::apply(
    const UserSession& session,
    const SessionContext& context,
    int timeoutMinutes,
    std::string& error
) const {
    const std::string xfconfQuery = desktop_backend::findExecutable({
        "/usr/bin/xfconf-query",
        "/bin/xfconf-query"
    });
    if (xfconfQuery.empty()) {
        error = "xfconf-query was not found";
        return false;
    }

    if (!set_property(session, context, xfconfQuery, "/saver/enabled", "bool", "true", error) ||
        !set_property(session, context, xfconfQuery, "/saver/idle-activation/enabled", "bool", "true", error) ||
        !set_property(session, context, xfconfQuery, "/saver/idle-activation/delay", "int", std::to_string(timeoutMinutes), error) ||
        !set_property(session, context, xfconfQuery, "/lock/enabled", "bool", "true", error) ||
        !set_property(session, context, xfconfQuery, "/lock/saver-activation/enabled", "bool", "true", error) ||
        !set_property(session, context, xfconfQuery, "/lock/saver-activation/delay", "int", "0", error)) {
        return false;
    }

    ProcessResult saverEnabled;
    ProcessResult idleEnabled;
    ProcessResult idleDelay;
    ProcessResult lockEnabled;
    ProcessResult lockWithSaverEnabled;
    ProcessResult lockDelay;
    if (!get_property(session, context, xfconfQuery, "/saver/enabled", saverEnabled, error) ||
        !get_property(session, context, xfconfQuery, "/saver/idle-activation/enabled", idleEnabled, error) ||
        !get_property(session, context, xfconfQuery, "/saver/idle-activation/delay", idleDelay, error) ||
        !get_property(session, context, xfconfQuery, "/lock/enabled", lockEnabled, error) ||
        !get_property(session, context, xfconfQuery, "/lock/saver-activation/enabled", lockWithSaverEnabled, error) ||
        !get_property(session, context, xfconfQuery, "/lock/saver-activation/delay", lockDelay, error)) {
        return false;
    }

    bool actualSaverEnabled = false;
    bool actualIdleEnabled = false;
    bool actualLockEnabled = false;
    bool actualLockWithSaverEnabled = false;
    const std::optional<int> actualIdleDelay = desktop_backend::parseInteger(idleDelay.standardOutput);
    const std::optional<int> actualLockDelay = desktop_backend::parseInteger(lockDelay.standardOutput);
    if (!desktop_backend::parseBoolean(saverEnabled.standardOutput, actualSaverEnabled) ||
        !desktop_backend::parseBoolean(idleEnabled.standardOutput, actualIdleEnabled) ||
        !desktop_backend::parseBoolean(lockEnabled.standardOutput, actualLockEnabled) ||
        !desktop_backend::parseBoolean(lockWithSaverEnabled.standardOutput, actualLockWithSaverEnabled) ||
        !actualSaverEnabled || !actualIdleEnabled || !actualLockEnabled || !actualLockWithSaverEnabled ||
        !actualIdleDelay.has_value() || actualIdleDelay.value() != timeoutMinutes ||
        !actualLockDelay.has_value() || actualLockDelay.value() != 0) {
        error = "XFCE screen lock settings did not reach the requested state";
        return false;
    }
    return true;
}
