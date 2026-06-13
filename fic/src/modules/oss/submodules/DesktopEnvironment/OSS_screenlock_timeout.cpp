#include "modules/oss/submodules/DesktopEnvironment/OSS_screenlock_timeout.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/ScreenLockTimeoutBackend.h"
#include "session/SessionAgentClient.h"
#include "session/SessionLocator.h"

#include <optional>
#include <string>
#include <vector>

OSS_screenlock_timeout::OSS_screenlock_timeout()
    : DesktopEnvironment()
{
    this->policyName = "screenlock_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 20, 5);
}

bool OSS_screenlock_timeout::check_and_fix()
{
    const std::optional<std::string> configuredValue = this->getValue();
    if (!configuredValue.has_value()) {
        return false;
    }

    int timeoutMinutes = 0;
    try {
        timeoutMinutes = std::stoi(configuredValue.value());
    } catch (...) {
        this->log("Invalid screen lock timeout value", logLevel::ERROR);
        return false;
    }

    std::vector<UserSession> sessions;
    std::string error;
    if (!SessionLocator::activeGraphicalSessions(sessions, error)) {
        this->log("Failed to enumerate graphical sessions: " + error, logLevel::ERROR);
        return false;
    }
    if (sessions.empty()) {
        this->log("No active graphical sessions; screenlock_timeout is not applicable", logLevel::DEBUG);
        return true;
    }

    bool success = true;
    for (const UserSession& session : sessions) {
        SessionContext context;
        if (!SessionAgentClient::query(session, context, error)) {
            this->log(
                "Session agent is unavailable for user " + session.user +
                ", session " + session.id + ": " + error,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        std::unique_ptr<ScreenLockTimeoutBackend> backend =
            ScreenLockTimeoutBackendFactory::create(context.desktop);
        if (!backend) {
            const std::string desktop = ScreenLockTimeoutBackendFactory::normalizeDesktopName(context.desktop);
            this->log(
                "screenlock_timeout is not supported for desktop " +
                (desktop.empty() ? std::string("UNKNOWN") : desktop) +
                ", user " + session.user + ", session " + session.id,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        std::string backendError;
        if (!backend->apply(session, context, timeoutMinutes, backendError)) {
            this->log(
                "Failed to apply screenlock_timeout for user " + session.user +
                ", session " + session.id + ", desktop " + backend->name() +
                ": " + backendError,
                logLevel::ERROR
            );
            success = false;
        }
    }

    return success;
}
