#include "modules/oss/submodules/DesktopEnvironment/OSS_screenlock_timeout.h"

#include "modules/oss/submodules/DesktopEnvironment/backends/DesktopEnvironmentBackend.h"
#include "modules/oss/submodules/DesktopEnvironment/policies/ScreenLockTimeoutHandler.h"
#include "session/SessionAgentClient.h"
#include "session/SessionLocator.h"

#include <optional>
#include <string>
#include <vector>

OSS_screenlock_timeout::OSS_screenlock_timeout(
    const fic::platform::SystemToolsPlatformConfig& systemTools)
    : DesktopEnvironment(),
      loginctlCandidates_(systemTools.loginctlCandidates)
{
    this->policyName = "screenlock_timeout";
    this->policyTypeValue = std::make_unique<IntPolicyTypeValue>(1, 20, 5);
}

bool OSS_screenlock_timeout::apply()
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
    if (!SessionLocator::activeGraphicalSessions(
            loginctlCandidates_, sessions, error)) {
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

        std::unique_ptr<ScreenLockTimeoutHandler> handler =
            ScreenLockTimeoutHandlerFactory::create(session, context);
        if (!handler) {
            const std::string desktop = DesktopEnvironmentBackend::normalizeName(context.desktop);
            this->log(
                "screenlock_timeout is not supported for desktop " +
                (desktop.empty() ? std::string("UNKNOWN") : desktop) +
                ", user " + session.user + ", session " + session.id,
                logLevel::ERROR
            );
            success = false;
            continue;
        }

        std::string handlerError;
        if (!handler->apply(timeoutMinutes, handlerError)) {
            this->log(
                "Failed to apply screenlock_timeout for user " + session.user +
                ", session " + session.id + ", desktop " + handler->desktopName() +
                ": " + handlerError,
                logLevel::ERROR
            );
            success = false;
        }
    }

    return success;
}
