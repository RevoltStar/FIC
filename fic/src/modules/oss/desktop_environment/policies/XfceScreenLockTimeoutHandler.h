#ifndef XFCE_SCREEN_LOCK_TIMEOUT_HANDLER_H
#define XFCE_SCREEN_LOCK_TIMEOUT_HANDLER_H

#include "modules/oss/desktop_environment/backends/XfceBackend.h"
#include "modules/oss/desktop_environment/backends/BackendCommand.h"
#include "modules/oss/desktop_environment/SessionSettingReconciler.h"
#include "modules/oss/desktop_environment/policies/ScreenLockTimeoutHandler.h"

#include <array>
#include <string>

namespace xfce_screen_lock_timeout {
struct RequiredProperty {
    const char* path;
    const char* type;
    std::string value;
};

inline std::array<RequiredProperty, 7> requiredProperties(int timeoutMinutes)
{
    return {{{"/saver/enabled", "bool", "true"},
             {"/saver/idle-activation/enabled", "bool", "true"},
             {"/saver/idle-activation/delay", "int",
              std::to_string(timeoutMinutes)},
             {"/saver/fullscreen-inhibit", "bool", "false"},
             {"/lock/enabled", "bool", "true"},
             {"/lock/saver-activation/enabled", "bool", "true"},
             {"/lock/saver-activation/delay", "int", "0"}}};
}

template <typename Backend>
bool applyTimeout(const Backend& backend, int timeoutMinutes,
                  std::string& error)
{
    constexpr const char* channel = "xfce4-screensaver";
    if (!backend.screenSaverAvailable(error)) return false;

    const auto required = requiredProperties(timeoutMinutes);
    const auto readState = [&](bool& matches, std::string&) {
        matches = true;
        for (const auto& property : required) {
            std::string actual;
            if (!backend.getProperty(
                    channel, property.path, actual, error)) return false;
            if (property.type == std::string("bool")) {
                bool parsed = false;
                bool expected = property.value == "true";
                if (!desktop_backend::parseBoolean(actual, parsed) ||
                    parsed != expected) matches = false;
            } else if (desktop_backend::parseInteger(actual) !=
                       desktop_backend::parseInteger(property.value)) {
                matches = false;
            }
        }
        return true;
    };
    const auto writeState = [&](std::string&) {
        for (const auto& property : required) {
            if (!backend.setProperty(channel, property.path, property.type,
                                     property.value, error)) return false;
        }
        return true;
    };
    if (!desktop_policy::reconcileEffectiveSetting(
            readState, writeState,
            "XFCE screen lock settings did not reach the requested state",
            error)) return false;
    return backend.screenSaverAvailable(error);
}
} // namespace xfce_screen_lock_timeout

class XfceScreenLockTimeoutHandler final : public ScreenLockTimeoutHandler {
public:
    XfceScreenLockTimeoutHandler(const UserSession& session, const SessionContext& context);

    const char* desktopName() const override { return backend.name(); }
    bool apply(int timeoutMinutes, std::string& error) const override;

private:
    XfceBackend backend;
};

#endif // XFCE_SCREEN_LOCK_TIMEOUT_HANDLER_H
