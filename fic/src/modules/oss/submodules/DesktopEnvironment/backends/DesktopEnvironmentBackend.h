#ifndef DESKTOP_ENVIRONMENT_BACKEND_H
#define DESKTOP_ENVIRONMENT_BACKEND_H

#include "session/UserSession.h"

#include <string>
#include <vector>

enum class DesktopEnvironmentKind {
    Unknown,
    Gnome,
    Kde,
    Xfce
};

class DesktopEnvironmentBackend {
public:
    DesktopEnvironmentBackend(const UserSession& session, const SessionContext& context);
    virtual ~DesktopEnvironmentBackend() = default;

    virtual const char* name() const = 0;

    static DesktopEnvironmentKind kindFromName(const std::string& desktop);
    static std::string normalizeName(std::string desktop);
    static std::string findExecutable(const std::vector<std::string>& paths);

protected:
    bool execute(
        const std::string& executable,
        const std::vector<std::string>& arguments,
        std::string& output,
        std::string& error
    ) const;

private:
    UserSession session;
    SessionContext context;
};

#endif // DESKTOP_ENVIRONMENT_BACKEND_H
