#ifndef XFCE_BACKEND_H
#define XFCE_BACKEND_H

#include "modules/oss/desktop_environment/backends/DesktopEnvironmentBackend.h"

#include <functional>

struct XfceBackendDependencies {
    std::function<std::string(const std::vector<std::string>&)> findExecutable;
    std::function<bool(const std::string&, const std::vector<std::string>&,
                       std::string&, std::string&)> execute;
};

class XfceBackend final : public DesktopEnvironmentBackend {
public:
    XfceBackend(const UserSession& session, const SessionContext& context);
    XfceBackend(const UserSession& session, const SessionContext& context,
                XfceBackendDependencies dependencies);

    const char* name() const override { return "XFCE"; }

    bool setProperty(
        const std::string& channel,
        const std::string& property,
        const std::string& type,
        const std::string& value,
        std::string& error
    ) const;

    bool getProperty(
        const std::string& channel,
        const std::string& property,
        std::string& value,
        std::string& error
    ) const;

    bool screenSaverAvailable(std::string& error) const;

private:
    XfceBackendDependencies dependencies_;

    std::string findCommand(const std::vector<std::string>& paths) const;
    bool runCommand(const std::string& executable,
                    const std::vector<std::string>& arguments,
                    std::string& output, std::string& error) const;
};

#endif // XFCE_BACKEND_H
