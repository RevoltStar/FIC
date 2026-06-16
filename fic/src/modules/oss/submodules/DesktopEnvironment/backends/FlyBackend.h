#ifndef FLY_BACKEND_H
#define FLY_BACKEND_H

#include "modules/oss/submodules/DesktopEnvironment/backends/DesktopEnvironmentBackend.h"

class FlyBackend final : public DesktopEnvironmentBackend {
public:
    FlyBackend(const UserSession& session, const SessionContext& context);

    const char* name() const override { return "FLY"; }

    bool setValue(
        const std::string& key,
        const std::string& value,
        std::string& error
    ) const;

    bool getValue(
        const std::string& key,
        std::string& value,
        std::string& error
    ) const;

private:
    UserSession session;
};

#endif // FLY_BACKEND_H
